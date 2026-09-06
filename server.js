require("dotenv").config();

const path = require("path");
const fs = require("fs");
const express = require("express");
const http = require("http");
const https = require("https");
const WebSocket = require("ws");
const {
    randomUUID,
    timingSafeEqual,
    createHmac,
    randomBytes,
    pbkdf2Sync,
} = require("crypto");
const Database = require("better-sqlite3");

const PORT = Number(process.env.PORT) || 8080;
const HTTPS_ENABLED = String(process.env.HTTPS || "").toLowerCase() === "true";
const SSL_KEY_PATH = process.env.SSL_KEY_PATH || "";
const SSL_CERT_PATH = process.env.SSL_CERT_PATH || "";
const SESSION_SECRET =
    String(process.env.SESSION_SECRET || "").trim() ||
    randomBytes(32).toString("hex");
const SESSION_TTL_SECONDS = Math.max(
    60,
    Number(process.env.SESSION_TTL_SECONDS) || 43200,
);
const TRUST_PROXY =
    String(process.env.TRUST_PROXY || "").toLowerCase() === "true";
const REQUIRE_HTTPS =
    String(process.env.REQUIRE_HTTPS || "").toLowerCase() === "true";
const ALLOWED_ORIGINS = String(process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
const ALLOWED_IPS = String(process.env.ALLOWED_IPS || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
const RATE_LIMIT_WINDOW_MS = Math.max(
    1000,
    Number(process.env.RATE_LIMIT_WINDOW_MS) || 60000,
);
const RATE_LIMIT_AUTH_MAX = Math.max(
    1,
    Number(process.env.RATE_LIMIT_AUTH_MAX) || 10,
);
const RATE_LIMIT_WS_MAX = Math.max(
    1,
    Number(process.env.RATE_LIMIT_WS_MAX) || 60,
);
const AUTH_COOKIE_NAME = "openbve_auth";
const HEALTHCHECK_PATH = "/healthz";
const DEFAULT_ROOM_ID = "mta-main";
const DEFAULT_CHANNEL = "operators";

// When true, game clients (operators) may connect to the WebSocket without logging in.
// Any registered web-browser dispatchers still authenticate normally.
// Set ALLOW_ANONYMOUS_WS=true in your .env to enable.
const ALLOW_ANONYMOUS_WS =
    String(process.env.ALLOW_ANONYMOUS_WS || "").toLowerCase() === "true";
// How long one operator may hold a channel before another operator's PTT request
// takes it from them, instead of being queued behind it. This is a floor on the
// interruption, not a hard transmission limit — a holder is never cut off unless
// somebody else actually wants the line. Set to 0 to disable interruption entirely.
const PTT_INTERRUPT_SECONDS = (() => {
    const raw = Number(process.env.PTT_INTERRUPT_SECONDS);
    if (!Number.isFinite(raw) || raw < 0) {
        return 35;
    }
    return raw;
})();

// How often to ping every connected socket.
//
// The `ws` library does not ping on its own, and browsers cannot send pings from
// JavaScript at all — so an idle radio connection has no traffic whatsoever
// between transmissions. Behind a reverse proxy (nginx's proxy_read_timeout
// defaults to 60s) that idle connection gets closed out from under us. Pinging
// keeps it alive and doubles as dead-peer detection.
const WS_HEARTBEAT_SECONDS = (() => {
    const raw = Number(process.env.WS_HEARTBEAT_SECONDS);
    if (!Number.isFinite(raw) || raw <= 0) {
        return 30;
    }
    return raw;
})();

// The channels a fresh database is seeded with. After that the set is owned by
// the dispatchers — see the radio_channels table and the channel registry below.
const SEED_CHANNELS = [
    { id: "operators", label: "Operators", restricted: 0 },
    { id: "a1-irt", label: "A1-IRT", restricted: 1 },
    { id: "b1-bmt", label: "B1-BMT", restricted: 1 },
    { id: "b2-ind", label: "B2-IND", restricted: 1 },
    { id: "y-yard", label: "Y-Yard", restricted: 1 },
];

// ── Ranks (stored in DB, determine permissions) ──────────────
// Hierarchy: admin > mod > t3 > t2 > t1
const ALLOWED_RANKS = new Set(["admin", "mod", "t3", "t2", "t1"]);
const STAFF_RANKS = new Set(["admin", "mod"]);
const RANK_HIERARCHY = ["admin", "mod", "t3", "t2", "t1"]; // index 0 = highest

// ── Session Roles (chosen per-session, determine display/channel) ─
const ALLOWED_SESSION_ROLES = new Set(["dispatcher", "operator", "listener"]);
const SESSION_HIERARCHY = ["dispatcher", "operator", "listener"]; // index 0 = highest

// Roles allowed by each rank
function allowedSessionRoles(rank) {
    if (rank === "t1") return ["listener"];
    if (rank === "t2") return ["listener", "operator"];
    return ["listener", "operator", "dispatcher"]; // t3, mod, admin
}

// Clamp a requested session role to what the rank permits
function capSessionRole(requestedRole, rank) {
    const allowed = allowedSessionRoles(rank);
    if (allowed.includes(requestedRole)) return requestedRole;
    // Return the highest allowed session role
    for (const r of SESSION_HIERARCHY) {
        if (allowed.includes(r)) return r;
    }
    return "listener";
}

// Normalize a rank value, migrating legacy role names
function normalizeRank(value) {
    const v = String(value || "").toLowerCase();
    if (v === "dispatcher") return "t3"; // legacy migration
    if (v === "operator") return "t2"; // legacy migration
    if (v === "listener") return "t1"; // legacy migration
    return ALLOWED_RANKS.has(v) ? v : "t1";
}

// Normalize a session role value from client
function normalizeSessionRole(value) {
    const v = String(value || "").toLowerCase();
    return ALLOWED_SESSION_ROLES.has(v) ? v : "operator";
}

/**
 * True for a client that administers the radio.
 *
 * Dispatchers run the radio, so signing on for a dispatcher shift carries the
 * whole radio privilege set: override a transmission in progress, own the
 * channel list, mute anyone, and reassign TIDs. Staff ranks connect with their
 * rank as their session role rather than "dispatcher", so they are matched
 * separately.
 *
 * This authority is scoped to the radio and nothing else. It is deliberately
 * *not* the account's global rank — that governs room administration and the
 * admin pages, and is only ever granted from the database. Which session roles
 * a rank may take is still capped by capSessionRole, so a T2 operator cannot
 * sign on as a dispatcher to get here.
 */
function isRadioAdmin(client) {
    if (!client) return false;
    return client.role === "dispatcher" || STAFF_RANKS.has(client.rank);
}

// Audio transport a client is able to negotiate.
//   "webrtc" — browser clients: peer mesh with other webrtc clients, and can
//              additionally send/receive PCM over the binary relay.
//   "relay"  — the in-game client: binary PCM relay only, no WebRTC stack.
// Audio between any pair of clients travels over exactly one transport: WebRTC
// when both ends speak it, the relay whenever either end is relay-only.
function normalizeTransport(value) {
    return String(value || "").toLowerCase() === "relay" ? "relay" : "webrtc";
}

function canAccessChannel(rank, channelId) {
    if (!isRestrictedChannel(channelId)) return true;
    return rank === "t3" || rank === "mod" || rank === "admin";
}

function capChannel(requestedChannel, rank) {
    const ch = String(requestedChannel || DEFAULT_CHANNEL).toLowerCase();
    if (!channelExists(ch)) return DEFAULT_CHANNEL;
    if (!canAccessChannel(rank, ch)) return DEFAULT_CHANNEL;
    return ch;
}

function getChannelDescriptors(rank) {
    return channelIds().map((ch) => ({
        id: ch,
        label: channelLabel(ch),
        restricted: isRestrictedChannel(ch),
        allowed: canAccessChannel(rank, ch),
    }));
}

const authRateLimit = new Map();
const wsRateLimit = new Map();

// ── SQLite setup ──────────────────────────────────────────────
const DB_PATH = path.join(__dirname, "data.db");
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS rooms (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    creator_id TEXT NOT NULL,
    creator_username TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    FOREIGN KEY(creator_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    role TEXT NOT NULL,
    granted_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY(user_id, room_id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(room_id) REFERENCES rooms(id)
  );

  CREATE TABLE IF NOT EXISTS radio_channels (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    restricted INTEGER NOT NULL DEFAULT 0,
    position INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  );
`);

// Schema migration: add required user email field for legacy databases.
const userColumns = db.prepare("PRAGMA table_info(users)").all();
if (!userColumns.some((col) => col.name === "email")) {
    db.exec("ALTER TABLE users ADD COLUMN email TEXT COLLATE NOCASE");
}
db.exec(
    "UPDATE users SET email = lower(username) || '@local.invalid' WHERE email IS NULL OR trim(email) = ''",
);
db.exec(
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_nocase ON users(email COLLATE NOCASE)",
);

// Schema migration: add per-room join policy for admin-controlled public access.
const roomColumns = db.prepare("PRAGMA table_info(rooms)").all();
if (!roomColumns.some((col) => col.name === "allow_anyone")) {
    db.exec(
        "ALTER TABLE rooms ADD COLUMN allow_anyone INTEGER NOT NULL DEFAULT 0",
    );
}

// Prepared statements
const stmts = {
    getUserByName: db.prepare(
        "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
    ),
    getUserByEmail: db.prepare(
        "SELECT * FROM users WHERE email = ? COLLATE NOCASE",
    ),
    getUserById: db.prepare("SELECT * FROM users WHERE id = ?"),
    createUser: db.prepare(
        "INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)",
    ),
    getRooms: db.prepare("SELECT * FROM rooms ORDER BY created_at DESC"),
    getRoomById: db.prepare("SELECT * FROM rooms WHERE id = ?"),
    createRoom: db.prepare(
        "INSERT INTO rooms (id, name, creator_id, creator_username) VALUES (?, ?, ?, ?)",
    ),
    updateRoomName: db.prepare("UPDATE rooms SET name = ? WHERE id = ?"),
    updateRoomJoinPolicy: db.prepare(
        "UPDATE rooms SET allow_anyone = ? WHERE id = ?",
    ),
    deleteRoom: db.prepare("DELETE FROM rooms WHERE id = ?"),
    clearRoomRoles: db.prepare("DELETE FROM user_roles WHERE room_id = ?"),
    getUserRole: db.prepare(
        "SELECT role FROM user_roles WHERE user_id = ? AND room_id = ?",
    ),
    setUserRole: db.prepare(
        "INSERT INTO user_roles (user_id, room_id, role) VALUES (?, ?, ?) ON CONFLICT(user_id, room_id) DO UPDATE SET role = excluded.role, granted_at = strftime('%s','now')",
    ),
    getRoster: db.prepare(
        "SELECT u.id AS user_id, u.username, ur.role, ur.granted_at FROM user_roles ur JOIN users u ON u.id = ur.user_id WHERE ur.room_id = ? ORDER BY ur.granted_at ASC",
    ),
    removeRosterRole: db.prepare(
        "DELETE FROM user_roles WHERE user_id = ? AND room_id = ?",
    ),
    hasAdminRole: db.prepare(
        "SELECT 1 AS ok FROM user_roles WHERE user_id = ? AND role = 'admin' LIMIT 1",
    ),
    hasModRole: db.prepare(
        "SELECT 1 AS ok FROM user_roles WHERE user_id = ? AND role = 'mod' LIMIT 1",
    ),
    hasStaffRole: db.prepare(
        "SELECT 1 AS ok FROM user_roles WHERE user_id = ? AND role IN ('admin','mod') LIMIT 1",
    ),
    getChannels: db.prepare(
        "SELECT * FROM radio_channels ORDER BY position ASC, created_at ASC",
    ),
    getChannelById: db.prepare("SELECT * FROM radio_channels WHERE id = ?"),
    createChannel: db.prepare(
        "INSERT INTO radio_channels (id, label, restricted, position) VALUES (?, ?, ?, ?)",
    ),
    deleteChannel: db.prepare("DELETE FROM radio_channels WHERE id = ?"),
    renameChannel: db.prepare("UPDATE radio_channels SET label = ? WHERE id = ?"),
    setChannelRestricted: db.prepare(
        "UPDATE radio_channels SET restricted = ? WHERE id = ?",
    ),
    maxChannelPosition: db.prepare(
        "SELECT COALESCE(MAX(position), 0) AS maxPos FROM radio_channels",
    ),
};

// ── Channel registry ──────────────────────────────────────────
// Channels used to be a hardcoded constant. They are now owned by the
// dispatchers and persisted, so the in-memory registry is the single source of
// truth that every room's channel state is built from.

/** @type {Map<string, {id: string, label: string, restricted: boolean}>} */
const channelRegistry = new Map();

function loadChannelRegistry() {
    if (stmts.getChannels.all().length === 0) {
        // Fresh database — lay down the defaults the radio shipped with.
        let position = 0;
        for (const seed of SEED_CHANNELS) {
            stmts.createChannel.run(seed.id, seed.label, seed.restricted, position++);
        }
    }

    channelRegistry.clear();
    for (const row of stmts.getChannels.all()) {
        channelRegistry.set(row.id, {
            id: row.id,
            label: row.label,
            restricted: Boolean(row.restricted),
        });
    }
}

loadChannelRegistry();

/** Every channel id, in display order. */
function channelIds() {
    return [...channelRegistry.keys()];
}

function channelExists(id) {
    return channelRegistry.has(id);
}

function isRestrictedChannel(id) {
    return Boolean(channelRegistry.get(id)?.restricted);
}

function channelLabel(id) {
    return channelRegistry.get(id)?.label || id;
}

/**
 * Turns a dispatcher's free text into a channel id: lowercase, spaces and
 * punctuation collapsed to single hyphens.
 */
function slugifyChannelId(value) {
    return String(value || "")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 32);
}

// ── Seed default admin account ────────────────────────────────
{
    const DEFAULT_ADMIN_USERNAME = String(
        process.env.DEFAULT_ADMIN_USERNAME || "admin",
    ).trim();
    const DEFAULT_ADMIN_EMAIL = String(
        process.env.DEFAULT_ADMIN_EMAIL || "admin@local.invalid",
    )
        .trim()
        .toLowerCase();
    const DEFAULT_ADMIN_PASSWORD = String(
        process.env.DEFAULT_ADMIN_PASSWORD || "",
    ).trim();

    if (!DEFAULT_ADMIN_PASSWORD) {
        console.warn(
            "[seed] DEFAULT_ADMIN_PASSWORD is not set; skipping default admin seed.",
        );
    } else {
        const seedAdmin = db.transaction(() => {
            let adminUser = stmts.getUserByName.get(DEFAULT_ADMIN_USERNAME);
            if (!adminUser) {
                const adminId = randomUUID();
                const adminHash = hashPassword(DEFAULT_ADMIN_PASSWORD);
                stmts.createUser.run(
                    adminId,
                    DEFAULT_ADMIN_USERNAME,
                    DEFAULT_ADMIN_EMAIL,
                    adminHash,
                );
                adminUser = stmts.getUserById.get(adminId);
                console.log(
                    `[seed] Default admin account created (username: ${DEFAULT_ADMIN_USERNAME})`,
                );
            }

            // Ensure the default room exists in the DB so the FK is satisfied.
            const existingRoom = stmts.getRoomById.get(DEFAULT_ROOM_ID);
            if (!existingRoom) {
                stmts.createRoom.run(
                    DEFAULT_ROOM_ID,
                    "Main",
                    adminUser.id,
                    adminUser.username,
                );
            }

            // Grant admin role if not already set.
            const existingRole = stmts.getUserRole.get(
                adminUser.id,
                DEFAULT_ROOM_ID,
            );
            if (!existingRole || existingRole.role !== "admin") {
                stmts.setUserRole.run(adminUser.id, DEFAULT_ROOM_ID, "admin");
            }
        });

        seedAdmin();
    } // end DEFAULT_ADMIN_PASSWORD guard
}

function isGlobalAdminUser(userId) {
    if (!userId) return false;
    if (stmts.hasAdminRole.get(userId)) return true;
    return false;
}

function isGlobalStaffUser(userId) {
    if (!userId) return false;
    if (isGlobalAdminUser(userId)) return true;
    if (stmts.hasStaffRole.get(userId)) return true;
    return false;
}

function isGlobalModUser(userId) {
    if (!userId) return false;
    return Boolean(stmts.hasModRole.get(userId));
}

function requireGlobalAdmin(req, res, next) {
    if (!isGlobalAdminUser(req.userId)) {
        res.status(403).json({
            error: "Forbidden",
            message: "Admin access required.",
        });
        return;
    }
    next();
}

function requireGlobalStaff(req, res, next) {
    if (!isGlobalStaffUser(req.userId)) {
        res.status(403).json({
            error: "Forbidden",
            message: "Staff access required.",
        });
        return;
    }
    next();
}

// ── Account password hashing (PBKDF2) ────────────────────────
function hashPassword(password, salt = randomBytes(16).toString("hex")) {
    const hash = pbkdf2Sync(password, salt, 100_000, 64, "sha512").toString(
        "hex",
    );
    return `${hash}:${salt}`;
}

function verifyPassword(password, stored) {
    try {
        const [hash, salt] = String(stored || "").split(":");
        const computed = pbkdf2Sync(
            password,
            salt,
            100_000,
            64,
            "sha512",
        ).toString("hex");
        const hashBuf = Buffer.from(hash, "hex");
        const computedBuf = Buffer.from(computed, "hex");
        if (hashBuf.length !== computedBuf.length) return false;
        return timingSafeEqual(hashBuf, computedBuf);
    } catch (_err) {
        return false;
    }
}

const app = express();
app.set("trust proxy", TRUST_PROXY);
app.use(express.json());

function parseCookies(cookieHeader) {
    const result = {};
    if (!cookieHeader) {
        return result;
    }

    const pairs = String(cookieHeader).split(";");
    for (const pair of pairs) {
        const idx = pair.indexOf("=");
        if (idx === -1) {
            continue;
        }

        const key = pair.slice(0, idx).trim();
        const value = pair.slice(idx + 1).trim();
        if (!key) {
            continue;
        }

        try {
            result[key] = decodeURIComponent(value);
        } catch (_err) {
            result[key] = value;
        }
    }

    return result;
}

function base64UrlEncode(value) {
    return Buffer.from(value)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}

function base64UrlDecode(value) {
    const normalized = String(value || "")
        .replace(/-/g, "+")
        .replace(/_/g, "/");
    const pad = normalized.length % 4;
    const padded =
        pad === 0 ? normalized : `${normalized}${"=".repeat(4 - pad)}`;
    return Buffer.from(padded, "base64").toString("utf8");
}

function safeJsonParse(raw) {
    try {
        return JSON.parse(raw);
    } catch (_err) {
        return null;
    }
}

function signSessionToken(payload) {
    const header = { alg: "HS256", typ: "JWT" };
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signature = createHmac("sha256", SESSION_SECRET)
        .update(signingInput)
        .digest("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
    return `${signingInput}.${signature}`;
}

function verifySessionToken(token) {
    const parts = String(token || "").split(".");
    if (parts.length !== 3) {
        return null;
    }

    const [encodedHeader, encodedPayload, signature] = parts;
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const expected = createHmac("sha256", SESSION_SECRET)
        .update(signingInput)
        .digest();
    const got = Buffer.from(
        String(signature || "")
            .replace(/-/g, "+")
            .replace(/_/g, "/"),
        "base64",
    );
    if (got.length !== expected.length || !timingSafeEqual(got, expected)) {
        return null;
    }

    const payload = safeJsonParse(base64UrlDecode(encodedPayload));
    if (!payload || typeof payload !== "object") {
        return null;
    }

    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== "number" || payload.exp <= now) {
        return null;
    }

    if (payload.scope !== "webrtc") {
        return null;
    }

    return payload;
}

function getTokenFromRequestUrl(urlText, host) {
    try {
        const urlObj = new URL(urlText || "/", `http://${host || "localhost"}`);
        return String(urlObj.searchParams.get("token") || "").trim();
    } catch (_err) {
        return "";
    }
}

function getTokenFromHeaders(headers) {
    const tokenHeader = String(headers["x-access-token"] || "").trim();
    if (tokenHeader) {
        return tokenHeader;
    }

    const authHeader = String(headers.authorization || "").trim();
    if (authHeader.toLowerCase().startsWith("bearer ")) {
        return authHeader.slice(7).trim();
    }

    const cookies = parseCookies(headers.cookie);
    return String(cookies[AUTH_COOKIE_NAME] || "").trim();
}

function isValidAccessToken(candidate) {
    if (!ACCESS_TOKEN) {
        return false;
    }

    const left = Buffer.from(String(candidate || ""));
    const right = Buffer.from(ACCESS_TOKEN);
    if (left.length !== right.length) {
        return false;
    }

    return timingSafeEqual(left, right);
}

function isValidAuthToken(candidate) {
    if (!candidate) {
        return false;
    }

    return (
        Boolean(verifySessionToken(candidate)) || isValidAccessToken(candidate)
    );
}

function isSecureFromHeaders(headers) {
    const forwardedProto = String(
        headers["x-forwarded-proto"] || headers["x-forwarded-protocol"] || "",
    ).toLowerCase();
    if (forwardedProto) {
        const hasHttps = forwardedProto
            .split(",")
            .map((v) => v.trim())
            .includes("https");
        if (hasHttps) {
            return true;
        }
    }

    const forwardedSsl = String(headers["x-forwarded-ssl"] || "").toLowerCase();
    return forwardedSsl === "on";
}

function isLocalRequestHost(host) {
    const hostOnly = String(host || "")
        .split(":")[0]
        .toLowerCase();
    return (
        hostOnly === "localhost" ||
        hostOnly === "127.0.0.1" ||
        hostOnly === "::1"
    );
}

function getClientIpFromRequest(req) {
    if (TRUST_PROXY) {
        const xf = String(req.headers["x-forwarded-for"] || "")
            .split(",")[0]
            .trim();
        if (xf) {
            return xf;
        }
    }

    return String(
        req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : "",
    );
}

function isAllowedIp(ip) {
    if (ALLOWED_IPS.length === 0) {
        return true;
    }

    const normalized = String(ip || "").replace(/^::ffff:/, "");
    return ALLOWED_IPS.includes(normalized);
}

function hitRateLimit(bucket, key, maxCount) {
    const now = Date.now();
    const cutoff = now - RATE_LIMIT_WINDOW_MS;
    const current = bucket.get(key) || [];
    const next = current.filter((time) => time > cutoff);
    if (next.length >= maxCount) {
        bucket.set(key, next);
        return true;
    }

    next.push(now);
    bucket.set(key, next);
    return false;
}

function isAllowedOrigin(origin) {
    if (ALLOWED_ORIGINS.length === 0) {
        return true;
    }

    if (!origin) {
        return false;
    }

    const normalizedOrigin = String(origin)
        .trim()
        .replace(/\/+$/, "")
        .toLowerCase();
    const parsedOrigin = safeParseUrl(normalizedOrigin);
    const originHost = parsedOrigin ? parsedOrigin.host : "";

    return ALLOWED_ORIGINS.some((allowed) => {
        const normalizedAllowed = String(allowed)
            .trim()
            .replace(/\/+$/, "")
            .toLowerCase();
        if (!normalizedAllowed) {
            return false;
        }

        if (normalizedAllowed === "*") {
            return true;
        }

        if (normalizedAllowed === normalizedOrigin) {
            return true;
        }

        const parsedAllowed = safeParseUrl(normalizedAllowed);
        if (parsedAllowed && parsedAllowed.origin === normalizedOrigin) {
            return true;
        }

        // Allow host-only entries like "example.com" in ALLOWED_ORIGINS.
        return Boolean(originHost) && normalizedAllowed === originHost;
    });
}

function safeParseUrl(value) {
    try {
        return new URL(value);
    } catch (_err) {
        return null;
    }
}

function setAuthCookie(res, token) {
    const attrs = [
        `${AUTH_COOKIE_NAME}=${encodeURIComponent(token)}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Strict",
        `Max-Age=${SESSION_TTL_SECONDS}`,
    ];

    if (HTTPS_ENABLED || REQUIRE_HTTPS) {
        attrs.push("Secure");
    }

    res.setHeader("Set-Cookie", attrs.join("; "));
}

function clearAuthCookie(res) {
    const attrs = [
        `${AUTH_COOKIE_NAME}=`,
        "Path=/",
        "HttpOnly",
        "SameSite=Strict",
        "Max-Age=0",
    ];
    if (HTTPS_ENABLED || REQUIRE_HTTPS) {
        attrs.push("Secure");
    }
    res.setHeader("Set-Cookie", attrs.join("; "));
}

function issueSession(res, ip, userId, username) {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        sub: userId,
        username,
        scope: "webrtc",
        ip,
        iat: now,
        exp: now + SESSION_TTL_SECONDS,
    };

    const token = signSessionToken(payload);
    setAuthCookie(res, token);
    return token;
}

app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "same-origin");
    next();
});

app.use((req, res, next) => {
    if (req.path === HEALTHCHECK_PATH) {
        next();
        return;
    }

    if (!REQUIRE_HTTPS) {
        next();
        return;
    }

    const secure = Boolean(req.secure) || isSecureFromHeaders(req.headers);
    if (secure || isLocalRequestHost(req.headers.host)) {
        next();
        return;
    }

    res.status(426).json({
        error: "HTTPS_REQUIRED",
        message: "HTTPS is required.",
    });
});

app.use((req, res, next) => {
    if (req.path === HEALTHCHECK_PATH) {
        next();
        return;
    }

    const ip = getClientIpFromRequest(req);
    if (!isAllowedIp(ip)) {
        res.status(403).json({
            error: "IP_BLOCKED",
            message: "IP not allowed.",
        });
        return;
    }
    req.clientIp = ip;
    next();
});

app.get("/login", (_req, res) => {
    res.type("html").send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Openbve Radio — Sign In</title>
    <style>
      *{box-sizing:border-box}
      body{font-family:Arial,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#101418;color:#d0d0d0}
      .card{width:min(420px,92vw);background:#1a1f24;border:1px solid #2b343f;border-radius:10px;padding:24px}
      h1{margin:0 0 4px;font-size:1.3rem;color:#d4a018}
      .subtitle{margin:0 0 20px;color:#9cabbb;font-size:0.9rem}
      .tabs{display:flex;gap:0;margin-bottom:20px;border-bottom:1px solid #2b343f}
      .tab{flex:1;padding:10px;background:transparent;border:none;color:#9cabbb;cursor:pointer;font-size:0.95rem;border-bottom:2px solid transparent;transition:.2s}
      .tab.active{color:#d4a018;border-bottom-color:#d4a018}
      .panel{display:none}.panel.active{display:block}
      label{display:block;margin-bottom:12px;font-size:0.85rem;color:#9cabbb}
      input{display:block;width:100%;margin-top:4px;padding:10px;background:#0f1419;border:1px solid #2b343f;border-radius:5px;color:#d0d0d0;font-size:0.95rem}
      input:focus{outline:none;border-color:#d4a018}
      button[type=submit]{width:100%;padding:11px;background:#d4a018;color:#201300;border:none;border-radius:5px;font-weight:bold;font-size:1rem;cursor:pointer;margin-top:4px}
      button[type=submit]:hover{opacity:.9}
      .msg{min-height:18px;margin-top:10px;font-size:0.86rem;color:#e09191}
      .msg.ok{color:#5dbf7a}
    </style>
  </head>
  <body>
    <main class="card">
      <h1>Openbve Radio</h1>
      <p class="subtitle">Sign in or create an account to continue</p>
      <div class="tabs">
        <button class="tab active" onclick="showTab('login',this)">Sign In</button>
        <button class="tab" onclick="showTab('register',this)">Register</button>
      </div>

      <div id="login" class="panel active">
        <form onsubmit="doLogin(event)">
          <label>Username<input id="loginUser" type="text" autocomplete="username" required /></label>
          <label>Password<input id="loginPass" type="password" autocomplete="current-password" required /></label>
          <button type="submit">Sign In</button>
        </form>
        <div id="loginMsg" class="msg"></div>
      </div>

      <div id="register" class="panel">
        <form onsubmit="doRegister(event)">
          <label>Username<input id="regUser" type="text" autocomplete="username" required /></label>
          <label>Email<input id="regEmail" type="email" autocomplete="email" required /></label>
          <label>Password<input id="regPass" type="password" autocomplete="new-password" required /></label>
          <label>Confirm Password<input id="regPass2" type="password" autocomplete="new-password" required /></label>
          <button type="submit">Create Account</button>
        </form>
        <div id="regMsg" class="msg"></div>
      </div>
    </main>
    <script>
      function showTab(name, btn) {
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
        document.getElementById(name).classList.add('active');
        btn.classList.add('active');
      }
      async function doLogin(e) {
        e.preventDefault();
        const msg = document.getElementById('loginMsg');
        msg.textContent = '';
        const res = await fetch('/auth/login', {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ username: loginUser.value, password: loginPass.value })
        });
        if (res.ok) { location.href = '/'; } else {
          const d = await res.json().catch(()=>({}));
          msg.textContent = d.message || 'Invalid username or password.';
        }
      }
      async function doRegister(e) {
        e.preventDefault();
        const msg = document.getElementById('regMsg');
        msg.textContent = '';
        if (regPass.value !== regPass2.value) { msg.textContent = 'Passwords do not match.'; return; }
        const res = await fetch('/auth/register', {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ username: regUser.value, email: regEmail.value, password: regPass.value })
        });
        const d = await res.json().catch(()=>({}));
        if (res.ok) {
          msg.className = 'msg ok';
          msg.textContent = 'Account created! Signing you in…';
          setTimeout(() => { location.href = '/'; }, 800);
        } else {
          msg.textContent = d.message || 'Registration failed.';
        }
      }
    </script>
  </body>
</html>`);
});

app.get("/auth/status", (req, res) => {
    const token =
        getTokenFromHeaders(req.headers) ||
        getTokenFromRequestUrl(req.url, req.headers.host);
    const payload = verifySessionToken(token);
    if (payload) {
        const userId = payload.sub;
        res.json({
            authenticated: true,
            userId,
            username: payload.username,
            isAdmin: isGlobalAdminUser(userId),
            isMod: isGlobalModUser(userId),
            isStaff: isGlobalStaffUser(userId),
        });
    } else {
        res.json({ authenticated: false });
    }
});

app.post("/auth/register", (req, res) => {
    const key = req.clientIp || "unknown";
    if (hitRateLimit(authRateLimit, key, RATE_LIMIT_AUTH_MAX)) {
        res.status(429).json({
            error: "RATE_LIMITED",
            message: "Too many requests.",
        });
        return;
    }

    const username = String((req.body && req.body.username) || "").trim();
    const email = String((req.body && req.body.email) || "")
        .trim()
        .toLowerCase();
    const password = String((req.body && req.body.password) || "");

    if (!username || username.length < 3 || username.length > 32) {
        res.status(400).json({ message: "Username must be 3-32 characters." });
        return;
    }
    if (!/^[a-zA-Z0-9_\-]+$/.test(username)) {
        res.status(400).json({
            message: "Username may only contain letters, numbers, _ and -.",
        });
        return;
    }
    if (!password || password.length < 6) {
        res.status(400).json({
            message: "Password must be at least 6 characters.",
        });
        return;
    }

    if (!email) {
        res.status(400).json({ message: "Email is required." });
        return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        res.status(400).json({
            message: "Please provide a valid email address.",
        });
        return;
    }

    const existing = stmts.getUserByName.get(username);
    if (existing) {
        res.status(409).json({ message: "Username already taken." });
        return;
    }

    const existingEmail = stmts.getUserByEmail.get(email);
    if (existingEmail) {
        res.status(409).json({ message: "Email already registered." });
        return;
    }

    const id = randomUUID();
    const hash = hashPassword(password);
    stmts.createUser.run(id, username, email, hash);

    const token = issueSession(res, req.clientIp, id, username);
    res.status(201).json({ ok: true, userId: id, username, token });
});

app.post("/auth/login", (req, res) => {
    const key = req.clientIp || "unknown";
    if (hitRateLimit(authRateLimit, key, RATE_LIMIT_AUTH_MAX)) {
        res.status(429).json({
            error: "RATE_LIMITED",
            message: "Too many login attempts.",
        });
        return;
    }

    const username = String((req.body && req.body.username) || "").trim();
    const password = String((req.body && req.body.password) || "");

    const user = stmts.getUserByName.get(username);
    if (!user || !verifyPassword(password, user.password_hash)) {
        res.status(401).json({
            error: "UNAUTHORIZED",
            message: "Invalid username or password.",
        });
        return;
    }

    issueSession(res, req.clientIp, user.id, user.username);
    res.json({
        ok: true,
        userId: user.id,
        username: user.username,
        expiresIn: SESSION_TTL_SECONDS,
    });
});

app.post("/auth/logout", (_req, res) => {
    clearAuthCookie(res);
    res.json({ ok: true });
});

app.get(HEALTHCHECK_PATH, (_req, res) => {
    res.status(200).json({ ok: true, status: "healthy" });
});

function httpAuthMiddleware(req, res, next) {
    if (
        req.path.startsWith("/auth/") ||
        req.path === "/login" ||
        req.path === HEALTHCHECK_PATH
    ) {
        next();
        return;
    }

    const queryToken = getTokenFromRequestUrl(req.url, req.headers.host);
    const headerToken = getTokenFromHeaders(req.headers);
    const token = queryToken || headerToken;
    const payload = verifySessionToken(token);

    if (!payload) {
        const accept = String(req.headers.accept || "").toLowerCase();
        if (req.method === "GET" && accept.includes("text/html")) {
            res.redirect("/login");
            return;
        }
        res.status(401).json({
            error: "Unauthorized",
            message: "Please log in.",
        });
        return;
    }

    req.userId = payload.sub;
    req.username = payload.username;
    next();
}

app.use(httpAuthMiddleware);

app.get("/admin.html", requireGlobalStaff, (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/admin.js", requireGlobalStaff, (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin.js"));
});

app.use(express.static(path.join(__dirname, "public")));

function createWebServer() {
    if (!HTTPS_ENABLED) {
        return http.createServer(app);
    }

    if (!SSL_KEY_PATH || !SSL_CERT_PATH) {
        throw new Error("HTTPS=true requires SSL_KEY_PATH and SSL_CERT_PATH.");
    }

    const keyPath = path.resolve(SSL_KEY_PATH);
    const certPath = path.resolve(SSL_CERT_PATH);

    const key = fs.readFileSync(keyPath, "utf8");
    const cert = fs.readFileSync(certPath, "utf8");

    return https.createServer({ key, cert }, app);
}

const server = createWebServer();
const wss = new WebSocket.Server({ noServer: true });

server.on("upgrade", (req, socket, head) => {
    const ip = getClientIpFromRequest(req);
    if (!isAllowedIp(ip)) {
        socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
        socket.destroy();
        return;
    }

    if (hitRateLimit(wsRateLimit, ip || "unknown", RATE_LIMIT_WS_MAX)) {
        socket.write("HTTP/1.1 429 Too Many Requests\r\n\r\n");
        socket.destroy();
        return;
    }

    if (REQUIRE_HTTPS) {
        const secure = isSecureFromHeaders(req.headers);
        if (!secure && !isLocalRequestHost(req.headers.host)) {
            socket.write("HTTP/1.1 426 Upgrade Required\r\n\r\n");
            socket.destroy();
            return;
        }
    }

    if (!isAllowedOrigin(req.headers.origin)) {
        socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
        socket.destroy();
        return;
    }

    {
        const queryToken = getTokenFromRequestUrl(req.url, req.headers.host);
        const headerToken = getTokenFromHeaders(req.headers);
        const wsToken = queryToken || headerToken;
        // Skip token check when anonymous mode is enabled — game clients connect without login
        if (!ALLOW_ANONYMOUS_WS && !verifySessionToken(wsToken)) {
            socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
            socket.destroy();
            return;
        }
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
        console.log("WebSocket connection established from IP:", ip);
        wss.emit("connection", ws, req);
    });
});

const rooms = new Map();
const clientsById = new Map();
const clientsByAccountId = new Map(); // accountId → client (one active session per account)

function send(ws, payload) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        return;
    }

    ws.send(JSON.stringify(payload));
}

function generateOperatorName(clientId) {
    const prefixes = ["Train", "Tower", "Ops", "Unit", "Control"];
    const suffix = clientId.slice(0, 4).toUpperCase();
    const bucket = Number.parseInt(clientId.slice(0, 2), 16) % prefixes.length;
    return `${prefixes[bucket]}-${suffix}`;
}

function normalizeRole(value) {
    return normalizeSessionRole(value);
}

function getRoom(roomId) {
    if (!rooms.has(roomId)) {
        const dbRoom = stmts.getRoomById.get(roomId);
        const roomName = dbRoom ? dbRoom.name : `Server ${roomId.slice(-4)}`;
        rooms.set(roomId, {
            id: roomId,
            createdAt: Date.now(),
            creatorId: null,
            creatorName: "",
            name: roomName,
            allowAnyone: Boolean(dbRoom && dbRoom.allow_anyone),
            members: new Map(), // userId -> { id, name, role, trainId, line, channel }
            clients: new Set(),
            channels: new Map(
                channelIds().map((name) => [
                    name,
                    {
                        holderId: null,
                        grantedAt: 0,
                        queue: [],
                    },
                ]),
            ),
        });
    }

    return rooms.get(roomId);
}

function createRoom(roomId, creatorId, creatorName, roomName) {
    if (rooms.has(roomId)) {
        return null;
    }

    const room = {
        id: roomId,
        createdAt: Date.now(),
        creatorId,
        creatorName,
        name: roomName || `Server ${roomId.slice(-4)}`,
        allowAnyone: false,
        members: new Map(),
        clients: new Set(),
        channels: new Map(
            channelIds().map((name) => [
                name,
                {
                    holderId: null,
                    grantedAt: 0,
                    queue: [],
                },
            ]),
        ),
    };

    rooms.set(roomId, room);
    return room;
}

function canAdminRoom(room, accountId) {
    if (!room || !accountId) return false;
    for (const member of room.members.values()) {
        if (member.accountId === accountId && member.rank === "admin")
            return true;
    }
    return false;
}

function canModerateRoom(room, accountId) {
    if (!room || !accountId) return false;
    for (const member of room.members.values()) {
        if (member.accountId === accountId && STAFF_RANKS.has(member.rank))
            return true;
    }
    return false;
}

function getClientSummary(member) {
    if (!member) return null;
    return {
        id: member.id,
        name: member.name,
        role: member.role,
        rank: member.rank,
        trainId: member.trainId,
        channel: member.channel,
        transport: member.transport || "webrtc",
        // `muted` is the effective state on the channel they are standing on, so
        // the roster shows what actually applies there. The two scopes are sent
        // alongside it for the dispatcher's mute menu.
        muted: Boolean(member.muted),
        mutedGlobally: Boolean(member.mutedGlobally),
        mutedChannels: member.mutedChannels || [],
        // Named so dispatchers see who took a unit off the air, not just that
        // somebody did.
        mutedBy: member.muted ? member.mutedByName || "" : "",
        degraded: Boolean(member.degraded),
    };
}

function getLiveClientSummary(client) {
    if (!client) return null;
    return {
        id: client.id,
        name: client.name,
        role: client.role,
        rank: client.rank,
        trainId: client.trainId,
        channel: client.channel,
        transport: client.transport || "webrtc",
        muted: isMutedHere(client),
        mutedGlobally: Boolean(client.globalMuted),
        mutedChannels: [...(client.mutedChannels || [])],
        mutedBy: isMutedHere(client) ? client.mutedByName || "" : "",
        degraded: Boolean(client.degraded),
    };
}

function getRoomSummary(room) {
    return {
        id: room.id,
        createdAt: room.createdAt,
        creatorId: room.creatorId,
        creatorName: room.creatorName,
        allowAnyone: Boolean(room.allowAnyone),
        memberCount: room.clients.size,
        members: Array.from(room.members.values()).map((m) => ({
            id: m.id,
            name: m.name,
            role: m.role,
        })),
    };
}

function generateUniqueTrainId(room) {
    // Generate a unique 4-digit code (1000-9999) for this room
    const usedIds = new Set();

    // Collect all current train IDs in the room
    for (const member of room.members.values()) {
        if (member.trainId && /^\d{4}$/.test(member.trainId)) {
            usedIds.add(member.trainId);
        }
    }

    // Try to find an unused ID
    for (let i = 0; i < 9000; i++) {
        const id = String(1000 + Math.floor(Math.random() * 9000));
        if (!usedIds.has(id)) {
            return id;
        }
    }

    // Fallback: find the first available number
    for (let i = 1000; i <= 9999; i++) {
        if (!usedIds.has(String(i))) {
            return String(i);
        }
    }

    return "0000"; // Should never reach here
}

function broadcastRoom(room, payload, excludedClientId = null) {
    for (const clientId of room.clients) {
        if (excludedClientId && excludedClientId === clientId) {
            continue;
        }

        const client = clientsById.get(clientId);
        if (client) {
            send(client.ws, payload);
        }
    }
}

function removeClientFromQueues(room, clientId) {
    for (const channelState of room.channels.values()) {
        channelState.queue = channelState.queue.filter((id) => id !== clientId);
    }
}

/**
 * Takes a client out of a room and tells the room about it.
 *
 * Shared by the socket-close handler and the duplicate-session eviction on
 * join. The eviction needs this to run *synchronously*: waiting for the old
 * socket's close event means the replacing client's `joined` payload still
 * lists the session it just replaced, which is what put a second copy of a
 * dispatcher on the roster after they cycled their radio power.
 */
function removeClientFromRoom(room, client) {
    if (!room || !client) return;
    if (!room.clients.has(client.id)) return;

    // A dispatcher may have been keying several channels at once; every one of
    // them has to be let go, not just the one they were standing on.
    for (const ch of client.txChannels || []) {
        releaseChannelFor(room, client, ch, "disconnect");
    }
    client.txChannels = new Set();
    releasePTT(room, client, "disconnect");
    removeClientFromQueues(room, client.id);

    room.clients.delete(client.id);
    room.members.delete(client.id);
    clientsById.delete(client.id);

    // Only clear the account index if this is still the registered session —
    // a newer session for the same account will have overwritten it already.
    if (client.accountId && clientsByAccountId.get(client.accountId) === client) {
        clientsByAccountId.delete(client.accountId);
    }

    broadcastRoom(room, { type: "peer-left", payload: { id: client.id } });

    // A private call cannot outlive either party.
    clearPrivateCallFor(client, "peer-disconnected");

    // An emergency dies with the operator who raised it, otherwise the room
    // would stay locked down with nobody able to stand it down.
    if (room.emergency && room.emergency.operatorId === client.id) {
        room.emergency = null;
        broadcastEmergencyState(room);
    }

    for (const channelName of channelIds()) {
        pushChannelSnapshot(room, channelName);
    }

    if (room.clients.size === 0) {
        for (const channelState of room.channels.values()) {
            channelState.holderId = null;
            channelState.grantedAt = 0;
            channelState.queue = [];
        }
    }
}

/** How a client is identified across reconnects: account when known, else name. */
function sessionIdentity(client) {
    if (!client) return null;
    if (client.accountId) return `acct:${client.accountId}`;
    const name = String(client.name || "").trim().toLowerCase();
    return name ? `name:${name}` : null;
}

/**
 * Drops any earlier session in this room belonging to the same person.
 *
 * A radio that is switched off and on again opens a new socket, and the old
 * one's close frame is not necessarily processed first — so without this the
 * room briefly holds two sessions for one operator and the newcomer is handed a
 * peer list containing itself. Matching on account covers signed-in dispatchers;
 * everyone else is matched on name, which is all the server is given.
 *
 * The evicted socket is closed without a `kicked` notice on purpose: this is
 * almost always the same client reconnecting, and their board reacts to
 * `kicked` by tearing down whatever connection it currently holds — which by
 * then is the new one.
 */
function evictDuplicateSessions(room, client) {
    const identity = sessionIdentity(client);
    if (!identity) return;
    for (const otherId of [...room.clients]) {
        if (otherId === client.id) continue;
        const other = clientsById.get(otherId);
        if (!other || sessionIdentity(other) !== identity) continue;
        console.log(`[room] Replacing stale session for '${other.name}' (${other.id})`);
        removeClientFromRoom(room, other);
        try {
            other.ws.close(4000, "superseded");
        } catch {
            /* already gone */
        }
    }
}

function getChannelState(room, channelName) {
    return room.channels.get(channelName);
}

function pushChannelSnapshot(room, channelName) {
    const channelState = getChannelState(room, channelName);
    if (!channelState) {
        return;
    }

    broadcastRoom(room, {
        type: "channel-state",
        payload: {
            channel: channelName,
            holderId: channelState.holderId,
            queue: channelState.queue,
        },
    });
}

function pushTxState(room, speakerId, channelName, active) {
    for (const listenerId of room.clients) {
        const listener = clientsById.get(listenerId);
        if (!listener) {
            continue;
        }

        const isOnChannel = listener.channel === channelName;

        send(listener.ws, {
            type: "tx-state",
            payload: {
                active: active && isOnChannel,
                speakerId,
                channel: channelName,
            },
        });
    }
}

function releasePTT(room, client, reason = "released") {
    return releaseChannelFor(room, client, client.channel, reason);
}

/**
 * Releases one named channel for this client.
 *
 * Split out from releasePTT so a multi-channel broadcast can let go of each
 * channel it took: releasing only the one the dispatcher is standing on would
 * leave the rest keyed open with nobody talking on them.
 */
function releaseChannelFor(room, client, channelName, reason = "released") {
    const channelState = getChannelState(room, channelName);
    if (!channelState) {
        return;
    }

    channelState.queue = channelState.queue.filter((id) => id !== client.id);

    if (channelState.holderId === client.id) {
        channelState.holderId = null;
        channelState.grantedAt = 0;

        send(client.ws, {
            type: "ptt-released",
            payload: { reason, channel: channelName },
        });

        pushTxState(room, client.id, channelName, false);

        while (channelState.queue.length > 0) {
            const nextId = channelState.queue.shift();
            const nextClient = clientsById.get(nextId);
            if (
                !nextClient ||
                nextClient.roomId !== room.id ||
                nextClient.channel !== channelName ||
                // Muting clears the queues, so this should not come up — but
                // handing the channel to a muted client is the one way a mute
                // could fail silently, so it is checked here as well.
                isMutedOn(nextClient, channelName)
            ) {
                continue;
            }

            channelState.holderId = nextClient.id;
            channelState.grantedAt = Date.now();
            send(nextClient.ws, {
                type: "ptt-granted",
                payload: {
                    channel: channelName,
                    reason: "queue-advanced",
                },
            });

            pushTxState(room, nextClient.id, channelName, true);
            break;
        }
    }

    pushChannelSnapshot(room, channelName);
}

// ── Dispatcher channel management ─────────────────────────────────────────

/// Re-sends every client the channel list as it applies to their own rank.
function broadcastChannelList(room) {
    for (const id of room.clients) {
        const member = clientsById.get(id);
        if (!member || member.ws.readyState !== WebSocket.OPEN) continue;
        send(member.ws, {
            type: "channels-updated",
            payload: { channels: getChannelDescriptors(member.rank) },
        });
    }
}

function createChannel(room, client, payload) {
    const fail = (message) =>
        send(client.ws, { type: "error", payload: { message } });

    if (!isRadioAdmin(client)) {
        fail("Only dispatchers can create channels.");
        return;
    }

    const label = String(payload.label || "").trim().slice(0, 40);
    if (!label) {
        fail("A channel needs a name.");
        return;
    }

    // The id is derived from the name unless one was given explicitly.
    const id = slugifyChannelId(payload.id || label);
    if (!id) {
        fail("That name has no usable letters or digits.");
        return;
    }
    if (channelExists(id)) {
        fail("Channel '" + id + "' already exists.");
        return;
    }

    const restricted = payload.restricted ? 1 : 0;
    const position = (stmts.maxChannelPosition.get()?.maxPos ?? 0) + 1;

    try {
        stmts.createChannel.run(id, label, restricted, position);
    } catch (err) {
        fail("Could not create that channel: " + err.message);
        return;
    }

    channelRegistry.set(id, { id, label, restricted: Boolean(restricted) });

    // Every room needs PTT state for the new channel, including rooms that are
    // idle right now, or the first request on it would find no channel state.
    for (const r of rooms.values()) {
        if (!r.channels.has(id)) {
            r.channels.set(id, { holderId: null, grantedAt: 0, queue: [] });
        }
    }

    broadcastChannelList(room);
    pushChannelSnapshot(room, id);
}

/**
 * Retitles a channel.
 *
 * Only the label moves — the id every client's channel assignment is keyed on
 * stays put, so a rename never strands anyone on a channel that no longer
 * exists the way a delete-and-recreate would.
 */
function renameChannel(room, client, payload) {
    const fail = (message) =>
        send(client.ws, { type: "error", payload: { message } });

    if (!isRadioAdmin(client)) {
        fail("Only dispatchers can rename channels.");
        return;
    }

    const id = slugifyChannelId(payload.id);
    const entry = channelRegistry.get(id);
    if (!entry) {
        fail("No such channel.");
        return;
    }

    const label = String(payload.label || "").trim().slice(0, 40);
    if (!label) {
        fail("A channel needs a name.");
        return;
    }
    if (label === entry.label) {
        return;
    }

    stmts.renameChannel.run(label, id);
    entry.label = label;

    broadcastChannelList(room);
}

/**
 * Opens a channel to everyone, or restricts it to T3 and above.
 *
 * Access is by rank rather than by naming individuals: a channel is a place, and
 * who may stand in it is a property of the place. Anyone already standing on a
 * channel that has just been restricted is moved back to the default one rather
 * than left somewhere they can no longer reach.
 */
function setChannelRestricted(room, client, payload) {
    const fail = (message) =>
        send(client.ws, { type: "error", payload: { message } });

    if (!isRadioAdmin(client)) {
        fail("Only dispatchers can change channel access.");
        return;
    }

    const id = slugifyChannelId(payload.id);
    const entry = channelRegistry.get(id);
    if (!entry) {
        fail("No such channel.");
        return;
    }
    if (id === DEFAULT_CHANNEL) {
        fail("The default channel cannot be restricted.");
        return;
    }

    const restricted = Boolean(payload.restricted);
    if (entry.restricted === restricted) return;

    stmts.setChannelRestricted.run(restricted ? 1 : 0, id);
    entry.restricted = restricted;

    if (restricted) {
        for (const r of rooms.values()) {
            for (const memberId of [...r.clients]) {
                const member = clientsById.get(memberId);
                if (!member || member.channel !== id) continue;
                if (canAccessChannel(member.rank, id)) continue;
                releaseChannelFor(r, member, id, "channel-restricted");
                member.channel = DEFAULT_CHANNEL;
                const record = r.members.get(memberId);
                if (record) record.channel = DEFAULT_CHANNEL;
                send(member.ws, {
                    type: "channel-changed",
                    payload: { id: memberId, channel: DEFAULT_CHANNEL },
                });
                broadcastMemberUpdate(r, memberId);
            }
        }
    }

    broadcastChannelList(room);
}

function deleteChannel(room, client, payload) {
    const fail = (message) =>
        send(client.ws, { type: "error", payload: { message } });

    if (!isRadioAdmin(client)) {
        fail("Only dispatchers can delete channels.");
        return;
    }

    const id = slugifyChannelId(payload.id);
    if (!channelExists(id)) {
        fail("No such channel.");
        return;
    }
    if (id === DEFAULT_CHANNEL) {
        fail("The default channel cannot be deleted.");
        return;
    }

    stmts.deleteChannel.run(id);
    channelRegistry.delete(id);

    // Move anyone standing on it back to the default channel, and drop the
    // per-room state so nothing is left holding a channel that no longer exists.
    for (const r of rooms.values()) {
        const state = r.channels.get(id);
        if (state && state.holderId) {
            const holder = clientsById.get(state.holderId);
            if (holder) releasePTT(r, holder, "channel-removed");
        }
        r.channels.delete(id);

        for (const memberId of r.clients) {
            const member = clientsById.get(memberId);
            if (!member || member.channel !== id) continue;
            member.channel = DEFAULT_CHANNEL;
            const record = r.members.get(memberId);
            if (record) record.channel = DEFAULT_CHANNEL;
            send(member.ws, {
                type: "channel-changed",
                payload: { id: memberId, channel: DEFAULT_CHANNEL },
            });
        }
    }

    broadcastChannelList(room);
}

// ── Dispatcher control of other clients ───────────────────────────────────

/// Pushes a member's current summary to the whole room, self included.
function broadcastMemberUpdate(room, targetId) {
    const member = room.members.get(targetId);
    if (!member) return;
    broadcastRoom(room, {
        type: "peer-updated",
        payload: getClientSummary(member),
    });
}

/**
 * Mutes standing against a room, so they survive the muted client reconnecting.
 *
 * Without this a mute lasts only as long as one WebSocket: an operator who did
 * not care for being taken off the air could simply rejoin, which would make
 * the whole thing advisory. Held in memory rather than the database — a mute is
 * a shift-level action, and a server restart drops every session anyway.
 */
function roomMutes(room) {
    if (!room.mutes) room.mutes = new Map();
    return room.mutes;
}

/**
 * Stable identity for carrying a mute across reconnects.
 *
 * Authenticated clients are keyed on the account. In-game clients connect
 * anonymously and have no account, so they are keyed on their display name —
 * weaker, since a rename escapes it, but it is the only identity they present.
 */
function muteKey(client) {
    if (!client) return null;
    if (client.accountId) return "acct:" + client.accountId;
    const name = String(client.name || "").trim().toLowerCase();
    return name ? "name:" + name : null;
}

/// Re-applies a standing mute to a client that has just joined.
/**
 * The standing record for one identity: a global mute, plus any channels they
 * are muted on individually.
 */
function standingMuteFor(room, client, create) {
    const key = muteKey(client);
    if (!key) return null;
    const mutes = roomMutes(room);
    let record = mutes.get(key);
    if (!record && create) {
        record = { global: false, globalBy: "", channels: new Map() };
        mutes.set(key, record);
    }
    return record || null;
}

/// Drops a record that no longer mutes anything, so the map does not grow forever.
function pruneStandingMute(room, client) {
    const key = muteKey(client);
    if (!key) return;
    const record = roomMutes(room).get(key);
    if (record && !record.global && record.channels.size === 0) {
        roomMutes(room).delete(key);
    }
}

/**
 * TIDs a dispatcher assigned, held against the room so they survive the
 * assigned client reconnecting.
 *
 * The per-client lock alone is not enough: the in-game radio applies its own
 * TID edit by reconnecting, which builds a fresh client record with the lock
 * cleared. Without this, an operator could overwrite a dispatcher's assignment
 * simply by typing a different number into their own radio.
 *
 * Keyed like mutes, and in memory for the same reason -- an assignment is a
 * shift-level action and a restart drops every session anyway.
 */
function roomTrainIds(room) {
    if (!room.assignedTrainIds) room.assignedTrainIds = new Map();
    return room.assignedTrainIds;
}

/// Records a dispatcher's assignment so a reconnect cannot shed it.
function rememberAssignedTrainId(room, client, trainId) {
    const key = muteKey(client);
    if (!key) return;
    roomTrainIds(room).set(key, String(trainId));
}

/// Re-applies a standing TID assignment to a client that has just joined.
function applyAssignedTrainId(room, client) {
    const key = muteKey(client);
    if (!key) return;
    const assigned = roomTrainIds(room).get(key);
    if (!assigned) return;

    // While they were away the number may have been handed to somebody else.
    // Two units answering to one TID would misdirect every private call placed
    // against it, so the assignment is dropped rather than duplicated.
    for (const member of room.members.values()) {
        if (member.id !== client.id && member.trainId === assigned) {
            roomTrainIds(room).delete(key);
            return;
        }
    }

    client.trainId = assigned;
    client.trainIdLocked = true;
}

function applyStandingMute(room, client) {
    const record = standingMuteFor(room, client, false);
    client.mutedChannels = new Set();
    client.globalMuted = false;
    client.mutedByName = "";
    if (!record) return;
    client.globalMuted = Boolean(record.global);
    if (record.global) client.mutedByName = record.globalBy || "";
    for (const [channel, by] of record.channels) {
        client.mutedChannels.add(channel);
        if (!client.mutedByName) client.mutedByName = by || "";
    }
}

/**
 * True when this client is muted on the given channel.
 *
 * A global mute covers every main channel; a local one covers only the channel
 * it was issued on. Neither touches private calls — those are arbitrated
 * separately and stay open whatever the mute state.
 */
function isMutedOn(client, channel) {
    if (!client) return false;
    if (client.globalMuted) return true;
    return Boolean(client.mutedChannels && client.mutedChannels.has(channel));
}

/// Whether the client is muted where they are currently standing. For display.
function isMutedHere(client) {
    return isMutedOn(client, client && client.channel);
}

/**
 * Mutes or unmutes a client on the open channels.
 *
 * Muting takes away the channels only. The muted client still hears everything,
 * and can still be reached by — and place — private calls, which is how a
 * dispatcher talks to somebody they have just taken off the air. What it does
 * take with it is the emergency button: an operator cannot mute-proof themselves
 * by raising an emergency, so muting stands down one they are holding.
 *
 * Dispatchers are mutable too, by any other dispatcher. Muting yourself is not
 * allowed — nobody else can be relied on to be online to undo it.
 */
function setClientMuted(room, client, payload) {
    const fail = (message) =>
        send(client.ws, { type: "error", payload: { message } });

    if (!isRadioAdmin(client)) {
        fail("Only dispatchers can mute.");
        return;
    }

    const targetId = String(payload.targetId || "");
    const target = clientsById.get(targetId);
    if (!target || target.roomId !== room.id) {
        fail("That unit is not on this server.");
        return;
    }
    if (target.id === client.id) {
        fail("You cannot mute yourself.");
        return;
    }

    const muted = Boolean(payload.muted);
    // "global" silences every main channel; "channel" silences one. Defaults to
    // the channel the target is standing on, which is the one the dispatcher was
    // looking at when they right-clicked.
    const global = payload.scope === "global";
    const channel = global
        ? null
        : String(payload.channel || target.channel || DEFAULT_CHANNEL);

    if (!global && !channelExists(channel)) {
        fail("No such channel.");
        return;
    }

    const before = isMutedHere(target);
    const record = standingMuteFor(room, target, muted);

    if (global) {
        if (target.globalMuted === muted) return;
        target.globalMuted = muted;
        if (record) {
            record.global = muted;
            record.globalBy = muted ? client.name : "";
        }
    } else {
        const already = target.mutedChannels && target.mutedChannels.has(channel);
        if (Boolean(already) === muted) return;
        if (!target.mutedChannels) target.mutedChannels = new Set();
        if (muted) {
            target.mutedChannels.add(channel);
            if (record) record.channels.set(channel, client.name);
        } else {
            target.mutedChannels.delete(channel);
            if (record) record.channels.delete(channel);
        }
    }

    if (muted) {
        target.mutedByName = client.name;
    } else {
        pruneStandingMute(room, target);
        // Re-derive from what is left, so lifting one scope does not clear the
        // attribution of another that still stands.
        if (!isMutedOn(target, target.channel) && !target.globalMuted) {
            target.mutedByName = "";
        }
    }

    const member = room.members.get(target.id);
    if (member) {
        member.muted = isMutedHere(target);
        member.mutedGlobally = Boolean(target.globalMuted);
        member.mutedChannels = [...(target.mutedChannels || [])];
        member.mutedByName = target.mutedByName;
    }

    // Only act on the line if the mute actually bites where they are standing.
    if (!before && isMutedHere(target)) {
        // Take the line off them now rather than at the end of the transmission
        // they are part-way through, and drop any place they were holding in a queue.
        releasePTT(room, target, "muted");
        removeClientFromQueues(room, target.id);
        if (room.emergency && room.emergency.operatorId === target.id) {
            room.emergency = null;
            broadcastEmergencyState(room);
        }
    }

    send(target.ws, {
        type: "mute-state",
        payload: {
            muted: isMutedHere(target),
            scope: global ? "global" : "channel",
            channel: global ? null : channel,
            mutedGlobally: Boolean(target.globalMuted),
            mutedChannels: [...(target.mutedChannels || [])],
            byName: muted ? client.name : "",
        },
    });
    broadcastMemberUpdate(room, target.id);
}

/**
 * Reassigns another client's TID — the 4-digit number private calls are placed
 * against, and how operators are identified on the air.
 *
 * An assignment made by a dispatcher sticks: it is latched so the client's own
 * presence updates cannot quietly put the old number back, which would leave the
 * dispatcher calling a TID nobody answers to.
 */
function setClientTrainId(room, client, payload) {
    const fail = (message) =>
        send(client.ws, { type: "error", payload: { message } });

    if (!isRadioAdmin(client)) {
        fail("Only dispatchers can assign TIDs.");
        return;
    }

    const targetId = String(payload.targetId || "");
    const target = clientsById.get(targetId);
    if (!target || target.roomId !== room.id) {
        fail("That unit is not on this server.");
        return;
    }

    const trainId = String(payload.trainId || "").replace(/[^0-9]/g, "");
    if (!/^\d{4}$/.test(trainId)) {
        fail("A TID is four digits.");
        return;
    }
    if (trainId === target.trainId) {
        return;
    }
    for (const member of room.members.values()) {
        if (member.id !== target.id && member.trainId === trainId) {
            fail("TID " + trainId + " is already in use.");
            return;
        }
    }

    const previous = target.trainId || "";
    target.trainId = trainId;
    target.trainIdLocked = true;
    rememberAssignedTrainId(room, target, trainId);

    const member = room.members.get(target.id);
    if (member) {
        member.trainId = trainId;
    }

    send(target.ws, {
        type: "train-id-assigned",
        payload: { trainId, byName: client.name },
    });

    // Told to the whole room, not just the unit whose number changed. A TID is how everyone
    // addresses that unit on the air, so a dispatcher who did not make the change still needs to
    // see it happen -- otherwise they carry on calling a number nobody answers to.
    broadcastRoom(room, {
        type: "train-id-changed",
        payload: {
            id: target.id,
            trainId,
            previousTrainId: previous,
            name: target.name,
            byName: client.name,
        },
    });

    broadcastMemberUpdate(room, target.id);
}

// ── Private one-to-one calls ──────────────────────────────────────────────
// A private call is strictly two parties. While one is up, both drop off the
// room channel entirely: their audio goes only to each other, and they neither
// hear nor are heard by the rest of the room. PTT arbitration runs per call.

const privateCalls = new Map();
let nextPrivateCallId = 1;

function getCall(client) {
    return client && client.privateCallId
        ? privateCalls.get(client.privateCallId) || null
        : null;
}

function isInActiveCall(client) {
    const call = getCall(client);
    return Boolean(call && call.active);
}

/// The other party, or null when there is no active call.
function activeCallPeer(client) {
    const call = getCall(client);
    if (!call || !call.active) {
        return null;
    }
    const peerId = call.participants.find((id) => id !== client.id);
    return clientsById.get(peerId) || null;
}

function callParty(c) {
    return c ? { id: c.id, name: c.name, trainId: c.trainId } : null;
}

/// tx-state for a call goes only to its two parties, never to the room.
function pushCallTxState(call, speakerId, active) {
    for (const id of call.participants) {
        const party = clientsById.get(id);
        if (!party || party.ws.readyState !== WebSocket.OPEN) {
            continue;
        }
        send(party.ws, {
            type: "tx-state",
            payload: { active, speakerId, channel: "private", private: true },
        });
    }
}

function findClientByTrainId(room, trainId) {
    const wanted = String(trainId || "").trim();
    if (!wanted) {
        return null;
    }
    for (const id of room.clients) {
        const candidate = clientsById.get(id);
        if (candidate && String(candidate.trainId) === wanted) {
            return candidate;
        }
    }
    return null;
}

function endPrivateCall(callId, reason) {
    const call = privateCalls.get(callId);
    if (!call) {
        return;
    }
    privateCalls.delete(callId);

    if (call.active && call.holderId) {
        pushCallTxState(call, call.holderId, false);
    }

    for (const id of call.participants) {
        const party = clientsById.get(id);
        if (!party) {
            continue;
        }
        party.privateCallId = null;
        if (party.ws.readyState === WebSocket.OPEN) {
            send(party.ws, {
                type: "private-call-ended",
                payload: { callId, reason },
            });
        }
    }
}

/// Drops whatever call this client is in, if any. Used on hang-up, disconnect,
/// and whenever something outranks the call (an emergency).
function clearPrivateCallFor(client, reason) {
    if (client && client.privateCallId) {
        endPrivateCall(client.privateCallId, reason);
    }
}

function requestPrivateCall(room, client, targetTrainId) {
    const fail = (message) =>
        send(client.ws, { type: "private-call-failed", payload: { message } });

    if (client.rank === "t1") {
        fail("T1 rank cannot place private calls.");
        return;
    }
    if (getCall(client)) {
        fail("You are already on a private call.");
        return;
    }

    const target = findClientByTrainId(room, targetTrainId);
    if (!target) {
        fail("No unit with TID " + targetTrainId + " on this room.");
        return;
    }
    if (target.id === client.id) {
        fail("You cannot call yourself.");
        return;
    }
    // One-to-one only: a unit already on a call cannot be pulled into another.
    if (getCall(target)) {
        fail("Unit " + target.trainId + " is busy.");
        return;
    }
    // The target has switched private calls off. Refused with the wording the
    // caller is meant to see, and without ringing them — the whole point of the
    // setting is that they are not disturbed.
    if (target.allowCalls === false) {
        fail("Call Denied");
        return;
    }
    if (target.rank === "t1") {
        fail("Unit " + target.trainId + " cannot take private calls.");
        return;
    }

    const callId = "pc" + nextPrivateCallId++;
    const call = {
        id: callId,
        roomId: room.id,
        participants: [client.id, target.id],
        callerId: client.id,
        active: false,
        holderId: null,
        grantedAt: 0,
        createdAt: Date.now(),
    };
    privateCalls.set(callId, call);
    client.privateCallId = callId;
    target.privateCallId = callId;

    send(client.ws, {
        type: "private-call-ringing",
        payload: { callId, peer: callParty(target) },
    });
    send(target.ws, {
        type: "private-call-incoming",
        payload: { callId, peer: callParty(client) },
    });
}

function answerPrivateCall(room, client, accept) {
    const call = getCall(client);
    if (!call || call.active) {
        return;
    }
    // Only the party who was rung may answer.
    if (call.callerId === client.id) {
        return;
    }

    if (!accept) {
        endPrivateCall(call.id, "declined");
        return;
    }

    // Leaving the room channel: drop any hold either party has on it, so the
    // main channel is not left blocked by somebody who has stepped away.
    for (const id of call.participants) {
        const party = clientsById.get(id);
        if (party) {
            releasePTT(room, party, "private-call");
        }
    }

    call.active = true;
    for (const id of call.participants) {
        const party = clientsById.get(id);
        const peer = clientsById.get(call.participants.find((p) => p !== id));
        if (party && party.ws.readyState === WebSocket.OPEN) {
            send(party.ws, {
                type: "private-call-started",
                payload: { callId: call.id, peer: callParty(peer) },
            });
        }
    }
}

/// PTT inside a private call, arbitrated per call rather than per channel.
function privateCallPtt(client, pressed) {
    const call = getCall(client);
    if (!call || !call.active) {
        return false;
    }

    if (pressed) {
        // A call is two people talking, not a channel to be queued for: either
        // party may take the line from the other at any time, and neither gets a
        // courtesy tone for it. Refusing the key here — as this used to — made a
        // one-to-one conversation harder to hold than an open channel.
        const previousHolder = call.holderId;
        if (previousHolder && previousHolder !== client.id) {
            const peer = clientsById.get(previousHolder);
            if (peer && peer.ws.readyState === WebSocket.OPEN) {
                send(peer.ws, {
                    type: "ptt-revoked",
                    payload: { channel: "private", reason: "peer-override" },
                });
            }
            pushCallTxState(call, previousHolder, false);
        }

        call.holderId = client.id;
        call.grantedAt = Date.now();
        send(client.ws, {
            type: "ptt-granted",
            payload: { channel: "private", reason: "private-call" },
        });
        pushCallTxState(call, client.id, true);
        return true;
    }

    if (call.holderId === client.id) {
        call.holderId = null;
        call.grantedAt = 0;
        send(client.ws, {
            type: "ptt-released",
            payload: { reason: "released" },
        });
        pushCallTxState(call, client.id, false);
    }
    return true;
}

// ── Emergency broadcast ───────────────────────────────────────────────────
// A latched, room-wide state raised by an operator. While it is up the line is
// reserved for that operator and the dispatchers, and every client is alarmed.
// Dispatchers are the master of the radio system, so they may also clear it.

/// True when this client is allowed to key up during an active emergency.
function mayTransmitDuringEmergency(room, client) {
    if (!room.emergency) {
        return true;
    }
    return client.id === room.emergency.operatorId || isRadioAdmin(client);
}

function broadcastEmergencyState(room) {
    const e = room.emergency;
    broadcastRoom(room, {
        type: "emergency-state",
        payload: e
            ? {
                  active: true,
                  operatorId: e.operatorId,
                  operatorName: e.operatorName,
                  trainId: e.trainId,
                  channel: e.channel,
                  since: e.startedAt,
                  // How long clients sound the alarm for. Sent with the emergency so
                  // the dispatchers' setting governs every client in the room, rather
                  // than each one deciding for itself.
                  toneSeconds: emergencyToneSeconds(room),
                  // So a client joining mid-emergency does not start an alarm the
                  // dispatchers have already answered.
                  acknowledged: Boolean(e.acknowledged),
              }
            : { active: false },
    });
}

/**
 * Seconds the emergency alarm sounds on every client, dispatcher-adjustable.
 *
 * The alarm is meant to get attention and then get out of the way — the channel
 * stays reserved for as long as the emergency is latched regardless, so this
 * governs the noise, not the lock-out.
 */
const DEFAULT_EMERGENCY_TONE_SECONDS = 20;
const MIN_EMERGENCY_TONE_SECONDS = 5;
const MAX_EMERGENCY_TONE_SECONDS = 120;

function emergencyToneSeconds(room) {
    const raw = Number(room && room.emergencyToneSeconds);
    if (!Number.isFinite(raw) || raw <= 0) return DEFAULT_EMERGENCY_TONE_SECONDS;
    if (raw < MIN_EMERGENCY_TONE_SECONDS) return MIN_EMERGENCY_TONE_SECONDS;
    if (raw > MAX_EMERGENCY_TONE_SECONDS) return MAX_EMERGENCY_TONE_SECONDS;
    return Math.round(raw);
}

/**
 * Acknowledges the emergency alarm: silences the tone on every client without
 * standing the emergency down.
 *
 * These are two different things and conflating them was the trap here. The
 * alarm is the noise; the emergency is the reservation of the channel. A
 * dispatcher who has seen the alarm wants the noise to stop so they can talk to
 * the train — they do not want the lock-out lifted, which is what clearing the
 * emergency would do and would let every other train key up over the incident.
 */
function acknowledgeEmergency(room, client) {
    if (!isRadioAdmin(client)) {
        send(client.ws, {
            type: "error",
            payload: { message: "Only dispatchers can acknowledge an emergency." },
        });
        return;
    }
    if (!room.emergency) return;
    if (room.emergency.acknowledged) return;

    room.emergency.acknowledged = true;
    room.emergency.acknowledgedBy = client.name;

    broadcastRoom(room, {
        type: "emergency-acknowledged",
        payload: {
            byName: client.name,
            operatorId: room.emergency.operatorId,
        },
    });
}

/**
 * Seconds a transmission must run before another operator's PTT takes the line
 * from them, dispatcher-adjustable per room.
 *
 * This is the lever for an open mic or somebody hogging the channel: it is a
 * floor on interruption, not a transmission limit — nobody is ever cut off
 * unless another operator actually wants to speak.
 */
const MIN_INTERRUPT_SECONDS = 20;
const MAX_INTERRUPT_SECONDS = 200;

function interruptSeconds(room) {
    const raw = Number(room && room.interruptSeconds);
    if (!Number.isFinite(raw) || raw <= 0) {
        // Not set for this room yet: fall back to the deployment default, which
        // may legitimately be 0 to disable interruption altogether.
        return PTT_INTERRUPT_SECONDS;
    }
    if (raw < MIN_INTERRUPT_SECONDS) return MIN_INTERRUPT_SECONDS;
    if (raw > MAX_INTERRUPT_SECONDS) return MAX_INTERRUPT_SECONDS;
    return Math.round(raw);
}

/**
 * Every channel a client's transmission should go out on.
 *
 * Ordinarily just the one they are standing on. A dispatcher may add others, or
 * arm "transmit all" — the point being a single announcement that reaches every
 * channel at once instead of repeating it five times. Private calls are not
 * channels and are never included.
 */
function transmitChannelsFor(client) {
    const channels = new Set();
    if (client.channel) channels.add(client.channel);
    if (!isRadioAdmin(client)) return channels;

    if (client.transmitAll) {
        for (const id of channelIds()) channels.add(id);
        return channels;
    }
    for (const id of client.multiChannels || []) {
        if (channelExists(id)) channels.add(id);
    }
    return channels;
}

/// Sets which extra channels a dispatcher keys alongside their own.
function setTransmitChannels(room, client, payload) {
    if (!isRadioAdmin(client)) {
        send(client.ws, {
            type: "error",
            payload: { message: "Only dispatchers can transmit to several channels." },
        });
        return;
    }

    client.transmitAll = Boolean(payload.all);
    const next = new Set();
    if (Array.isArray(payload.channels)) {
        for (const raw of payload.channels) {
            const id = slugifyChannelId(raw);
            // The channel they are standing on is always keyed; listing it as an
            // extra would double up.
            if (channelExists(id) && id !== client.channel) next.add(id);
        }
    }
    client.multiChannels = next;

    send(client.ws, {
        type: "transmit-channels",
        payload: {
            all: client.transmitAll,
            channels: [...next],
            effective: [...transmitChannelsFor(client)],
        },
    });
}

/// Sets the room's interruption window. Dispatchers only.
function setInterruptSeconds(room, client, payload) {
    if (!isRadioAdmin(client)) {
        send(client.ws, {
            type: "error",
            payload: { message: "Only dispatchers can set the override timer." },
        });
        return;
    }
    const seconds = Number(payload.seconds);
    if (!Number.isFinite(seconds) || seconds <= 0) {
        send(client.ws, {
            type: "error",
            payload: { message: "Override timer must be a number of seconds." },
        });
        return;
    }
    room.interruptSeconds = seconds;
    broadcastRoom(room, {
        type: "interrupt-seconds",
        payload: { seconds: interruptSeconds(room) },
    });
}

/// Sets the room's alarm duration. Dispatchers only.
function setEmergencyToneSeconds(room, client, payload) {
    if (!isRadioAdmin(client)) {
        send(client.ws, {
            type: "error",
            payload: { message: "Only dispatchers can set the alarm duration." },
        });
        return;
    }
    const seconds = Number(payload.seconds);
    if (!Number.isFinite(seconds) || seconds <= 0) {
        send(client.ws, {
            type: "error",
            payload: { message: "Alarm duration must be a number of seconds." },
        });
        return;
    }
    room.emergencyToneSeconds = seconds;
    broadcastRoom(room, {
        type: "emergency-tone-seconds",
        payload: { seconds: emergencyToneSeconds(room) },
    });
}

function setEmergency(room, client, active) {
    if (active) {
        if (room.emergency) {
            // Already raised; re-broadcast so a late joiner or a client that missed
            // the first alarm is brought into step.
            broadcastEmergencyState(room);
            return;
        }

        // An emergency overrides all communications, private calls included — the
        // raiser needs to be on the open channel, not tied up one-to-one.
        clearPrivateCallFor(client, "emergency");

        room.emergency = {
            operatorId: client.id,
            operatorName: client.name,
            trainId: client.trainId,
            channel: client.channel,
            startedAt: Date.now(),
        };

        // Override whoever holds the line, ignoring the usual interrupt window.
        const channelState = getChannelState(room, client.channel);
        if (channelState && channelState.holderId !== client.id) {
            const previousHolder = clientsById.get(channelState.holderId);
            if (previousHolder && previousHolder.ws.readyState === WebSocket.OPEN) {
                send(previousHolder.ws, {
                    type: "ptt-revoked",
                    payload: { channel: client.channel, reason: "emergency" },
                });
            }
            if (channelState.holderId) {
                pushTxState(room, channelState.holderId, client.channel, false);
            }
            channelState.queue = [];
            channelState.holderId = null;
            channelState.grantedAt = 0;
            pushChannelSnapshot(room, client.channel);
        }

        broadcastEmergencyState(room);
        return;
    }

    if (!room.emergency) {
        return;
    }

    // Only the operator who raised it, or a dispatcher, may stand it down.
    if (room.emergency.operatorId !== client.id && !isRadioAdmin(client)) {
        send(client.ws, {
            type: "error",
            payload: { message: "Only the raising operator or a dispatcher can clear an emergency." },
        });
        return;
    }

    const raiser = clientsById.get(room.emergency.operatorId);
    room.emergency = null;
    if (raiser) {
        releasePTT(room, raiser, "emergency-cleared");
    }
    broadcastEmergencyState(room);
}

/**
 * Keys one channel for this client.
 *
 * `secondary` marks a channel being keyed as part of a multi-channel broadcast:
 * the client is not moved onto it and does not get a second ptt-granted for it,
 * because they are still standing on their own channel and already know they
 * are transmitting.
 */
function requestPTT(room, client, channelName, secondary = false) {
    if (!channelExists(channelName)) {
        send(client.ws, {
            type: "error",
            payload: { message: "Unknown channel." },
        });
        return;
    }

    if (!secondary) client.channel = channelName;
    const channelState = getChannelState(room, channelName);
    if (!channelState) {
        return;
    }

    // A dispatcher has muted this client off the open channels. Private calls are
    // arbitrated before this is ever reached, so a muted operator can still be
    // spoken to one-to-one — they are off the air, not cut off.
    if (isMutedOn(client, channelName)) {
        send(client.ws, {
            type: "ptt-denied",
            payload: { channel: channelName, reason: "muted" },
        });
        return;
    }

    // While an emergency is up the line belongs to the raising operator and the
    // dispatchers; everybody else is locked out of transmitting (they still hear it).
    if (!mayTransmitDuringEmergency(room, client)) {
        send(client.ws, {
            type: "ptt-denied",
            payload: { channel: channelName, reason: "emergency" },
        });
        return;
    }

    if (!channelState.holderId || channelState.holderId === client.id) {
        channelState.holderId = client.id;
        channelState.grantedAt = Date.now();

        if (!secondary) {
            send(client.ws, {
                type: "ptt-granted",
                payload: {
                    channel: channelName,
                    reason: "free-channel",
                },
            });
        }

        pushTxState(room, client.id, channelName, true);
        pushChannelSnapshot(room, channelName);
        return;
    }

    // The channel is held by somebody else. Once they have blocked the line for
    // longer than the configured limit, take it from them rather than queueing,
    // so one stuck or over-long transmission cannot hold the channel forever.
    //
    // A dispatcher does not wait out that window at all. They administer the
    // radio, and the traffic they need to break into — an operator running long,
    // or one who needs stopping — is exactly the traffic the window would make
    // them sit through.
    const heldForMs = channelState.grantedAt
        ? Date.now() - channelState.grantedAt
        : 0;
    const dispatcherOverride = isRadioAdmin(client);
    const windowSeconds = interruptSeconds(room);
    if (
        dispatcherOverride ||
        (windowSeconds > 0 && heldForMs >= windowSeconds * 1000)
    ) {
        const previousHolder = clientsById.get(channelState.holderId);

        channelState.queue = channelState.queue.filter(
            (id) => id !== client.id && id !== channelState.holderId,
        );

        if (previousHolder && previousHolder.ws.readyState === WebSocket.OPEN) {
            send(previousHolder.ws, {
                type: "ptt-revoked",
                payload: {
                    channel: channelName,
                    reason: dispatcherOverride
                        ? "dispatcher-override"
                        : "interrupted",
                    heldSeconds: Math.round(heldForMs / 1000),
                },
            });
        }
        // Close out the old transmission before opening the new one, so listeners
        // see a clean stop/start rather than the speaker appearing to change mid-air.
        pushTxState(room, channelState.holderId, channelName, false);

        channelState.holderId = client.id;
        channelState.grantedAt = Date.now();

        if (!secondary) {
            send(client.ws, {
                type: "ptt-granted",
                payload: {
                    channel: channelName,
                    reason: dispatcherOverride
                        ? "dispatcher-override"
                        : "interrupted-previous",
                },
            });
        }

        pushTxState(room, client.id, channelName, true);
        pushChannelSnapshot(room, channelName);
        return;
    }

    if (!channelState.queue.includes(client.id)) {
        channelState.queue.push(client.id);
    }

    send(client.ws, {
        type: "ptt-queued",
        payload: {
            channel: channelName,
            position: channelState.queue.length,
        },
    });

    pushChannelSnapshot(room, channelName);
}

app.get("/api/rooms", (_req, res) => {
    const dbRooms = stmts.getRooms.all();
    const roomList = dbRooms.map((r) => {
        const live = rooms.get(r.id);
        const members = live
            ? Array.from(live.members.values()).map((m) => ({ name: m.name }))
            : [];
        return {
            id: r.id,
            name: r.name,
            allowAnyone: Boolean(r.allow_anyone),
            createdAt: r.created_at * 1000,
            creatorUsername: r.creator_username,
            memberCount: live ? live.clients.size : 0,
            members: members,
        };
    });
    res.json({ rooms: roomList });
});

app.get("/api/rooms/:roomId", (req, res) => {
    const room = rooms.get(req.params.roomId);
    if (!room) {
        res.status(404).json({ error: "Room not found" });
        return;
    }

    res.json({
        room: getRoomSummary(room),
    });
});

app.post("/api/rooms", requireGlobalAdmin, (req, res) => {
    const { roomName } = req.body;
    const creatorId = req.userId;
    const creatorUsername = req.username;

    let roomId = "";
    for (let i = 0; i < 10; i += 1) {
        const candidate = `room-${randomBytes(5).toString("hex")}`;
        if (!stmts.getRoomById.get(candidate) && !rooms.has(candidate)) {
            roomId = candidate;
            break;
        }
    }

    if (!roomId) {
        res.status(500).json({ error: "Failed to generate room id" });
        return;
    }

    const name = String(roomName || `Server ${roomId.slice(-4)}`);

    stmts.createRoom.run(roomId, name, creatorId, creatorUsername);

    const room = createRoom(roomId, creatorId, creatorUsername, name);

    // Save creator as admin in user_roles
    stmts.setUserRole.run(creatorId, roomId, "admin");

    res.status(201).json({
        room: { id: roomId, name, creatorUsername },
        creatorId,
    });
});

app.get("/api/rooms/:roomId/members", requireGlobalStaff, (req, res) => {
    const room = rooms.get(req.params.roomId);
    if (!room) {
        res.status(404).json({ error: "Room not found" });
        return;
    }

    const members = Array.from(room.members.values()).map((m) => {
        // Resolve assigned rank from DB / creator status
        let assignedRank;
        if (m.accountId && room.creatorId === m.accountId) {
            assignedRank = "admin";
        } else if (m.accountId) {
            const saved = stmts.getUserRole.get(m.accountId, room.id);
            assignedRank = saved ? normalizeRank(saved.role) : "t1";
        } else {
            assignedRank = "t1";
        }
        return {
            id: m.id,
            name: m.name,
            role: m.role, // session role (listener/operator/dispatcher or admin/mod for staff)
            rank: assignedRank, // global rank
            line: m.line,
            trainId: m.trainId,
        };
    });

    res.json({ members });
});

// Returns all users who have ever been assigned a role in this room (online + offline)
app.get("/api/rooms/:roomId/roster", requireGlobalStaff, (req, res) => {
    const { roomId } = req.params;

    const room = rooms.get(roomId);
    if (!room) {
        res.status(404).json({ error: "Room not found" });
        return;
    }

    // Build a set of online accountIds for quick lookup
    const onlineAccountIds = new Set();
    for (const member of room.members.values()) {
        if (member.accountId) onlineAccountIds.add(member.accountId);
    }

    const roster = stmts.getRoster.all(roomId).map((row) => ({
        userId: row.user_id,
        username: row.username,
        rank: normalizeRank(row.role), // stored as legacy or new rank value
        online: onlineAccountIds.has(row.user_id),
        grantedAt: row.granted_at * 1000,
    }));

    res.json({ roster });
});

// Change role for a user in the roster (works for offline users too)
app.post(
    "/api/rooms/:roomId/roster/:userId/role",
    requireGlobalStaff,
    (req, res) => {
        const { roomId, userId } = req.params;
        const { role } = req.body;
        const requesterId = req.userId;

        const room = rooms.get(roomId);
        if (!room) {
            res.status(404).json({ error: "Room not found" });
            return;
        }

        // Prevent self-role-change
        if (userId === requesterId) {
            res.status(403).json({ error: "You cannot change your own role" });
            return;
        }

        if (!ALLOWED_RANKS.has(role)) {
            res.status(400).json({ error: "Invalid rank" });
            return;
        }

        // Only admins may assign admin or moderator ranks.
        if (
            !isGlobalAdminUser(requesterId) &&
            (role === "admin" || role === "mod")
        ) {
            res.status(403).json({
                error: "Only admins can assign admin or mod ranks",
            });
            return;
        }

        stmts.setUserRole.run(userId, roomId, role);

        // If the user is currently online, update their live rank + cap session role
        const liveClient = clientsByAccountId.get(userId);
        if (liveClient && liveClient.roomId === roomId) {
            liveClient.rank = role;
            const member = room.members.get(liveClient.id);
            if (member) {
                member.rank = role;
                // Cap session role to what the new rank allows
                if (!STAFF_RANKS.has(role)) {
                    const capped = capSessionRole(liveClient.role, role);
                    liveClient.role = capped;
                    member.role = capped;
                }
                if (role === "t1") releasePTT(room, liveClient, "revoked");

                // If downgrading to T2 or T1, force user to operators channel
                if (role === "t2" || role === "t1") {
                    liveClient.channel = DEFAULT_CHANNEL;
                    member.channel = DEFAULT_CHANNEL;
                }

                const summary = getClientSummary(member);
                broadcastRoom(
                    room,
                    {
                        type: "peer-updated",
                        payload: summary,
                    },
                    liveClient.id,
                );

                // Send channel change notification to the affected user
                if (role === "t2" || role === "t1") {
                    send(liveClient.ws, {
                        type: "channel-changed",
                        payload: {
                            id: liveClient.id,
                            channel: DEFAULT_CHANNEL,
                        },
                    });
                }

                // Send updated available channels based on new rank
                send(liveClient.ws, {
                    type: "channels-updated",
                    payload: { channels: getChannelDescriptors(role) },
                });

                broadcastRoom(room, {
                    type: "peer-rank-changed",
                    payload: {
                        id: liveClient.id,
                        rank: role,
                        role: member.role,
                    },
                });
            }
        }

        res.json({ ok: true });
    },
);

// Change SESSION ROLE of an online member (temporary, not persisted, capped by rank)
app.post(
    "/api/rooms/:roomId/members/:memberId/role",
    requireGlobalStaff,
    (req, res) => {
        const { roomId, memberId } = req.params;
        const { role } = req.body; // listener | operator | dispatcher
        const requesterId = req.userId;

        const room = rooms.get(roomId);
        if (!room) {
            res.status(404).json({ error: "Room not found" });
            return;
        }
        if (!ALLOWED_SESSION_ROLES.has(role)) {
            res.status(400).json({ error: "Invalid session role" });
            return;
        }

        const member = room.members.get(memberId);
        if (!member) {
            res.status(404).json({ error: "Member not found" });
            return;
        }
        if (member.accountId && member.accountId === requesterId) {
            res.status(403).json({
                error: "You cannot change your own session role",
            });
            return;
        }

        // Cap the requested session role to what the member's rank allows
        const allowed = allowedSessionRoles(member.rank || "t1");
        const capped = allowed.includes(role) ? role : allowed[0];

        member.role = capped;
        const targetClient = clientsById.get(memberId);
        if (targetClient) {
            targetClient.role = capped;
            if (capped === "listener")
                releasePTT(room, targetClient, "revoked");
        }

        broadcastRoom(room, {
            type: "peer-session-role-changed",
            payload: { id: memberId, role: capped },
        });
        res.json({ ok: true });
    },
);

// Change RANK of an online member (also persists to DB)
app.post(
    "/api/rooms/:roomId/members/:memberId/rank",
    requireGlobalStaff,
    (req, res) => {
        const { roomId, memberId } = req.params;
        const { rank } = req.body;
        const requesterId = req.userId;

        const room = rooms.get(roomId);
        if (!room) {
            res.status(404).json({ error: "Room not found" });
            return;
        }
        if (!ALLOWED_RANKS.has(rank)) {
            res.status(400).json({ error: "Invalid rank" });
            return;
        }

        // Only admins may assign admin or moderator ranks.
        if (
            !isGlobalAdminUser(requesterId) &&
            (rank === "admin" || rank === "mod")
        ) {
            res.status(403).json({
                error: "Only admins can assign admin or mod ranks",
            });
            return;
        }

        const member = room.members.get(memberId);
        if (!member) {
            res.status(404).json({ error: "Member not found" });
            return;
        }
        if (member.accountId && member.accountId === requesterId) {
            res.status(403).json({ error: "You cannot change your own rank" });
            return;
        }

        member.rank = rank;
        const targetClient = clientsById.get(memberId);
        if (targetClient) {
            targetClient.rank = rank;
            if (!STAFF_RANKS.has(rank)) {
                const capped = capSessionRole(targetClient.role, rank);
                targetClient.role = capped;
                member.role = capped;
            }
            if (rank === "t1") releasePTT(room, targetClient, "revoked");

            // If downgrading to T2 or T1, force user to operators channel
            if (rank === "t2" || rank === "t1") {
                targetClient.channel = DEFAULT_CHANNEL;
                member.channel = DEFAULT_CHANNEL;
            }
        }

        if (member.accountId) {
            stmts.setUserRole.run(member.accountId, roomId, rank);
        }

        const summary = getClientSummary(member);
        broadcastRoom(
            room,
            {
                type: "peer-updated",
                payload: summary,
            },
            memberId,
        );

        // Send channel change notification to the affected user
        if (targetClient && (rank === "t2" || rank === "t1")) {
            send(targetClient.ws, {
                type: "channel-changed",
                payload: { id: memberId, channel: DEFAULT_CHANNEL },
            });
        }

        // Send updated available channels based on new rank
        if (targetClient) {
            send(targetClient.ws, {
                type: "channels-updated",
                payload: { channels: getChannelDescriptors(rank) },
            });
        }

        broadcastRoom(room, {
            type: "peer-rank-changed",
            payload: { id: memberId, rank, role: member.role },
        });
        res.json({ ok: true, member: getClientSummary(member) });
    },
);

app.post(
    "/api/rooms/:roomId/members/:memberId/kick",
    requireGlobalStaff,
    (req, res) => {
        const { roomId, memberId } = req.params;

        const room = rooms.get(roomId);
        if (!room) {
            res.status(404).json({ error: "Room not found" });
            return;
        }

        const member = room.members.get(memberId);
        if (!member) {
            res.status(404).json({ error: "Member not found" });
            return;
        }

        // Find and disconnect the client
        const client = clientsById.get(memberId);
        if (client && client.ws && client.ws.readyState === WebSocket.OPEN) {
            send(client.ws, {
                type: "kicked",
                payload: { reason: "Kicked by moderator" },
            });
            client.ws.close(1000, "Kicked");
        }

        res.json({ ok: true, message: "Member kicked" });
    },
);

app.patch("/api/rooms/:roomId", requireGlobalAdmin, (req, res) => {
    const { roomId } = req.params;
    const room = rooms.get(roomId);
    const dbRoom = stmts.getRoomById.get(roomId);

    if (!room && !dbRoom) {
        res.status(404).json({ error: "Room not found" });
        return;
    }

    const hasName = typeof (req.body && req.body.name) === "string";
    const hasAllowAnyone = Object.prototype.hasOwnProperty.call(
        req.body || {},
        "allowAnyone",
    );
    if (!hasName && !hasAllowAnyone) {
        // Treat empty PATCH payload as a no-op for better client resilience.
        res.json({
            ok: true,
            room: {
                id: roomId,
                name: dbRoom
                    ? dbRoom.name
                    : room
                      ? room.name
                      : `Server ${roomId.slice(-4)}`,
                allowAnyone: Boolean(
                    (dbRoom && dbRoom.allow_anyone) ||
                    (room && room.allowAnyone),
                ),
            },
        });
        return;
    }

    let name = dbRoom
        ? dbRoom.name
        : room
          ? room.name
          : `Server ${roomId.slice(-4)}`;
    if (hasName) {
        const requestedName = String(req.body.name || "").trim();
        if (requestedName) {
            name = requestedName.slice(0, 80);
            stmts.updateRoomName.run(name, roomId);
            if (room) {
                room.name = name;
            }
        } else if (!hasAllowAnyone) {
            // Only reject blank names when name is the only requested change.
            res.status(400).json({ error: "Invalid name" });
            return;
        }
    }

    let allowAnyone = Boolean(
        (dbRoom && dbRoom.allow_anyone) || (room && room.allowAnyone),
    );
    if (hasAllowAnyone) {
        allowAnyone = Boolean(req.body.allowAnyone);
        stmts.updateRoomJoinPolicy.run(allowAnyone ? 1 : 0, roomId);
        if (room) {
            room.allowAnyone = allowAnyone;
        }
    }

    res.json({ ok: true, room: { id: roomId, name, allowAnyone } });
});

app.delete("/api/rooms/:roomId", requireGlobalAdmin, (req, res) => {
    const { roomId } = req.params;
    const room = rooms.get(roomId);
    const dbRoom = stmts.getRoomById.get(roomId);

    if (!room && !dbRoom) {
        res.status(404).json({ error: "Room not found" });
        return;
    }

    if (room) {
        for (const clientId of room.clients) {
            const client = clientsById.get(clientId);
            if (
                client &&
                client.ws &&
                client.ws.readyState === WebSocket.OPEN
            ) {
                send(client.ws, {
                    type: "kicked",
                    payload: { reason: "Server removed by admin" },
                });
                client.ws.close(1000, "Server removed");
            }
        }
    }

    stmts.clearRoomRoles.run(roomId);
    stmts.deleteRoom.run(roomId);
    rooms.delete(roomId);

    res.json({ ok: true, roomId });
});

// Restore persisted rooms from SQLite on startup
for (const r of stmts.getRooms.all()) {
    if (!rooms.has(r.id)) {
        const room = {
            id: r.id,
            createdAt: r.created_at * 1000,
            creatorId: r.creator_id,
            creatorName: r.creator_username,
            name: r.name,
            allowAnyone: Boolean(r.allow_anyone),
            members: new Map(),
            clients: new Set(),
            channels: new Map(
                channelIds().map((name) => [
                    name,
                    { holderId: null, grantedAt: 0, queue: [] },
                ]),
            ),
        };
        rooms.set(r.id, room);
    }
}

wss.on("connection", (ws, req) => {
    const client = {
        id: randomUUID(),
        ws,
        roomId: null,
        userId: null,
        name: "",
        role: "operator",
        line: "A",
        trainId: "",
        // Set once a dispatcher assigns the TID, after which the client's own
        // presence updates no longer get to change it.
        trainIdLocked: false,
        channel: DEFAULT_CHANNEL,
        transport: "webrtc",
        // Set on join for connections from the dispatcher board.
        isBoardClient: false,
        // Muted off the open channels by a dispatcher; private calls still work.
        // Global covers every main channel; mutedChannels covers individual ones.
        globalMuted: false,
        mutedChannels: new Set(),
        /// Whether this client accepts incoming private calls. Their own choice.
        allowCalls: true,
        // ── Multi-channel transmit (dispatchers) ──────────────────
        /// Extra channels this dispatcher keys alongside the one they stand on.
        multiChannels: new Set(),
        /// True while "transmit to all" is armed.
        transmitAll: false,
        /// Channels currently keyed. Empty unless transmitting.
        txChannels: new Set(),
        /// Which dispatcher muted them, for display.
        mutedByName: "",
        /// Set when the socket misses a heartbeat; see the heartbeat sweep.
        degraded: false,
        privateCallId: null,
        wsUrl: req.url,
        wsHeaders: req.headers,
    };

    // Heartbeat: flags live on the socket so the sweep needs no client lookup,
    // and a back-reference so it can publish the degraded state to the room.
    ws.isAlive = true;
    ws.missedPongs = 0;
    ws.voiceClient = client;
    ws.on("pong", () => {
        ws.isAlive = true;
    });

    ws.on("message", (raw, isBinary) => {
        // Binary = PCM audio frame from the current PTT holder → relay to channel peers
        if (isBinary) {
            // On a private call the audio goes to the other party and nowhere else.
            const call = getCall(client);
            if (call && call.active) {
                if (call.holderId !== client.id) {
                    return;
                }
                const peer = activeCallPeer(client);
                if (peer && peer.ws.readyState === WebSocket.OPEN) {
                    peer.ws.send(raw, { binary: true });
                }
                return;
            }

            if (client.roomId) {
                const room = rooms.get(client.roomId);
                if (room) {
                    // Fan out across every channel this client currently holds. A
                    // dispatcher transmitting to all channels holds several at once,
                    // and each listener should hear it exactly once wherever they are.
                    const keyed = [];
                    for (const ch of client.txChannels || []) {
                        const st = getChannelState(room, ch);
                        if (st && st.holderId === client.id) keyed.push(ch);
                    }
                    if (keyed.length === 0) {
                        const fallback = getChannelState(room, client.channel);
                        if (fallback && fallback.holderId === client.id) {
                            keyed.push(client.channel);
                        }
                    }
                    if (keyed.length > 0) {
                        const audience = new Set(keyed);
                        const senderRelayOnly = client.transport === "relay";
                        for (const lid of room.clients) {
                            if (lid === client.id) continue;
                            const listener = clientsById.get(lid);
                            if (
                                !listener ||
                                !audience.has(listener.channel) ||
                                listener.ws.readyState !== WebSocket.OPEN
                            ) {
                                continue;
                            }
                            // Anyone on a private call has stepped off the channel.
                            if (isInActiveCall(listener)) {
                                continue;
                            }
                            // When both ends speak WebRTC the peer mesh already carries
                            // this audio; relaying it too would play the transmission twice.
                            if (
                                !senderRelayOnly &&
                                listener.transport !== "relay"
                            ) {
                                continue;
                            }
                            listener.ws.send(raw, { binary: true });
                        }
                    }
                }
            }
            return;
        }

        let msg;
        try {
            msg = JSON.parse(String(raw));
        } catch (_err) {
            send(ws, {
                type: "error",
                payload: { message: "Invalid JSON payload." },
            });
            return;
        }

        const { type, payload = {} } = msg;

        if (type === "join") {
            const roomId = String(payload.roomId || DEFAULT_ROOM_ID);
            const room = getRoom(roomId);
            const userName = String(
                payload.userName || generateOperatorName(client.id),
            );

            client.roomId = roomId;
            client.userId = client.id;
            client.name = userName;

            // Determine account identity from session token
            const wsToken = getTokenFromRequestUrl(
                client.wsUrl || "",
                "localhost",
            );
            const wsPayload =
                verifySessionToken(wsToken) ||
                verifySessionToken(getTokenFromHeaders(client.wsHeaders || {}));
            const accountId = wsPayload ? wsPayload.sub : null;
            const roomAllowsAnyone = Boolean(room && room.allowAnyone);
            // Anonymous game-client connections are allowed when ALLOW_ANONYMOUS_WS=true
            if (
                !ALLOW_ANONYMOUS_WS &&
                (!accountId ||
                    (!isGlobalAdminUser(accountId) && !roomAllowsAnyone))
            ) {
                send(ws, {
                    type: "error",
                    payload: {
                        message:
                            "This server is restricted. Admin can enable Anyone Can Join.",
                    },
                });
                ws.close(1008, "Server restricted");
                return;
            }
            client.accountId = accountId;

            // One live session per person. Covers signed-in dispatchers by
            // account and everyone else by name, and runs before this client is
            // added to the room so the peer list it receives cannot contain the
            // session it just replaced.
            evictDuplicateSessions(room, client);
            if (accountId) {
                clientsByAccountId.set(accountId, client);
            }

            // Resolve rank — anonymous game clients get t2 (operator) so they can transmit
            let rank;
            if (accountId && room.creatorId === accountId) {
                rank = "admin";
                stmts.setUserRole.run(accountId, roomId, rank);
            } else if (accountId) {
                const saved = stmts.getUserRole.get(accountId, roomId);
                rank = saved ? normalizeRank(saved.role) : "t1";
                // Ensure the user's rank is saved to the roster (even if T1)
                stmts.setUserRole.run(accountId, roomId, rank);
            } else {
                // Anonymous game client — grant operator rank so PTT works out of the box
                rank = "t2";
            }
            // The dispatcher board is a dispatcher console — there is nothing
            // else to be on it. A signed-in board session therefore always holds
            // the dispatcher role, rather than being capped down to whatever rank
            // happens to be on the room roster.
            //
            // Without this a dispatcher whose account had no saved role for the
            // room resolved to t1 above, which is listener-only: the board came
            // up unable to transmit, clear an emergency or place a call, and said
            // nothing about why. Signing in left you with less than an anonymous
            // game client, which gets t2.
            //
            // The lift is for this session only. It is applied after the roster
            // write above, so it never promotes the underlying account.
            // Anonymous board sessions are not refused here: a connection with
            // no account only gets this far on a server that has deliberately
            // enabled ALLOW_ANONYMOUS_WS, and the check above has already turned
            // away accountless clients everywhere else. Refusing again would
            // break local development for no gain in protection.
            const isBoardClient = String(payload.client || "") === "board";
            if (isBoardClient && !STAFF_RANKS.has(rank) && rank !== "t3") {
                rank = "t3";
            }

            client.rank = rank;
            client.isBoardClient = isBoardClient;

            // Staff always connect at their rank as session role; others pick a session role
            if (STAFF_RANKS.has(rank)) {
                client.role = rank; // "admin" or "mod" as session role for display
            } else if (isBoardClient) {
                client.role = "dispatcher";
            } else {
                const requestedSessionRole = normalizeSessionRole(payload.role);
                client.role = capSessionRole(requestedSessionRole, rank);
            }

            client.trainId = String(payload.trainId || "").replace(
                /[^0-9]/g,
                "",
            );
            // Auto-assign a unique 4-digit train ID if not provided or empty
            if (!client.trainId) {
                client.trainId = generateUniqueTrainId(room);
            }
            client.channel = capChannel(
                payload.channel || DEFAULT_CHANNEL,
                rank,
            );
            client.transport = normalizeTransport(payload.transport);

            // A mute the dispatchers set earlier follows them back in.
            applyStandingMute(room, client);
            // As does a TID they assigned -- applied after the join payload has
            // been read, so a reconnect cannot be used to shed it.
            applyAssignedTrainId(room, client);

            // Add to room members
            room.clients.add(client.id);
            room.members.set(client.id, {
                id: client.id,
                accountId: accountId,
                name: client.name,
                role: client.role,
                rank: client.rank,
                trainId: client.trainId,
                channel: client.channel,
                transport: client.transport,
                muted: isMutedHere(client),
                mutedGlobally: Boolean(client.globalMuted),
                mutedChannels: [...(client.mutedChannels || [])],
                mutedByName: client.mutedByName,
                degraded: client.degraded,
            });
            clientsById.set(client.id, client);

            const peers = [...room.clients]
                .filter((id) => id !== client.id)
                .map((id) => {
                    const member = room.members.get(id);
                    return getClientSummary(member);
                })
                .filter(Boolean);

            const self = room.members.get(client.id);

            send(ws, {
                type: "joined",
                payload: {
                    self: getClientSummary(self),
                    peers,
                    channels: getChannelDescriptors(rank),
                    roomId,
                    roomName: room.name,
                    rank,
                    isAdmin: rank === "admin",
                    isMod: rank === "mod",
                    isT1: rank === "t1",
                    // Radio authority, which dispatchers hold regardless of rank.
                    // Distinct from isAdmin, which is account-level.
                    isRadioAdmin: isRadioAdmin(client),
                    emergencyToneSeconds: emergencyToneSeconds(room),
                    interruptSeconds: interruptSeconds(room),
                    // So a client joining mid-emergency is alarmed straight away.
                    emergency: room.emergency
                        ? {
                              active: true,
                              operatorId: room.emergency.operatorId,
                              operatorName: room.emergency.operatorName,
                              trainId: room.emergency.trainId,
                              channel: room.emergency.channel,
                              since: room.emergency.startedAt,
                              toneSeconds: emergencyToneSeconds(room),
                              acknowledged: Boolean(room.emergency.acknowledged),
                          }
                        : { active: false },
                },
            });

            broadcastRoom(
                room,
                {
                    type: "peer-joined",
                    payload: getClientSummary(room.members.get(client.id)),
                },
                client.id,
            );

            for (const channelName of channelIds()) {
                pushChannelSnapshot(room, channelName);
            }

            return;
        }

        if (!client.roomId) {
            send(ws, {
                type: "error",
                payload: { message: "Join a room first." },
            });
            return;
        }

        const room = rooms.get(client.roomId);
        if (!room) {
            return;
        }

        if (type === "signal") {
            const targetId = String(payload.to || "");
            const target = clientsById.get(targetId);
            if (target) {
                send(target.ws, {
                    type: "signal",
                    payload: {
                        from: client.id,
                        data: payload.data,
                    },
                });
            }
            return;
        }

        if (type === "set-presence") {
            // Train ID must be numeric only. A TID a dispatcher assigned is not
            // the client's to change back.
            if (payload.trainId && !client.trainIdLocked) {
                client.trainId = String(payload.trainId).replace(/[^0-9]/g, "");
            }

            let roleChanged = false;
            if (STAFF_RANKS.has(client.rank)) {
                if (client.role !== client.rank) {
                    client.role = client.rank;
                    roleChanged = true;
                }
            } else if (client.isBoardClient) {
                // A board session stays a dispatcher session; a presence update
                // must not quietly demote the console mid-shift.
                if (client.role !== "dispatcher") {
                    client.role = "dispatcher";
                    roleChanged = true;
                }
            } else {
                const requestedRole = normalizeSessionRole(
                    payload.role || client.role,
                );
                const cappedRole = capSessionRole(requestedRole, client.rank);
                if (cappedRole !== client.role) {
                    client.role = cappedRole;
                    roleChanged = true;
                }
            }

            const member = room.members.get(client.id);
            if (member) {
                member.trainId = client.trainId;
                if (member.role !== client.role) {
                    member.role = client.role;
                    roleChanged = true;
                }
            }

            if (roleChanged && client.role === "listener") {
                releasePTT(room, client, "revoked");
            }

            if (roleChanged) {
                broadcastRoom(room, {
                    type: "peer-session-role-changed",
                    payload: { id: client.id, role: client.role },
                });
            }

            broadcastRoom(
                room,
                {
                    type: "peer-updated",
                    payload: getClientSummary(member),
                },
                client.id,
            );
            return;
        }

        if (type === "set-channel") {
            const newChannel = capChannel(
                payload.channel || DEFAULT_CHANNEL,
                client.rank,
            );
            const previousChannel = client.channel;
            if (newChannel === previousChannel) {
                return;
            }

            // Leave the old channel properly before standing on the new one.
            // Without this a client keeps whatever they held on the channel they
            // walked away from: the line stays keyed for everybody still on it,
            // and their place in its queue is still theirs. A client belongs to
            // exactly one channel, so leaving has to be as real as arriving.
            //
            // Every keyed channel is let go, not just the one being left. A
            // dispatcher broadcasting holds several at once, and releasePTT only
            // ever addresses client.channel, so moving channel mid-broadcast left
            // the rest keyed by them -- verified against the previous code, which
            // released only the channel being left.
            //
            // A held channel does block other operators: theirs queues behind it.
            // How long the stale hold survives was not pinned down; it did clear
            // by itself in every sequence tried. Releasing all of them here makes
            // that moot rather than relying on whatever cleared it.
            const keyedBefore = [...(client.txChannels || [])];
            client.txChannels = new Set();
            if (keyedBefore.length === 0) {
                releasePTT(room, client, "channel-changed");
            } else {
                for (const ch of keyedBefore) {
                    releaseChannelFor(room, client, ch, "channel-changed");
                }
            }
            removeClientFromQueues(room, client.id);

            client.channel = newChannel;
            const member = room.members.get(client.id);
            if (member) {
                member.channel = newChannel;
            }

            // Both sides are re-published: the channel they left needs its holder
            // and queue corrected, and the one they joined needs to show them.
            pushChannelSnapshot(room, previousChannel);
            pushChannelSnapshot(room, newChannel);

            // A local mute applies to one channel, so moving between channels can
            // silence or free this client without anything else changing. Tell
            // them, or their key would simply stop working with no explanation.
            const wasMuted = isMutedOn(client, previousChannel);
            const nowMuted = isMutedOn(client, newChannel);
            if (wasMuted !== nowMuted) {
                send(client.ws, {
                    type: "mute-state",
                    payload: {
                        muted: nowMuted,
                        scope: client.globalMuted ? "global" : "channel",
                        channel: newChannel,
                        mutedGlobally: Boolean(client.globalMuted),
                        mutedChannels: [...(client.mutedChannels || [])],
                        byName: nowMuted ? client.mutedByName || "" : "",
                    },
                });
            }
            const movedMember = room.members.get(client.id);
            if (movedMember) movedMember.muted = nowMuted;
            const summary =
                getClientSummary(member) || getLiveClientSummary(client);
            // Broadcast to everyone except the initiating client (they already updated their own state)
            broadcastRoom(
                room,
                {
                    type: "peer-updated",
                    payload: summary,
                },
                client.id,
            );
            broadcastRoom(room, {
                type: "channel-changed",
                payload: {
                    id: client.id,
                    channel: newChannel,
                },
            });
            return;
        }

        if (type === "channel-create") {
            createChannel(room, client, payload);
            return;
        }

        if (type === "channel-delete") {
            deleteChannel(room, client, payload);
            return;
        }

        if (type === "channel-set-restricted") {
            setChannelRestricted(room, client, payload);
            return;
        }

        if (type === "channel-rename") {
            renameChannel(room, client, payload);
            return;
        }

        if (type === "set-mute") {
            setClientMuted(room, client, payload);
            return;
        }

        if (type === "set-train-id") {
            setClientTrainId(room, client, payload);
            return;
        }

        if (type === "set-emergency-tone-seconds") {
            setEmergencyToneSeconds(room, client, payload);
            return;
        }

        if (type === "set-transmit-channels") {
            setTransmitChannels(room, client, payload);
            return;
        }

        if (type === "set-interrupt-seconds") {
            setInterruptSeconds(room, client, payload);
            return;
        }

        if (type === "emergency-acknowledge") {
            acknowledgeEmergency(room, client);
            return;
        }

        // A client switching its own private calls on or off. Their own setting,
        // so there is no permission check — it only ever restricts themselves.
        if (type === "set-allow-calls") {
            client.allowCalls = payload.allow !== false;
            send(client.ws, {
                type: "allow-calls",
                payload: { allow: client.allowCalls },
            });
            return;
        }

        if (type === "private-call-request") {
            requestPrivateCall(room, client, payload.trainId);
            return;
        }

        if (type === "private-call-accept") {
            answerPrivateCall(room, client, true);
            return;
        }

        if (type === "private-call-decline") {
            answerPrivateCall(room, client, false);
            return;
        }

        if (type === "private-call-end") {
            clearPrivateCallFor(client, "hung-up");
            return;
        }

        if (type === "emergency-set") {
            if (client.rank === "t1") {
                send(client.ws, {
                    type: "error",
                    payload: { message: "T1 rank cannot raise an emergency." },
                });
                return;
            }
            // Being muted takes the emergency button with it, so it cannot be
            // used to key up over the top of the mute. Clearing one is still
            // allowed — that path is guarded by setEmergency itself.
            if (isMutedOn(client, client.channel) && Boolean(payload.active)) {
                send(client.ws, {
                    type: "error",
                    payload: {
                        message:
                            "You are muted and cannot raise an emergency.",
                    },
                });
                return;
            }
            setEmergency(room, client, Boolean(payload.active));
            return;
        }

        if (type === "ptt-request") {
            // On a private call the key is arbitrated within the call, not the channel.
            if (privateCallPtt(client, true)) {
                return;
            }
            if (client.rank === "t1") {
                send(client.ws, {
                    type: "error",
                    payload: {
                        message:
                            "T1 rank cannot transmit. Ask an admin to assign you a higher rank.",
                    },
                });
                return;
            }
            const requestedChannel = capChannel(
                payload.channel || client.channel || DEFAULT_CHANNEL,
                client.rank,
            );

            // Keep server-side channel state in sync before granting TX.
            if (requestedChannel !== client.channel) {
                client.channel = requestedChannel;
                const member = room.members.get(client.id);
                if (member) {
                    member.channel = requestedChannel;
                }

                const summary =
                    getClientSummary(member) || getLiveClientSummary(client);
                broadcastRoom(
                    room,
                    {
                        type: "peer-updated",
                        payload: summary,
                    },
                    client.id,
                );
                broadcastRoom(
                    room,
                    {
                        type: "channel-changed",
                        payload: {
                            id: client.id,
                            channel: requestedChannel,
                        },
                    },
                    client.id,
                );
                send(ws, {
                    type: "channel-changed",
                    payload: {
                        id: client.id,
                        channel: requestedChannel,
                    },
                });
            }

            // Key every channel this client is set to transmit on. For everybody
            // except a dispatcher with extras armed this is exactly one channel,
            // and behaves as it always did.
            const targets = transmitChannelsFor(client);
            targets.add(requestedChannel);
            client.txChannels = new Set();
            for (const ch of targets) {
                if (!channelExists(ch)) continue;
                // Restricted channels still respect rank, even in a broadcast.
                if (!canAccessChannel(client.rank, ch)) continue;
                requestPTT(room, client, ch, ch !== requestedChannel);
                client.txChannels.add(ch);
            }
            return;
        }

        if (type === "ptt-release") {
            if (privateCallPtt(client, false)) {
                return;
            }
            // Let go of every channel that was keyed, not just the one they are
            // standing on — otherwise a broadcast leaves the others held open.
            const held = [...(client.txChannels || [])];
            client.txChannels = new Set();
            if (held.length === 0) {
                releasePTT(room, client);
            } else {
                for (const ch of held) releaseChannelFor(room, client, ch, "released");
            }
            return;
        }
    });

    ws.on("close", () => {
        if (!client.roomId) {
            return;
        }

        const room = rooms.get(client.roomId);
        if (!room) {
            return;
        }

        // Safe to call for a session already evicted by a newer one: it returns
        // immediately when the client is no longer a member of the room.
        removeClientFromRoom(room, client);
    });
});

// ── WebSocket heartbeat ───────────────────────────────────────────────────
// Pings every socket on an interval. This keeps otherwise-idle radio links
// alive through a reverse proxy, and drops peers that have gone away without a
// close frame (which the browser clients cannot recover from on their own).
//
// One missed pong marks the client degraded rather than dropping it: a train on
// a marginal connection is exactly the case where cutting the radio is the wrong
// answer, and it gives dispatchers a visible "reconnecting" state before the
// unit disappears. Two consecutive misses is a real disconnection.

/// Flags a client degraded (or recovered) and tells the room, if it changed.
function setClientDegraded(client, degraded) {
    if (!client || client.degraded === degraded) return;
    client.degraded = degraded;
    const room = client.roomId ? rooms.get(client.roomId) : null;
    if (!room) return;
    const member = room.members.get(client.id);
    if (member) member.degraded = degraded;
    broadcastMemberUpdate(room, client.id);
}

const heartbeatTimer = setInterval(() => {
    for (const socket of wss.clients) {
        if (socket.readyState !== WebSocket.OPEN) {
            continue;
        }
        const client = socket.voiceClient;
        if (socket.isAlive === false) {
            // Missed a second sweep in a row — the peer really is gone.
            if (socket.missedPongs >= 2) {
                socket.terminate();
                continue;
            }
            socket.missedPongs = (socket.missedPongs || 0) + 1;
            setClientDegraded(client, true);
        } else {
            socket.missedPongs = 0;
            setClientDegraded(client, false);
        }
        socket.isAlive = false;
        try {
            socket.ping();
        } catch {
            // Socket died between the readyState check and the ping.
        }
    }
}, WS_HEARTBEAT_SECONDS * 1000);

wss.on("close", () => clearInterval(heartbeatTimer));

server.listen(PORT, () => {
    // eslint-disable-next-line no-console
    const protocol = HTTPS_ENABLED ? "https" : "http";
    console.log(
        `MTA radio server listening on ${protocol}://localhost:${PORT}`,
    );
});
