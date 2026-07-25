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
const CHANNELS = ["operators", "a1-irt", "b1-bmt", "b2-ind", "y-yard"];
const RESTRICTED_CHANNELS = new Set(["a1-irt", "b1-bmt", "b2-ind", "y-yard"]);
const CHANNEL_LABELS = {
    operators: "Operators",
    "a1-irt": "A1-IRT",
    "b1-bmt": "B1-BMT",
    "b2-ind": "B2-IND",
    "y-yard": "Y-Yard",
};

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
    if (!RESTRICTED_CHANNELS.has(channelId)) return true;
    return rank === "t3" || rank === "mod" || rank === "admin";
}

function capChannel(requestedChannel, rank) {
    const ch = String(requestedChannel || DEFAULT_CHANNEL).toLowerCase();
    if (!CHANNELS.includes(ch)) return DEFAULT_CHANNEL;
    if (!canAccessChannel(rank, ch)) return DEFAULT_CHANNEL;
    return ch;
}

function getChannelDescriptors(rank) {
    return CHANNELS.map((ch) => ({
        id: ch,
        label: CHANNEL_LABELS[ch] || ch,
        restricted: RESTRICTED_CHANNELS.has(ch),
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
};

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
                CHANNELS.map((name) => [
                    name,
                    {
                        holderId: null,
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
            CHANNELS.map((name) => [
                name,
                {
                    holderId: null,
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
    const channelState = getChannelState(room, client.channel);
    if (!channelState) {
        return;
    }

    channelState.queue = channelState.queue.filter((id) => id !== client.id);

    if (channelState.holderId === client.id) {
        channelState.holderId = null;

        send(client.ws, {
            type: "ptt-released",
            payload: { reason },
        });

        pushTxState(room, client.id, client.channel, false);

        while (channelState.queue.length > 0) {
            const nextId = channelState.queue.shift();
            const nextClient = clientsById.get(nextId);
            if (
                !nextClient ||
                nextClient.roomId !== room.id ||
                nextClient.channel !== client.channel
            ) {
                continue;
            }

            channelState.holderId = nextClient.id;
            send(nextClient.ws, {
                type: "ptt-granted",
                payload: {
                    channel: client.channel,
                    reason: "queue-advanced",
                },
            });

            pushTxState(room, nextClient.id, client.channel, true);
            break;
        }
    }

    pushChannelSnapshot(room, client.channel);
}

function requestPTT(room, client, channelName) {
    if (!CHANNELS.includes(channelName)) {
        send(client.ws, {
            type: "error",
            payload: { message: "Unknown channel." },
        });
        return;
    }

    client.channel = channelName;
    const channelState = getChannelState(room, channelName);
    if (!channelState) {
        return;
    }

    if (!channelState.holderId || channelState.holderId === client.id) {
        channelState.holderId = client.id;

        send(client.ws, {
            type: "ptt-granted",
            payload: {
                channel: channelName,
                reason: "free-channel",
            },
        });

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
                CHANNELS.map((name) => [name, { holderId: null, queue: [] }]),
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
        channel: DEFAULT_CHANNEL,
        transport: "webrtc",
        wsUrl: req.url,
        wsHeaders: req.headers,
    };

    ws.on("message", (raw, isBinary) => {
        // Binary = PCM audio frame from the current PTT holder → relay to channel peers
        if (isBinary) {
            if (client.roomId) {
                const room = rooms.get(client.roomId);
                if (room) {
                    const chState = getChannelState(room, client.channel);
                    if (chState && chState.holderId === client.id) {
                        const senderRelayOnly = client.transport === "relay";
                        for (const lid of room.clients) {
                            if (lid === client.id) continue;
                            const listener = clientsById.get(lid);
                            if (
                                !listener ||
                                listener.channel !== client.channel ||
                                listener.ws.readyState !== WebSocket.OPEN
                            ) {
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

            // Kick any existing session for this account (only applies to authenticated users)
            if (accountId) {
                const existing = clientsByAccountId.get(accountId);
                if (existing && existing.id !== client.id) {
                    send(existing.ws, {
                        type: "kicked",
                        payload: { reason: "Signed in from another location" },
                    });
                    existing.ws.close(1000, "Duplicate session");
                }
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
            client.rank = rank;

            // Staff always connect at their rank as session role; others pick a session role
            if (STAFF_RANKS.has(rank)) {
                client.role = rank; // "admin" or "mod" as session role for display
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

            for (const channelName of CHANNELS) {
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
            // Train ID must be numeric only
            if (payload.trainId) {
                client.trainId = String(payload.trainId).replace(/[^0-9]/g, "");
            }

            let roleChanged = false;
            if (STAFF_RANKS.has(client.rank)) {
                if (client.role !== client.rank) {
                    client.role = client.rank;
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
            client.channel = newChannel;
            const member = room.members.get(client.id);
            if (member) {
                member.channel = newChannel;
            }
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

        if (type === "ptt-request") {
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

            requestPTT(room, client, requestedChannel);
            return;
        }

        if (type === "ptt-release") {
            releasePTT(room, client);
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

        releasePTT(room, client, "disconnect");
        removeClientFromQueues(room, client.id);

        room.clients.delete(client.id);
        room.members.delete(client.id);
        clientsById.delete(client.id);

        // Remove from account index only if this is still the registered session
        if (
            client.accountId &&
            clientsByAccountId.get(client.accountId) === client
        ) {
            clientsByAccountId.delete(client.accountId);
        }

        broadcastRoom(room, {
            type: "peer-left",
            payload: { id: client.id },
        });

        for (const channelName of CHANNELS) {
            pushChannelSnapshot(room, channelName);
        }

        if (room.clients.size === 0) {
            for (const channelState of room.channels.values()) {
                channelState.holderId = null;
                channelState.queue = [];
            }
        }
    });
});

server.listen(PORT, () => {
    // eslint-disable-next-line no-console
    const protocol = HTTPS_ENABLED ? "https" : "http";
    console.log(
        `MTA radio server listening on ${protocol}://localhost:${PORT}`,
    );
});
