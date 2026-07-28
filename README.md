# MTA Subway Radio WebRTC Server

A Node.js WebRTC signaling server and demo client that simulates subway radio behavior for MTA-style operations.

## Features

- WebRTC peer mesh voice with WebSocket signaling.
- One fixed room (`mta-main`) and one fixed radio channel (`operations`).
- Push-to-talk arbitration with queueing (single active transmitter).
- Long transmissions can be interrupted once the holder has blocked the line for
  `PTT_INTERRUPT_SECONDS` (default 35, `0` disables).
- Two roles: `operator` and `tower`.
- Server-generated user names.
- Mobile-friendly PTT behavior and walkie-talkie style audio processing.
- Optional local HTTPS mode for secure mobile microphone access.

## Requirements

- Node.js 18+ recommended.

## Install

```bash
npm install
```

## Run (HTTP)

```bash
npm start
```

Open browser tabs (or multiple devices) at:

- http://localhost:8080

## Access Protection (recommended)

To prevent unauthorized developers/apps from using your signaling server:

1. Enable password login sessions.
2. Restrict WebSocket origins.
3. Optionally allow only trusted IPs.
4. Enforce HTTPS.

Set these environment variables:

- `AUTH_PASSWORD=<strong-password>`
- `SESSION_SECRET=<long-random-secret>`
- `ALLOWED_ORIGINS=https://radio.yourdomain.com,https://www.radio.yourdomain.com`
- `REQUIRE_HTTPS=true`

Optional:

- `ALLOWED_IPS=<comma-separated IP list>`
- `SESSION_TTL_SECONDS=43200`
- `RATE_LIMIT_AUTH_MAX=10`
- `RATE_LIMIT_WS_MAX=60`

How it works:

- Browser requests are redirected to `/login` when unauthenticated.
- `/auth/login` issues an expiring, signed session cookie.
- HTTP assets/API and WebSocket upgrades require valid auth.
- Upgrade/auth endpoints are rate-limited.

Legacy compatibility:

- `ACCESS_TOKEN` still works if set, but password session login is preferred.

## Behind nginx (reverse proxy)

The radio is almost entirely WebSocket traffic, including the binary PCM relay,
so a plain `proxy_pass` is not enough — the upgrade headers are required or the
connection is rejected at the handshake.

```nginx
server {
    listen 443 ssl;
    server_name radio.openbvenews.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;

        # Required, or the WebSocket upgrade fails
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Voice is real-time; buffering adds audible latency
        proxy_buffering off;

        # Longer than WS_HEARTBEAT_SECONDS so idle radios are not dropped
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }
}
```

Also set in `.env`:

- `TRUST_PROXY=true` — so `X-Forwarded-For` / `X-Forwarded-Proto` are honoured.
  Without it every client appears to come from the proxy, which breaks rate
  limiting and `ALLOWED_IPS`.
- `ALLOW_ANONYMOUS_WS=true` — if in-game clients connect without logging in.

Clients reach it over `wss://` on 443; nginx terminates TLS and the server itself
stays plain HTTP on the loopback interface.

## Run (HTTPS local)

Set these environment variables before starting:

- `HTTPS=true`
- `SSL_KEY_PATH=<path to key.pem>`
- `SSL_CERT_PATH=<path to cert.pem>`

Example (Git Bash):

```bash
HTTPS=true SSL_KEY_PATH=./certs/localhost-key.pem SSL_CERT_PATH=./certs/localhost.pem npm start
```

Example (PowerShell):

```powershell
$env:HTTPS="true"
$env:SSL_KEY_PATH="./certs/localhost-key.pem"
$env:SSL_CERT_PATH="./certs/localhost.pem"
npm start
```

Then open:

- https://localhost:8080

If you test from a phone, use your PC LAN host and a trusted cert:

- https://<your-lan-ip>:8080

## mkcert quick setup

1. Install `mkcert`.
2. Run `mkcert -install`.
3. Generate cert files (example):

```bash
mkdir -p certs
mkcert -key-file certs/localhost-key.pem -cert-file certs/localhost.pem localhost 127.0.0.1 ::1
```

4. Start server with the HTTPS env vars above.

Note:

- Phone microphone access usually requires HTTPS with a trusted certificate chain on the phone.

## How to test quickly

1. Open two browser tabs.
2. Join same network session.
3. Use one tab as transmitter and one as receiver.
4. Hold Push To Talk in one tab.
5. Try holding Push To Talk in the other tab to see queue behavior.

## API

- `GET /api/rooms` returns room/channel occupancy snapshot.

## Message overview

WebSocket message types used by the client:

- `join`
- `joined`
- `peer-joined`
- `peer-left`
- `peer-updated`
- `signal` (offer/answer/ice)
- `set-channel`
- `set-presence`
- `ptt-request`
- `ptt-release`
- `ptt-granted`
- `ptt-queued`
- `ptt-released`
- `ptt-revoked`
- `tx-state`
- `channel-state`

## Notes for production

- Add TURN (coturn) for NAT traversal.
- Configure `AUTH_PASSWORD`, `SESSION_SECRET`, `ALLOWED_ORIGINS`, and `REQUIRE_HTTPS=true`.
- Use network-level firewalling and optionally `ALLOWED_IPS`.
- Add persistence and operational logging.
- Consider SFU architecture (mediasoup/Janus) for larger rooms.
# openbve-voice-server
