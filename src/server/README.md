# Relay server

Fastify backend + React/Vite dashboard. Two workspaces:

- `backend/` — the relay: devices (hawk-service clients) connect to `/v1/ws`
  and register themselves with a `hello` message; the dashboard connects to
  `/v1/dashboard` for a live, read-only view of who's connected.
- `frontend/` — the dashboard UI.

Command/control (acting on a connected device) isn't implemented yet — this
is just the connection registry and a view into it.

## Development

```sh
bun install   # from src/server, installs both workspaces
bun run certs  # generates a local dev TLS cert into certs/ (one-time)

bun run dev:backend    # terminal 1 — relay on :8080 (https/wss)
bun run dev:frontend   # terminal 2 — dashboard on :5173, proxies to :8080
```

## Production build

```sh
bun run build   # type-checks backend, builds frontend/dist
bun run start   # serves the built frontend and runs the relay on :8080
```

The backend runs straight from TypeScript source via `bun`/`bun --watch` —
there's no separate compile step for it, `build` just type-checks it as a gate.

## TLS

The backend serves `https`/`wss` whenever it finds a cert and key — by
default at `certs/dev-cert.pem` / `certs/dev-key.pem`, or wherever
`TLS_CERT_PATH` / `TLS_KEY_PATH` point. `bun run certs` generates a
self-signed one for local dev. If neither is found it falls back to plain
`http`/`ws` with a logged warning — fine for a throwaway local test, never
for anything crossing a network you don't control.

The hawk-service client validates the server cert the normal way (via the
Windows trust store), so to point it at a local dev relay you need to import
`certs/dev-cert.pem` into that machine's **Trusted Root Certification
Authorities** store first. For anything beyond your own LAN, skip the
self-signed cert entirely and use one from a real CA (e.g. Let's Encrypt)
for an actual domain pointed at this server.

## Roadmap

Planned work on the server, in rough order. Nothing below is implemented yet.

### Accounts

- Sign-up and login from the dashboard. Passwords are stored hashed
  (`Bun.password`, argon2id), never in plain text.
- Sessions use an `HttpOnly`, `Secure`, `SameSite=Strict` cookie. Every
  `/api/*` route and the `/v1/dashboard` socket require one.
- Accounts, machines and sessions are kept in a local SQLite file
  (`bun:sqlite`), so registered machines survive a restart. Live connection
  state stays in memory, as it is today.

### Per-account machine key

Each account has one secret machine key. It is what ties a PC to its owner,
so a user can only ever see and act on their own machines.

- The key is random (32 bytes, base64url) and only its hash is stored. It
  is shown in Settings, where it can be copied or regenerated.
- The hawk-service client sends it in its hello:
  `{"type":"hello","machine_id":"...","key":"..."}`.
- The relay looks up the account by key hash. An unknown or missing key
  closes the socket with code `1008` (policy violation) before the device
  is ever added to the registry.

### Dashboard: tabs and layout

The single table becomes a small tabbed app with a sharp-edged, dark,
professional look — no rounded corners anywhere (`border-radius: 0`).

- **Machines** — every machine registered to the account, each row showing
  connection status (online/offline dot), hostname and last-seen IP, plus
  when it was last seen. Online rows come from the live registry; offline
  ones from the stored list.
- **Settings** — account email, the machine key (reveal / copy / regenerate)
  and logout.

### Desktop capture

A live view of a selected machine's screen in the dashboard.

- `hawk-capture` already encodes the desktop to H.264 (`src/capture`); the
  missing pieces are it handing packets to `hawk-service` over a local pipe,
  and the service forwarding them over the relay socket.
- The relay routes a viewer's capture request to the owning machine and
  streams the returned H.264 packets back to that dashboard only. Decoding
  in the browser is via WebCodecs (`VideoDecoder`).
- Capture starts only on an explicit request from an authenticated owner and
  stops when the viewer disconnects.

Other control features come later; capture is the first one.
