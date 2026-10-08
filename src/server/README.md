# Relay server

Rust relay + React/Vite dashboard:

- `relay/` — the relay (axum + tokio, TLS via rustls). Devices (hawk-service
  clients) connect to `/v1/ws` and register with a `hello` message, then
  stream H.264 frames up; dashboards connect to `/v1/dashboard` to see who's
  connected and to start/stop watching a device. It also serves the built
  dashboard from `frontend/dist`.
- `frontend/` — the dashboard UI (a bun workspace).

Each viewer gets a bounded frame queue. A viewer that falls behind loses
frames until the next keyframe instead of making the relay buffer video for
it, and a new viewer starts on a keyframe.

## Development

Needs a Rust toolchain (`cargo`) and `bun`.

```sh
bun install       # from src/server, installs the frontend workspace
bun run certs     # generates a local dev TLS cert into certs/ (one-time)

bun run dev:relay      # terminal 1 — relay on :8080 (https/wss)
bun run dev:frontend   # terminal 2 — dashboard on :5173, proxies to :8080
```

## Production build

```sh
bun run build   # builds frontend/dist and the release relay
bun run start   # serves the built frontend and runs the relay on :8080
```

Configuration is by environment variable: `HOST` (default `127.0.0.1`),
`PORT` (default `8080`), `FRONTEND_DIST`, `TLS_CERT_PATH`, `TLS_KEY_PATH`,
`HAWK_DB_PATH` (default `data/hawk.db`), `PUBLIC_URL` (the address people
reach the dashboard at, used in links the relay logs), and
`HAWK_SERVER_ROOT` (the directory the default paths are relative to;
defaults to this directory). `RUST_LOG` controls log verbosity.

## Accounts

Accounts are invite-only; there is no open sign-up.

- **First run:** with no accounts in the database, the relay logs a one-time
  link (`.../invite/<token>`) that creates the **admin** account. Only
  someone who can read the server's output can claim it. Restarting before
  it's used replaces the link.
- **Inviting:** the admin creates single-use invite links (valid 7 days) in
  the dashboard's Admin tab, and can revoke unused ones.
- **Admin:** lists users and can disable/enable them. Disabling ends the
  user's sessions and closes their open dashboards immediately. Being admin
  does not grant access to other people's machines (once machines have
  owners; see the roadmap).
- Passwords: argon2id, at least 10 characters. Session and invite tokens are
  32 random bytes; the database stores only their SHA-256.
- Sessions: `hawk_session` cookie, `HttpOnly`, `SameSite=Strict`, `Secure`
  under TLS, valid 30 days. Every `/api/*` route except login, signup and
  invite lookup requires one, as does the `/v1/dashboard` socket, which also
  rejects a cross-origin `Origin`.
- Failed logins are throttled per client IP (10 per 15 minutes). Behind a
  reverse proxy all clients share the proxy's IP, so this is a coarse brake.

Until machines have owners, connected devices are visible to the **admin
only**; other accounts can log in but see no machines.

## TLS

The relay serves `https`/`wss` whenever it finds a cert and key — by
default at `certs/dev-cert.pem` / `certs/dev-key.pem`, or wherever
`TLS_CERT_PATH` / `TLS_KEY_PATH` point. `bun run certs` generates a
self-signed one for local dev. If neither is found it falls back to plain
`http`/`ws` with a logged warning — fine for a throwaway local test, never
for anything crossing a network you don't control. Note that hawk-service
always connects with `wss://`, so it can't reach a relay running without TLS.

The hawk-service client validates the server cert the normal way (via the
Windows trust store), so to point it at a local dev relay you need to import
`certs/dev-cert.pem` into that machine's **Trusted Root Certification
Authorities** store first. For anything beyond your own LAN, skip the
self-signed cert entirely and use one from a real CA (e.g. Let's Encrypt)
for an actual domain pointed at this server.

## Roadmap

Planned work on the server, in rough order. Nothing below is implemented yet.

### Machines and enrollment

Every machine has exactly one owner, and its own credential.

- The owner enrolls a PC from the dashboard, which issues a one-time
  enrollment code. hawk-service exchanges it for a long-lived per-machine
  credential (random, only its hash stored server-side).
- The service sends that credential in its hello. An unknown, missing or
  revoked credential closes the socket with code `1008` (policy violation)
  before the device is ever added to the registry.
- Removing a machine revokes its credential and disconnects it.

### Sharing and permissions

An owner can share a machine with another account (inviting them first if
they have none), with one of two roles:

- **view** — can watch the screen. Nothing it sends can act on the machine.
- **control** — can watch and send input.

The owner always has full access. Permissions are enforced by the relay, not
the dashboard: it checks the role on every `start_view` and on every input
message, and drops input from a `view` share. Revoking a share disconnects
that user's live view immediately.

### Multiple viewers

Several dashboards can watch one machine at once (already supported by the
registry). With accounts, the relay knows who each viewer is, so:

- the owner can see who is currently watching each machine;
- the machine itself shows an indicator while anyone is viewing it.

### Dashboard: tabs and layout

The single table becomes a small tabbed app with a sharp-edged, dark,
professional look — no rounded corners anywhere (`border-radius: 0`).

- **Machines** — machines you own and machines shared with you, each row
  showing online/offline status, hostname, last-seen time and your role.
- **Sharing** — per owned machine: who has access, with which role; invite
  or revoke.
- **Settings** — account email, password, enrolled machines, logout. The
  admin also sees account management here.
