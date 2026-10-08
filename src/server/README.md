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

### Reaching it from another computer on the LAN

```sh
bun run certs -- 192.168.1.150 my-pc   # add this PC's LAN address(es) to the cert
bun run dev:relay:lan                  # relay on 0.0.0.0:8080 instead of 127.0.0.1
```

`bun run certs` reuses the existing key, so the pin enrolled machines check
stays valid. Windows Firewall also has to let port 8080 in; from an elevated
PowerShell, limited to the local subnet on Private networks:

```powershell
New-NetFirewallRule -DisplayName "Hawk relay (LAN)" -Direction Inbound -Protocol TCP -LocalPort 8080 `
  -Action Allow -Profile Private -RemoteAddress LocalSubnet
```

The other computer then browses to `https://192.168.1.150:8080`. The cert
is self-signed, so its browser warns until `certs/dev-cert.pem` is imported
into that computer's trusted roots.

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
  user's sessions, closes their open dashboards and disconnects the
  machines they own, immediately. Being admin does not grant access to
  other people's machines.
- **Settings:** every user's Settings tab picks the dashboard's accent
  color (kept in that browser), changes their password (the
  current one is checked first; wrong guesses count toward the login
  throttle) and lists their sessions with the browser and IP each signed in
  from. A session can be revoked on its own, or all but the current one at
  once. Changing the password also ends every other session. Revoking
  closes that session's open dashboards immediately.
- Passwords: argon2id, at least 10 characters. Session and invite tokens are
  32 random bytes; the database stores only their SHA-256.
- Sessions: `hawk_session` cookie, `HttpOnly`, `SameSite=Strict`, `Secure`
  under TLS, valid 30 days. Every `/api/*` route except login, signup and
  invite lookup requires one, as does the `/v1/dashboard` socket, which also
  rejects a cross-origin `Origin`.
- Failed logins are throttled per client IP (10 per 15 minutes). Behind a
  reverse proxy all clients share the proxy's IP, so this is a coarse brake.

## Machines

Every machine has exactly one owner and its own key pair.

- **Enrolling:** in the dashboard, **Machines > Add machine** issues a
  one-time enrollment code (like `7K3QD-WX2MP`, valid 1 hour) and the exact
  install command, `install-service.ps1 -EnrollCode <code> -RelayPin <pin>`
  (see `scripts/README.md`). The service creates an ECDSA P-256 key in the
  machine's TPM (or the software key store without one) and sends the
  public key with the code. The relay stores the public key, and consumes
  the code only once the machine has proven it holds the private key.
- **Connecting:** hello, then the relay sends a fresh 32-byte challenge and
  the machine signs it (`hawk-machine-auth-v1\0 || nonce`, verified with
  `ring`). An unknown or removed machine, a failed proof, a spent or expired
  code, or a disabled owner closes the socket with `1008` (policy violation)
  before the machine is registered. Nothing secret is stored server-side or
  sent over the wire. The dashboard shows owners whether each machine's key
  is in a TPM ("software key" otherwise); that's as reported by the
  machine, not attested.
- **Removing** a machine (owner only) deletes its public key, disconnects
  it, and takes it away from everyone it was shared with. To bring it back,
  or move it to another account, enroll it again.
- Machines enrolled before key-based authentication show "re-enroll needed"
  and can't connect until they are.
- Live connections are keyed by machine, so the dashboard also lists your
  machines while they're offline, with when they were last seen.

### Sharing

An owner can share a machine with another existing account (the admin
invites them first if they have none), with one of two roles:

- **view** - can watch the screen.
- **control** - can watch and use the machine's mouse and keyboard.

The owner always has full access and sees, live, who is watching each of
their machines. Access is enforced by the relay, not the dashboard: a
dashboard only ever learns about machines its user can access, and every
`start_view` is checked. Granting, changing or revoking a share, renaming
or removing a machine all apply to open dashboards immediately; a revoked
viewer's stream stops at once.

A share can also be temporary. These combine freely:

- **Expiry:** for 30 minutes up to a week, or until a chosen date and
  time. When it runs out the relay deletes the share and cuts off a live
  viewer, the same as a manual revoke. **+1 h** extends it.
- **Scheduled start:** the share grants nothing until its start time
  (e.g. tomorrow 9:00 for 2 hours), then appears on the viewer's dashboard
  live.
- **One viewing:** the share is used up when the viewer stops watching, or
  leaves for more than 60 seconds (long enough for the dashboard to
  reconnect and resume after a network blip). A machine going offline mid-view
  doesn't use it up.

Sharing again with the same person replaces the share's terms. A timer in
the relay wakes at the next start or expiry, so changes land within about a
second. Starts and ends can be at most a year away.

### Input

A viewer with the **control** role, and the owner, can use the machine as
well as watch it: clicking the live screen hands it your mouse and keyboard,
and clicking away (or **Release**) takes them back. **Full screen** also
asks the browser for a keyboard lock where it supports one (Chromium), so
shortcuts it would otherwise keep (`Alt+Tab`, `Ctrl+W`, `Esc`) go to the
machine too; holding `Esc` leaves full screen.

- The dashboard sends pointer positions as a fraction of the screen, button
  presses, wheel notches and physical keys (`KeyboardEvent.code`). Pointer
  moves are coalesced to one per repaint.
- The relay checks the sender's role on **every** input message, not just at
  `start_view`: input from a `view` share, or from a dashboard that isn't
  watching that machine at that moment, is dropped without an answer. It
  also clamps positions and wheel deltas, rejects unusable ones, and caps
  each dashboard at 500 events a second.
- When a viewer stops watching, or their share drops to `view` mid-session,
  the relay tells the machine to release whatever that viewer's input was
  holding down. The dashboard releases it too when the screen loses focus,
  so nothing stays pressed on the machine with nobody pressing it.
- The machine replays events with `SendInput`, as physical scancodes and
  absolute desktop positions — see "Input Injection" in the top-level
  README for what that reaches and what it can't (`Ctrl+Alt+Del` and the
  UAC prompt, among others).
- Desktop Duplication doesn't put the machine's own mouse cursor in the
  captured frames, so while controlling, the viewer's own pointer stands in
  for it; someone only watching sees no pointer at all.

### Dashboard connection

If the dashboard loses its link to the relay (relay restart, network loss)
it retries on its own: after 1s, then 2s, 4s, ... up to 30s, with jitter.
Coming back online retries straight away. Before each attempt it checks the
session is still valid, and returns to the login page if it isn't. An open
live view stays open and resumes once the link is back. If the machine is
offline at that point, it resumes when the machine reconnects.

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

### Pinning

On top of the chain check, machines pin the relay's **TLS key**: the relay
logs `relay certificate pin` at startup (base64 SHA-256 of the
certificate's SubjectPublicKeyInfo) and the dashboard puts it in every
install command as `-RelayPin`. A machine with a pin refuses any other key,
even from a certificate that chains to a root it trusts (a rogue or
corporate CA), before sending anything.

Because it pins the key, not the certificate, renewing the certificate is
fine **as long as the key stays the same** (e.g. certbot `--reuse-key`). To
change the key: put the new key's pin on every machine first, alongside the
old one (`install-service.ps1 -RelayPin <old>,<new>`), then switch the relay
to it. A machine whose pins don't match logs `refusing ...: server key <pin>
is not pinned` and retries every 30s.

## Roadmap

Planned work on the server. Nothing below is implemented yet.

- **On-machine indicator.** Show something on the shared PC itself while
  anyone is watching it.
- **The machine's cursor in the stream.** Desktop Duplication reports the
  mouse pointer separately from the frame; compositing it in would let a
  watcher see it too.
