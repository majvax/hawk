# Relay server

Rust relay + React/Vite dashboard:

- `relay/` — the relay (axum + tokio, TLS via rustls). Devices (hawk-service
  clients) connect to `/v1/ws` and register with a `hello` message, then
  stream H.264 frames up; dashboards connect to `/v1/dashboard` to see who's
  connected and to start/stop watching a device. It also serves the built
  dashboard from `frontend/dist`.
- `frontend/` — the dashboard UI (a bun workspace). `frontend/docs/` is the
  user documentation served at `/docs`, one Markdown file per page; keep it
  in step when a feature or a setup step changes.

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
`HAWK_DB_PATH` (default `data/hawk.db`), `HAWK_SECRET_KEY_PATH` (default
`secret.key` beside the database), `PUBLIC_URL` (the address people reach
the dashboard at, used in links the relay logs and emails), `HAWK_SMTP_URL`
and `HAWK_MAIL_FROM` (see "Email" below), and `HAWK_SERVER_ROOT` (the
directory the default paths are relative to; defaults to this directory).
`RUST_LOG` controls log verbosity.

**Back up the secret key with the database.** The relay creates
`secret.key` (32 random bytes, readable by its owner only) on first start
and seals every TOTP seed under it, so a copy of the database alone doesn't
give the seeds away. Without the key, a restored database still works, but
every authenticator has to be removed by the admin and set up again.

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
  color (kept in that browser), shows their identity key's fingerprint,
  changes their password (the current one is checked first; wrong guesses
  count toward the login throttle) and lists their sessions with the
  browser and IP each signed in from. A session can be revoked on its own,
  or all but the current one at once. Changing the password also ends every
  other session. Revoking closes that session's open dashboards immediately.
- Passwords never reach the relay. The browser stretches the password
  (PBKDF2-SHA256, 600,000 iterations, salted with the email) and derives
  two keys from it: an auth key, which is what login sends and what the
  relay hashes with argon2id, and a wrapping key, which encrypts the
  account's identity key before the relay stores it. At least 10 characters,
  checked by the dashboard. Accounts made before this send their password
  itself one last time on their next login, which upgrades them. Session
  and invite tokens are 32 random bytes; the database stores only their
  SHA-256.
- Sessions: `hawk_session` cookie, `HttpOnly`, `SameSite=Strict`, `Secure`
  under TLS, valid 30 days. Every `/api/*` route except login, signup,
  invite lookup and email verification requires one, as does the
  `/v1/dashboard` socket, which also rejects a cross-origin `Origin`.
- Failed logins are throttled per client IP (10 per 15 minutes). Behind a
  reverse proxy all clients share the proxy's IP, so this is a coarse brake.

### Two-factor authentication

- **Authenticator apps (TOTP, RFC 6238):** SHA-1, 6 digits, 30-second
  steps, one step of clock drift either way. Settings shows a QR code and
  the key to type in by hand. A code from the app proves it was set up
  right before anything is stored. An account can have up to 8, and any of
  them signs in, so losing one phone isn't a lockout. Each factor remembers
  the last time step it accepted, so a code can't be used twice.
- **Recovery codes:** the first authenticator comes with 10 single-use
  codes (80 random bits each), shown once. Only their SHA-256 is stored.
  Settings can replace the whole set. Signing in with one sends a notice.
- **Login** takes two steps for an account with a factor: the password
  gets a ticket (in memory, 5 minutes, 5 tries), and a code trades it for
  the session. Wrong codes count against the client IP and against the
  account (10 per 15 minutes wherever they come from).
- **Step-up:** some actions need a factor proved in the last 5 minutes,
  checked by the relay on each request: enrolling, renaming, endorsing and
  removing a machine, sharing and unsharing, changing the password, adding
  and removing factors, new recovery codes, and every change in the Admin
  tab (reading it doesn't). A refused request answers 403 with
  `"stepUp": true`; the dashboard asks for a code (`POST
  /api/account/step-up`) and tries again. Signing in with a code counts as
  stepping up.
- **Control, files and shells** need the same over the dashboard socket.
  The relay can't read sealed messages, so it gates whole channels: a view
  is *elevated* when it starts inside the window, or later on `elevate`, and
  stays elevated until it ends. Until then the relay drops the view's
  input, file and shell messages (watching and the clipboard aren't
  affected), and the dashboard shows **Confirm to control**.
- **Adding or removing a factor** ends every other session. The first
  factor is confirmed with the password, later ones by stepping up, so a
  stolen session can't quietly add its own.
- **Admin:** the Users table shows who has two-factor on. **Reset
  two-factor** removes every factor and recovery code of an account that
  lost them all, and signs it out. **Require two-factor** (only once the
  admin has it) confines every account without a factor to setting one up
  after signing in, and keeps anyone from removing their last one.
- Security notices (a factor added or removed, new recovery codes, a
  recovery-code sign-in, a password change, a reset by the admin) go to the
  account's email address when a mailer is configured.

### Email

Optional. With `HAWK_SMTP_URL` (`smtps://user:password@host:465`, or
`smtp://user:password@host:587?tls=required` for STARTTLS) and
`HAWK_MAIL_FROM` (`Hawk <hawk@example.com>`), the relay sends:

- **Verification links.** A new account gets a link (valid 24 hours, only
  its hash stored) to confirm its address. It works in any browser, signed
  in or not. Until it's opened, the account can sign in, but no one can
  share a machine with it and it can't enroll one. The dashboard can send
  the link again, at most once a minute and 5 times an hour.
- **Security notices**, listed above. They never contain a link to act on.

With neither variable set there is no mailer: addresses are taken as
given, and nothing is sent. Accounts that existed before verification are
taken as confirmed. Mail goes out in the background, so a broken mail
server shows in the log, not in the dashboard.

## Machines

Every machine has exactly one owner and its own key pair.

- **Enrolling:** in the dashboard, **Machines > Add machine** makes a
  one-time enrollment code (25 characters, valid 1 hour) and shows the exact
  install command, `install-service.ps1 -EnrollCode <code> -RelayPin <pin>`
  (see `scripts/README.md`). The code is made in the browser, and the relay
  only ever gets its hash: it keys the bindings that let the machine and its
  owner trust each other's keys (see "End-to-end encryption" below). The
  service creates an ECDSA P-256 key in the machine's TPM (or the software
  key store without one) and sends the public key with the code's hash. The
  relay stores the public key, and consumes the code only once the machine
  has proven it holds the private key.
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
their machines. Access is enforced twice. The relay only tells a dashboard
about machines its user can access and checks every `start_view`. The
machine checks again, from the owner's own signatures: every share is a
grant the owner's browser signs, every revoke a signed revocation, and the
machine refuses anyone without a valid grant, so not even the relay can add
a viewer. Granting, changing or revoking a share, renaming or removing a
machine all apply to open dashboards immediately; a revoked viewer's stream
stops at once.

Sharing needs the recipient's identity key, so they must have logged in
once. The owner's browser pins each recipient's key the first time it's
seen and shows its fingerprint; a different key later is refused until the
owner confirms it with them. Shares from before grants existed are signed
automatically the next time the owner opens the machine's Sharing tab.

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
- Input is sealed for the machine, so the relay can't read it. The relay
  still checks the sender's role on **every** input message: input from a
  `view` share, or from a dashboard that isn't watching that machine at that
  moment, is dropped without an answer, and each dashboard is capped at 500
  events a second.
- The machine opens each event with that viewer's session key, refuses any
  it has already seen (so input can't be replayed), checks the role its
  owner granted, clamps positions and wheel deltas, and rejects unusable
  events.
- When a viewer stops watching, or their share changes mid-session (which
  restarts their view), the machine releases whatever that viewer's input
  was holding down, unless another viewer holds it too. The dashboard
  releases it as well when the screen loses focus, so nothing stays pressed
  on the machine with nobody pressing it.
- The machine replays events with `SendInput`, as physical scancodes and
  absolute desktop positions — see "Input Injection" in the top-level
  README for what that reaches and what it can't (`Ctrl+Alt+Del` and the
  UAC prompt, among others).
- Desktop Duplication doesn't put the machine's own mouse cursor in the
  captured frames, so while controlling, the viewer's own pointer stands in
  for it; someone only watching sees no pointer at all.

### End-to-end encryption

The relay carries the stream and input but can read neither, and nothing
it says is taken on trust. Formats are in `relay/src/e2e.rs`,
`frontend/src/e2e.ts` and `src/service/e2e.cpp`.

- **Identity keys:** every account has an ECDSA P-256 key. Its private half
  is stored on the relay encrypted under the password-derived wrapping key,
  and kept in each signed-in browser as a non-extractable WebCrypto key.
- **Enrollment:** the machine and the owner's browser each MAC their own
  public key with the enrollment code, which the relay never sees. The
  machine pins the owner's key only if its MAC checks out; the browser that
  made the code checks the machine's MAC, then signs the machine's key (an
  endorsement). From another browser, the owner can compare the machine's
  fingerprint (logged by the service as `machine key fingerprint`) instead.
- **Trust:** viewers trust the machine's key through the owner's
  endorsement. The owner trusts their own key; everyone else pins the
  owner's key the first time they see it.
- **Each view:** the browser sends a join signed with its identity key and a
  fresh ECDH key. The machine checks the owner's grant for that key,
  answers with its own ECDH key signed by its machine key, and sends the
  stream key wrapped for that viewer alone. Keys come from HKDF over the
  shared secret.
- **Frames:** AES-256-GCM under the stream key, with a counter nonce. The
  header (keyframe flag, timestamp, key id) stays readable, so the relay can
  still start a viewer on a keyframe, and is authenticated. When a viewer
  leaves, everyone else moves to a new stream key.
- **Input:** AES-256-GCM under a key only that viewer and the machine
  share, with a counter the machine requires to keep increasing.
- **Clipboard:** a viewer's paste or read request is sealed like input
  (same key, same counter, its own associated data, so neither can be
  replayed as the other). The machine's answer is sealed under a third
  per-viewer key, the reply key, with its own counter. The relay passes
  requests on for any role while the viewer is watching, and leaves the
  rest to the machine. Each message is at most about 342 KB, and there are
  at most 2 a second per dashboard and per viewer.
- **Files:** requests and upload chunks are sealed like input, with their
  own associated data. What the machine sends back (listings, progress,
  download chunks) uses a fourth per-viewer key with its own counter,
  because the relay queues it apart from everything else and may deliver it
  out of order with the rest. Only passed on for control, dev or owner. The relay queues
  file data per dashboard in a bounded queue, written after events and
  video, and drops what overflows. It caps each message at about 171 KB and
  each dashboard at 64 MB/s of uploads.
- **Shells:** the same scheme with a fifth per-viewer key for output, and
  their own associated data. Only passed on for roles that may open shells
  (dev and owner); output shares the bounded per-dashboard queue with file
  data, and keystrokes are budgeted at 1 MB/s per dashboard.
- **Roles** are capabilities, not a ladder (see the top-level README): dev
  gets shells and files but no screen. The machine never gives a dev viewer
  the stream key, and the relay neither starts capture for it nor forwards
  it frames.
- **Limits:** the relay can still refuse service, see who watches what and
  when, and delay a revocation it should pass on, though not past the
  share's expiry. A dashboard served by a compromised relay could be
  modified to leak keys; a separately hosted dashboard (see the top-level
  README) closes that.
- Machines enrolled before end-to-end encryption have no pinned owner key
  and refuse every viewer until they're enrolled again.

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

