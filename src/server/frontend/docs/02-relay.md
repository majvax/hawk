# Running the relay

The relay is one Rust program. It serves this dashboard, the API, and the
WebSocket endpoints that browsers and machines connect to. Its state is
one SQLite database and one secret key file.

You need a Rust toolchain (`cargo`) and [bun](https://bun.sh). All commands
run from `src/server` in the repository.

## Build and start

```sh
bun install
bun run build    # builds the dashboard into frontend/dist, and the release relay
bun run start    # runs the relay on 127.0.0.1:8080
```

By default it listens on `127.0.0.1` only. Set `HOST=0.0.0.0` to accept
connections from other computers.

### For development

```sh
bun run certs          # self-signed certificate for localhost, once
bun run dev:relay      # terminal 1: the relay on :8080
bun run dev:frontend   # terminal 2: the dashboard on :5173, with live reload
```

To reach a development relay from another computer on your network, add
this PC's address to the certificate and listen on every interface:

```sh
bun run certs -- 192.168.1.150 my-pc
bun run dev:relay:lan
```

Then let port 8080 through Windows Firewall, from an elevated PowerShell:

```powershell
New-NetFirewallRule -DisplayName "Hawk relay (LAN)" -Direction Inbound -Protocol TCP -LocalPort 8080 `
  -Action Allow -Profile Private -RemoteAddress LocalSubnet
```

The other computer browses to `https://192.168.1.150:8080`. It warns about
the certificate until `certs/dev-cert.pem` is imported into its trusted
roots.

## Environment variables

| Variable | Default | What it sets |
|---|---|---|
| `HOST` | `127.0.0.1` | Address to listen on. `0.0.0.0` for every interface. |
| `PORT` | `8080` | Port to listen on. |
| `PUBLIC_URL` | the listen address | The address people reach the dashboard at. Used in the links the relay logs and emails. Set it in production. |
| `TLS_CERT_PATH` | `certs/dev-cert.pem` | TLS certificate (PEM). |
| `TLS_KEY_PATH` | `certs/dev-key.pem` | TLS private key (PEM). |
| `HAWK_DB_PATH` | `data/hawk.db` | The SQLite database. |
| `HAWK_SECRET_KEY_PATH` | `secret.key` beside the database | The key two-factor secrets are encrypted with. |
| `HAWK_SMTP_URL` | none | Mail server, to send verification links and security notices. See [Email](#email). |
| `HAWK_MAIL_FROM` | none | Sender address, e.g. `Hawk <hawk@example.com>`. |
| `FRONTEND_DIST` | `frontend/dist` | The built dashboard to serve. |
| `HAWK_SERVER_ROOT` | `src/server` | The directory the default paths above are relative to. |
| `RUST_LOG` | `info` | Log detail, e.g. `debug`. |

## TLS and the pin

The relay serves HTTPS whenever it finds a certificate and key. Without
one it falls back to plain HTTP with a warning. That's fine for a quick
local test, but machines always connect with `wss://`, so **a machine
can't connect to a relay without TLS**.

- **On the internet:** use a certificate from a real CA for a domain
  pointed at the server, e.g. Let's Encrypt.
- **On a LAN:** `bun run certs` makes a self-signed one. Every machine and
  every browser that connects has to trust it: import
  `certs/dev-cert.pem` into *Trusted Root Certification Authorities*.

At startup the relay logs `relay certificate pin`, the SHA-256 of its TLS
**key**. The dashboard puts it in every install command as `-RelayPin`.
A machine with a pin refuses any other key, even one with a certificate
its system trusts, so a rogue CA or an intercepting proxy can't pose as
your relay.

Because the pin is the key, not the certificate, **renewing is fine as
long as the key stays the same** (with certbot: `--reuse-key`).
`bun run certs` also reuses the existing key. To move to a new key:

1. Add the new pin on every machine first, alongside the old one:
   `install-service.ps1 -RelayPin <old>,<new>`.
2. Then switch the relay to the new key.

## Email

Optional. With a mail server set, the relay asks new accounts to confirm
their address, and tells account holders when their sign-in settings
change.

```sh
HAWK_SMTP_URL='smtps://user:password@mail.example.com:465'
# or, for STARTTLS on port 587:
HAWK_SMTP_URL='smtp://user:password@mail.example.com:587?tls=required'
HAWK_MAIL_FROM='Hawk <hawk@example.com>'
```

Set both or neither: with only one, the relay refuses to start. Set
`PUBLIC_URL` too, so links point at the right address. With neither set,
nothing is sent and email addresses are taken as given.

Mail is sent in the background. If it doesn't arrive, look for
`mail: sending failed` in the relay's log.

## Backups

Back up these two files together, ideally with the relay stopped:

- **The database** (`data/hawk.db`): accounts, machines, shares, sessions.
- **The secret key** (`data/secret.key`): 32 random bytes the relay makes
  on its first start. Two-factor secrets are encrypted with it.

A database restored without its key still works, but no one's
authenticator app does: the admin has to reset two-factor for every
account, and everyone sets it up again.

Keep the TLS key too. A new key means a new pin, and every machine
refuses it until you update the pin on it.

## Behind a reverse proxy

The relay can sit behind a proxy such as nginx or Caddy. The proxy must
pass WebSocket upgrades on `/v1/ws` (machines) and `/v1/dashboard`
(browsers), and keep the original `Host` header: the dashboard socket is
refused when the page's origin doesn't match it.

Two catches:

- **Pinning:** machines pin the key of the certificate *they* see. When
  the proxy terminates TLS, that's the proxy's key, so put the proxy's pin
  on machines, not the relay's.
- **Login throttling** counts failed sign-ins per client address. Behind a
  proxy, every client shares the proxy's address, so the limit applies to
  everyone at once.
