# Running the relay

The relay is one Rust program. It serves this dashboard, the API, and the
WebSocket endpoints that browsers and machines connect to. Its state is
one SQLite database and one secret key file.

## Install on a server

On a Linux server with systemd (any current Debian, Ubuntu, Fedora…), as
root, with `hawk-setup-<version>-linux-x64` (or `-arm64`) from the
releases:

```sh
chmod +x hawk-setup-*-linux-x64
./hawk-setup-*-linux-x64 install relay --public-url https://relay.example.com --tls certbot --email you@example.com
```

It checks the release's signature, then:

- installs the relay and dashboard in `/opt/hawk`, running as its own
  `hawk` user under systemd (`hawk-relay.service`), locked down to its
  data folder, `/var/lib/hawk`;
- sets up TLS: `--tls certbot` gets a Let's Encrypt certificate (port 80
  must be reachable) that renews with **the same key**, `--tls
  self-signed` makes one, and `--tls existing --cert … --key …` uses
  yours;
- opens the port in ufw or firewalld if one is running;
- prints the relay's **key pin** and the link to create the admin account.

| Option | Meaning |
|---|---|
| `--public-url` | Where people and machines reach it. Its port is the one it listens on, unless `--port` says otherwise. |
| `--port` | Listen here instead, behind a proxy or a port forward. |
| `--origin` | Another origin allowed to use this relay: a separately hosted dashboard. The desktop app is always allowed. Repeat for several. |
| `--smtp-url`, `--mail-from` | Mail, see [Email](#email). |
| `--updates` | `notify` (default), `auto` or `off`. See [Updates](/docs/updates). |

Settings end up in `/etc/hawk/relay.env`; change them there and
`systemctl restart hawk-relay`. Run `hawk-setup status` to see what's
installed, and `hawk-setup uninstall relay` to remove it (the database,
settings and TLS key stay unless you add `--delete-data`).

A self-signed certificate is fine for machines, which pin its key, but
browsers warn about it and the desktop app refuses it: give the relay a
domain and a real certificate if people will use either.

## Build from source

You need a Rust toolchain (`cargo`) and [bun](https://bun.sh). All commands
run from `src/server` in the repository.

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
| `HOST` | `127.0.0.1` | Address to listen on. `0.0.0.0` for every IPv4 interface, `[::]` for IPv6 and IPv4 both (what hawk-setup sets). |
| `PORT` | `8080` | Port to listen on. |
| `PUBLIC_URL` | the listen address | The address people reach the dashboard at. Used in the links the relay logs and emails. Set it in production. |
| `TLS_CERT_PATH` | `certs/dev-cert.pem` | TLS certificate (PEM). |
| `TLS_KEY_PATH` | `certs/dev-key.pem` | TLS private key (PEM). |
| `HAWK_DB_PATH` | `data/hawk.db` | The SQLite database. |
| `HAWK_SECRET_KEY_PATH` | `secret.key` beside the database | The key two-factor secrets are encrypted with. |
| `HAWK_SMTP_URL` | none | Mail server, to send verification links and security notices. See [Email](#email). |
| `HAWK_MAIL_FROM` | none | Sender address, e.g. `Hawk <hawk@example.com>`. |
| `FRONTEND_DIST` | `frontend/dist` | The built dashboard to serve. |
| `HAWK_ALLOWED_ORIGINS` | none | Other origins that may sign in to this relay, comma separated: the desktop app (`http://tauri.localhost,tauri://localhost`) and any separately hosted dashboard. They get bearer tokens instead of the cookie. |
| `HAWK_AUDIT_RETENTION_DAYS` | `90` | How many days the activity log keeps events. `0` keeps them forever. Older ones are deleted hourly. |
| `HAWK_SERVER_ROOT` | `src/server` | The directory the default paths above are relative to. |
| `RUST_LOG` | `info` | Log detail, e.g. `debug`. |

## TLS and the pin

The relay serves HTTPS whenever it finds a certificate and key. Without
one it falls back to plain HTTP with a warning. That's fine for a quick
local test, but machines always connect with `wss://`, so **a machine
can't connect to a relay without TLS**.

- **On the internet:** use a certificate from a real CA for a domain
  pointed at the server, e.g. Let's Encrypt.
- **On a LAN:** `bun run certs` (or `hawk-setup install relay --tls
  self-signed`) makes a self-signed one. Machines given its pin accept
  it as it is. Browsers have to trust it: import its certificate into
  *Trusted Root Certification Authorities*.

At startup the relay logs `relay certificate pin`, the SHA-256 of its TLS
**key**. The dashboard shows it with every enrollment code.
A machine with a pin refuses any other key, even one with a certificate
its system trusts, so a rogue CA or an intercepting proxy can't pose as
your relay.

Because the pin is the key, not the certificate, **renewing is fine as
long as the key stays the same** (with certbot: `--reuse-key`).
`bun run certs` also reuses the existing key. To move to a new key:

1. Add the new pin on every machine first, alongside the old one:
   `hawk-setup install machine --pin <old> --pin <new>`.
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
