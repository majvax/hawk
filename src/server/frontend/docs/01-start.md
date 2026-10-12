# Getting started

Hawk lets you use your own Windows PCs from any browser, through a relay
server you run yourself. No port forwarding, no third-party service: the
PC and the browser both connect *out* to your relay, and the relay pairs
them.

## The three parts

| Part | Runs on | What it does |
|---|---|---|
| **Relay** | A server or VPS (or your own PC, for testing) | Serves this dashboard, holds accounts, and passes encrypted traffic between browsers and machines. |
| **Dashboard** | Your browser | Where you sign in, add machines, watch and control them, and share them. |
| **Machine service** | Each Windows PC you want to reach | `hawk-service` starts at boot as a Windows service and keeps a connection to the relay. `hawk-capture` runs in the signed-in user's session while someone watches. |

The screen, input, clipboard, files and shells are encrypted end to end
between your browser and the machine. The relay passes them on but can't
read them. See [Security model](/docs/security).

## Setup, in order

1. **Run the relay** and give it a TLS certificate. Note the **pin** it
   logs at startup. See [Running the relay](/docs/relay).
2. **Create the admin account** with the one-time link the relay logs on
   its first start. See [Accounts and sign-in](/docs/accounts).
3. **Turn on two-factor** in *Settings* (recommended), and invite anyone
   else from the *Admin* tab.
4. **Add a machine:** *Machines → Add machine* gives a one-time code and the
   exact install command to run on the PC. See
   [Adding a machine](/docs/machine).
5. **Choose what the machine allows** (clipboard, file transfer, shells) in
   its own config file. Everything beyond the screen is off or limited by
   default. See [Machine config file](/docs/machine-config).
6. **Share it**, if you want to, from the machine's *Sharing* tab. See
   [Sharing](/docs/sharing).

Something not working? See [Troubleshooting](/docs/troubleshooting).

## Quick local test

To try everything on one PC before deploying anything, from
`src/server` in the repository:

```sh
bun install
bun run certs        # a self-signed certificate for localhost, once
bun run dev:relay    # the relay on https://127.0.0.1:8080
```

Open `https://127.0.0.1:8080`, accept the certificate warning, and create
the admin account with the link in the relay's output. Then build and
install the machine service on the same PC (see
[Adding a machine](/docs/machine)). It connects to `127.0.0.1:8080` by
default.
