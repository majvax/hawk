# Adding a machine

Each Windows PC you want to reach runs `hawk-service`, a Windows service
that starts at boot. When someone watches, it launches `hawk-capture`
into the signed-in user's session, which captures the screen and replays
the viewer's mouse and keyboard.

## 1. Get hawk-setup

Download `hawk-setup-<version>-windows-x64.exe` from the project's
releases. It's the whole install: it fetches the service from the same
release, checks it against the release's signature, and sets it up.

Windows may warn that the file is from an unknown publisher: the releases
aren't signed with a Windows code-signing certificate. The signature that
matters to Hawk is checked by hawk-setup itself, on everything it
installs.

## 2. Get an enrollment code

In the dashboard: **Machines → Add machine**. It shows a one-time code,
valid for an hour, with your relay's address and key pin.

The code is made in your browser, and the relay only ever sees its hash.
**Leave this browser tab open** until the machine shows up: this browser
uses the code to check the machine's key, and vouches for it on its own.

## 3. Install the service

Run `hawk-setup.exe` and choose **Set up this PC**. It asks for the
relay's address, its key pin and the code, then checks everything before
it changes anything:

- that it's running as an administrator, on Windows 10 1809 or later;
- whether there's a TPM for the machine's key;
- that the relay answers, **with the key you pinned**.

Then it installs to `C:\Program Files\Hawk\Service`, registers `HawkService`
(LocalSystem, starts at boot, restarts if it ever fails), and shows the
machine enrolling. The service:

- creates the machine's key **inside the TPM**, where it can't be copied
  off the PC. Without a usable TPM, it uses the Windows software key store
  instead. The dashboard shows which.
- connects to the relay, proves it holds the key, and enrolls under your
  account. The code file is deleted once used.
- pins your account's key, and from then on lets in only the people you
  share it with.

The machine appears in your list within a few seconds.

### From a terminal

The dashboard shows the same install as one command, for scripts and PCs
you reach without a screen. In an elevated terminal:

```powershell
hawk-setup install machine --relay relay.example.com --pin wqsPIpg8...xW0= --code 7K3QD-WX2MP-4HZ8R-QN1CV-B6T2J
```

| Option | Meaning |
|---|---|
| `--relay` | The relay's address, as the dashboard shows it. |
| `--pin` | The relay's TLS key pin. Repeat it to also accept the next key ahead of a change. Without one the machine checks only the certificate, which has to be from a CA it trusts. |
| `--code` | The one-time code. Needed the first time, or to enroll again after removing the machine. |
| `--updates` | `notify` (default), `auto` or `off`. See [Updates](/docs/updates). |
| `--quiet` | Print only warnings and errors. |

Run it again with a different `--relay` or `--pin` to change them; the
enrollment is kept. Without `--code`, an enrolled machine stays enrolled.

## 4. Verify it, if needed

Normally the browser that made the code verifies the machine on its own.
If the machine shows **Unverified** (you enrolled it from another browser,
or closed the tab), nobody can watch it until you check its key yourself:

1. Open the machine's **Machine** tab and note the fingerprint.
2. On the PC, find the line `machine key fingerprint` in
   `C:\ProgramData\HawkService\hawk-service.log`.
3. If they match, press **The fingerprints match**.

If the dashboard says the key doesn't match the code you made, don't
trust it: remove the machine and enroll it again with a new code.

## Where things are on the PC

| Path | What |
|---|---|
| `C:\Program Files\Hawk\Service` | The service, the capture helper and hawk-setup. (`C:\Program Files\Hawk` itself is the desktop app's.) |
| `C:\ProgramData\HawkService\hawk-service.log` | The service's log. It has no console window; look here. |
| `C:\ProgramData\HawkService\config.toml` | What the machine allows. See [Machine config file](/docs/machine-config). |
| `C:\ProgramData\HawkService\machine.txt` | Which machine it enrolled as, and its key's name. Not secret. |
| `C:\ProgramData\HawkService\owner-key.txt` | The owner's key it trusts. |
| `C:\ProgramData\HawkService\relay-pins.txt` | The relay pins it accepts. |

Only SYSTEM and administrators can read or change anything in
`C:\ProgramData\HawkService`: hawk-setup restricts it, so nobody else using
the PC can change what the machine allows.

## Removing or moving a machine

- **Remove** it from the dashboard (*Machine* tab, owner only): the relay
  forgets its key, disconnects it, and everyone it was shared with loses
  it.
- **Uninstall** it on the PC: *Settings → Apps → Hawk (machine service)*,
  or run hawk-setup again and choose **Uninstall**, or from an elevated
  terminal `hawk-setup uninstall machine`. It deletes the machine's key
  from the TPM too; `--keep-data` keeps the key and settings for a
  reinstall.

- **Move it to another account:** remove it in the dashboard, then enroll
  it again with a code made by the new owner. The old key is deleted from
  the TPM.

## What it needs to work

- **Someone signed in at the PC.** Capture runs in the interactive
  session, so with nobody signed in there's no screen to show. Once
  someone is, the lock screen and UAC prompts are captured and
  controllable too.
- **Outbound access to the relay** on its port. Nothing inbound: no port
  forwarding or firewall rule on the PC.
