# Adding a machine

Each Windows PC you want to reach runs `hawk-service`, a Windows service
that starts at boot. When someone watches, it launches `hawk-capture`
into the signed-in user's session, which captures the screen and replays
the viewer's mouse and keyboard.

## 1. Build it

The machine side is C++ built with CMake. With MSYS2's UCRT64 toolchain
and Ninja, from the repository root:

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

That puts `hawk-service.exe` and `hawk-capture.exe` in `bin\`. Keep them
side by side: the service looks for `hawk-capture.exe` in its own
directory.

**Point it at your relay before building.** The relay address is set in
the source, as `kRelayServerUrl` in `src/service/main.cpp`. It's
`wss://127.0.0.1:8080/v1/ws` by default, which only works when the relay
runs on the same PC. Change it to your relay, e.g.
`wss://relay.example.com/v1/ws`, then build.

**Trust the relay's certificate.** The machine checks the relay's
certificate against the Windows trust store. With a certificate from a
real CA there's nothing to do. With a self-signed one, import
`certs/dev-cert.pem` into the PC's *Trusted Root Certification
Authorities* (Local Machine) first.

## 2. Get an enrollment code

In the dashboard: **Machines → Add machine**. It shows a one-time code,
valid for an hour, and the exact command to run, including your relay's
pin.

The code is made in your browser, and the relay only ever sees its hash.
**Leave this browser tab open** until the machine shows up: this browser
uses the code to check the machine's key, and vouches for it on its own.

## 3. Install the service

On the PC, in an **elevated** PowerShell (right-click → *Run as
administrator*), from the repository root, paste the command the dashboard
gave you:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-service.ps1 -EnrollCode 7K3QD-WX2MP-4HZ8R-QN1CV-B6T2J -RelayPin wqsPIpg8...xW0=
```

This registers `HawkService` (runs as LocalSystem, starts at boot) and
starts it. The service then:

- creates the machine's key **inside the TPM**, where it can't be copied
  off the PC. Without a usable TPM, it uses the Windows software key store
  instead. The dashboard shows which.
- connects to the relay, proves it holds the key, and enrolls under your
  account. The code file is deleted once used.
- pins your account's key, and from then on lets in only the people you
  share it with.

The machine appears in your list within a few seconds.

| Option | Meaning |
|---|---|
| `-EnrollCode` | The one-time code. Needed the first time, or to enroll again after removing the machine. |
| `-RelayPin` | The relay's TLS key pin. Several, comma-separated, to also accept the next key ahead of a change. Without it the machine still checks the certificate, but logs a warning. |
| `-BinPath` | Where `hawk-service.exe` is, if not `bin\hawk-service.exe`. |

To reinstall an enrolled machine (after rebuilding, say), run the script
with no options: the enrollment and pins are kept.

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
| `C:\ProgramData\HawkService\hawk-service.log` | The service's log. It has no console window; look here. |
| `C:\ProgramData\HawkService\config.toml` | What the machine allows. See [Machine config file](/docs/machine-config). |
| `C:\ProgramData\HawkService\machine.txt` | Which machine it enrolled as, and its key's name. Not secret. |
| `C:\ProgramData\HawkService\owner-key.txt` | The owner's key it trusts. |
| `C:\ProgramData\HawkService\relay-pins.txt` | The relay pins it accepts. |

## Removing or moving a machine

- **Remove** it from the dashboard (*Machine* tab, owner only): the relay
  forgets its key, disconnects it, and everyone it was shared with loses
  it.
- **Uninstall** the service on the PC, from an elevated PowerShell:

  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts\uninstall-service.ps1
  ```

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
