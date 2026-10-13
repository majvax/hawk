# Scripts

`bump-version.py` sets the version everywhere, and `release/` holds the
release tooling (see "Releasing" in the main README).

The PowerShell scripts below are the developer's way to run a build from
`bin\` as the service. Installs from a release use `hawk-setup` instead
(`src/installer`), which also locks down `C:\ProgramData\HawkService`,
registers updates and can uninstall cleanly. All require an **elevated**
PowerShell prompt (right-click → Run as administrator). Run them on the
Windows machine you are capturing, not the relay host.

| Script | Purpose |
|---|---|
| `install-service.ps1` | Registers `hawk-service.exe` as the `HawkService` Windows service (LocalSystem, auto-start) and starts it. |
| `uninstall-service.ps1` | Stops and removes the service. |
| `run-as-system.ps1` | Runs any executable once as `NT AUTHORITY\SYSTEM` for ad-hoc debugging. |

## Typical flow

In the dashboard, open **Machines → Add machine** to get a one-time
enrollment code (valid for an hour), then on the PC:

```powershell
# from the repo root, after building into bin\ (copy the exact command the
# dashboard shows; it includes your relay's pin)
powershell -ExecutionPolicy Bypass -File scripts\install-service.ps1 -EnrollCode 7K3QD-WX2MP-4HZ8R-QN1CV-B6T2J -RelayPin wqsPIpg8...xW0=
```

The service connects to the relay (`wss://127.0.0.1:8080/v1/ws` by
default — see `kRelayServerUrl` in `src/service/main.cpp`) and enrolls:

- It creates an ECDSA P-256 key **inside the TPM** (Microsoft Platform
  Crypto Provider), non-exportable, so the private key never leaves the
  chip. Without a usable TPM it falls back to a non-exportable key in the
  Windows software key store; the dashboard shows which one each machine
  has. Secure Boot is not required.
- It sends the public key with the code, and proves it holds the private key
  by signing a challenge from the relay. From then on, every connection is
  a fresh challenge signed in the TPM. There's no secret on disk or on the
  wire to steal or replay.
- The code itself never leaves the PC: the relay gets its hash. The service
  MACs its public key with the code, and checks the owner key the relay
  answers with against the owner's own MAC under the same code. Only if that
  matches does it pin the owner's key in `owner-key.txt`; from then on it
  admits only viewers the owner has signed a grant for (see "End-to-end
  encryption" in `src/server/README.md`). It logs its own key's fingerprint
  (`machine key fingerprint`) on every connect, for the owner to compare.
- `C:\ProgramData\HawkService\machine.txt` records which machine it enrolled
  as and the key's name (neither is secret). The code file is deleted once
  used; a rejected code is deleted too, and leaves the existing enrollment
  and key untouched. `access-state.txt` remembers the newest grant and
  revocation seen per viewer, so an old grant can't be replayed.

`-RelayPin` pins the relay's TLS key (`relay-pins.txt`): the service then
refuses any relay whose certificate doesn't carry that key, even one that
chains to a root this PC trusts, before sending anything. Pass several
(`-RelayPin pinA,pinB`) to also accept a backup key ahead of a rotation.
Without it the service still works, checking only the certificate chain, and
logs a warning.

Reinstalling an enrolled machine needs neither option (pins already set are
kept). To move a machine to another account, remove it in the dashboard and
enroll it again with a new code; the old key is deleted from the TPM.

Once enrolled, the service waits for a `start_capture` command. It launches `hawk-capture.exe` into the logged-on
user's session on demand, so a user must be signed in at the console for
capture to start. That same helper replays the viewer's mouse and keyboard
with `SendInput`; the service passes the events to it over a private named
pipe and never injects anything itself (Session 0 has no desktop to type
into).

Logs: `C:\ProgramData\HawkService\hawk-service.log`.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\uninstall-service.ps1
```

## Notes

- `hawk-capture.exe` must sit next to `hawk-service.exe`; the service looks
  for it in its own directory.
- Because the service runs in Session 0, it has no console — watch the log
  file above rather than expecting output in a window.
- If you change `kRelayServerUrl` to a non-localhost relay, the server's TLS
  certificate must be trusted by this machine (see `src/server/README.md`).
