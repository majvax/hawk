# Scripts

Administration helpers for the host machine. All require an **elevated**
PowerShell prompt (right-click → Run as administrator). Run them on the
Windows machine you are capturing, not the relay host.

| Script | Purpose |
|---|---|
| `install-service.ps1` | Registers `hawk-service.exe` as the `HawkService` Windows service (LocalSystem, auto-start) and starts it. |
| `uninstall-service.ps1` | Stops and removes the service. |
| `run-as-system.ps1` | Runs any executable once as `NT AUTHORITY\SYSTEM` for ad-hoc debugging. |

## Typical flow

```powershell
# from the repo root, after building into bin\
powershell -ExecutionPolicy Bypass -File scripts\install-service.ps1
```

The service then connects to the relay (`wss://127.0.0.1:8080/v1/ws` by
default — see `kRelayServerUrl` in `src/service/main.cpp`) and waits for a
`start_capture` command. It launches `hawk-capture.exe` into the logged-on
user's session on demand, so a user must be signed in at the console for
capture to start.

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
