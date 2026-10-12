# Machine config file

Some things are decided by the machine itself, never by the relay or the
dashboard: whether its clipboard can be read, whether files can be sent
to it, and whether it gives out shells. They're set in a file on the PC:

```
C:\ProgramData\HawkService\config.toml
```

The service reads it **once, when it starts**. After editing it, restart
the service, from an elevated PowerShell:

```powershell
Restart-Service HawkService
```

With no file, every feature has its defaults: clipboard **pull**, file
transfer **off**, shells **off**.

**A mistake never opens up more than the defaults.** A file that doesn't
parse, an unknown value, or the same table written twice turns that
feature **off**, and the log says why
(`C:\ProgramData\HawkService\hawk-service.log`, lines starting `config:`).

## A full example

```toml
[[clipboard]]
mode = "pull"            # off | pull | sync
max_size = 262144        # bytes of text, at most 262144 (256 KB)
view_pull = false        # let view-only shares read it too

[[files]]
enabled = true
drop_dir = ""            # empty: the signed-in user's Downloads\Hawk
max_size = 1073741824    # bytes per file, either way; at most 64 GiB

[[shell]]
enabled = true
command = "powershell.exe -NoLogo"   # or pwsh.exe, cmd.exe, ...
```

## Clipboard

Text only. The two directions are treated differently:

- **Pasting into the machine** needs control access. It's input in all
  but name.
- **Reading the machine's clipboard** depends on `mode`:

| `mode` | What viewers get |
|---|---|
| `off` | Nothing, either way. |
| `pull` (default) | They choose **Clipboard ▾ → Copy the machine's clipboard to mine** to read it once. Each read is logged. |
| `sync` | Every copy on the machine is sent to viewers allowed to read it. |

View-only shares can never paste, and can read only with
`view_pull = true`.

## Files

File transfer goes through **one folder**, never an arbitrary path:
uploads land in it, and only its contents can be downloaded. Every file
operation runs as the signed-in user, never as SYSTEM.

- `drop_dir` must be an absolute path, and may use the user's environment
  variables. Write it as a literal string with single quotes, or double
  the backslashes:

  ```toml
  drop_dir = '%USERPROFILE%\Desktop\Drop'
  drop_dir = "D:\\Shared\\Hawk"
  ```

  `"D:\Shared"` doesn't parse (`\S` is an invalid escape), so file
  transfer would be off.
- `max_size` caps each file, in both directions.

## Shell

Gives a terminal on the machine to the owner and to **Shell only** shares.

- The shell runs **as the signed-in user**, never as SYSTEM, and only
  while someone is signed in.
- Closing the tab, leaving, or losing the connection ends the shell and
  everything it started.
- Each viewer can have 2 shells open, and the machine 4.
- Every shell is logged with who opened it and for how long. What's typed
  isn't.
