# Machine config file

Some things are decided by the machine itself, never by the relay:
whether its clipboard can be read, whether files can be sent to it, and
whether it gives out shells. They're set in a file on the PC:

```
C:\ProgramData\HawkService\config.toml
```

The service reads it **when it starts**. After editing it, restart the
service, from an elevated PowerShell:

```powershell
Restart-Service HawkService
```

The owner can also change it from the dashboard, in the machine's
**Config** tab (see [below](/docs/machine-config#from-the-dashboard)).

With no file, every feature has its defaults: sound **on**, clipboard
**pull**, file transfer **off**, shells **off**.

**A mistake never opens up more than the defaults.** A file that doesn't
parse, an unknown value, or the same table written twice turns that
feature **off**, and the log says why
(`C:\ProgramData\HawkService\hawk-service.log`, lines starting `config:`).

## A full example

```toml
[[stream]]
quality = "auto"         # auto | low | balanced | high | max

[[audio]]
enabled = true           # what the machine plays goes to its viewers

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

[[metrics]]
enabled = true           # the Analytics and Processes tabs
history_days = 7         # how long the machine keeps its history, 1 to 90

[[locked]]               # what the Config tab may only read; see below
keys = ["shell.enabled", "shell.command", "files.enabled", "files.drop_dir",
        "relay.url", "update.manifest_url", "update.public_key"]
```

## From the dashboard

The machine's **Config** tab shows this file as a form, with each
setting's default and a line about it. It needs a live connection to the
machine, and a machine whose service is new enough (older ones don't show
it).

- **Control** shares can read it. Only the **owner** can change it, after
  confirming with a fresh code, as with power actions.
- The change is end-to-end encrypted. The machine checks it against the
  same rules it uses at startup and refuses it, saying why, if anything is
  wrong. Only the lines that change are rewritten; comments stay.
- The clipboard settings and `audio.enabled` take effect **at once** (the
  picture pauses for a moment while the machine's capture restarts), and
  so does `stream.quality`, without a pause, unless a viewer picked a
  preset for the stream that's running.
  Settings marked **after restart** take effect when the service next
  starts. Viewers already connected see a clipboard change in their menu
  the next time they connect, but the machine holds them to it at once.
- If the file was edited on the machine since the tab loaded it, the
  change is refused and the tab shows the file as it is now.

**Locked settings** can only be changed at the machine. By default those
are the ones that widen what the machine allows: `shell.enabled`,
`shell.command`, `files.enabled`, `files.drop_dir`, `relay.url`,
`update.manifest_url` and `update.public_key`. A `[[locked]]` table
replaces that list: add `clipboard.mode` to keep the clipboard as you set
it here, or leave `keys = []` to let the owner change everything from the
dashboard. A name in it that isn't a setting locks everything, so a typo
can't unlock anything.

## Audio

What the machine plays (its default output device, or the one a viewer
with control chose for the stream) goes to everyone watching, with the
picture. Anyone who may watch hears it, view-only shares
included. `enabled = false` keeps the room's sound in the room. A config
that doesn't parse turns sound off too.

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

## Metrics

The machine's health for the **Analytics** and **Processes** tabs. On by
default: nothing leaves the machine unless someone allowed asks for it.

- The machine samples itself once a second and keeps the history itself,
  in `C:\ProgramData\HawkService\metrics`: every second for the last
  hour, every minute for `history_days` (about 100 KB a day). Nothing is
  stored on the relay.
- `enabled = false` stops the sampling and closes both tabs for everyone.
- See [Analytics](/docs/analytics) for what's measured and who can see it.

## Stream quality

`[[stream]] quality` is how the picture is encoded until a viewer with
control picks another preset from **Quality ▾** in the live view (see
[Using a machine](/docs/using#quality)):

| Preset     | Bitrate                          | Frame rate |
| ---------- | -------------------------------- | ---------- |
| `auto`     | follows the connection, 0.5–12 Mb/s, starting at 4 | 60 |
| `low`      | 1 Mb/s                           | 30         |
| `balanced` | 4 Mb/s                           | 60         |
| `high`     | 8 Mb/s                           | 60         |
| `max`      | 16 Mb/s                          | 60         |

The default is `auto`. A value it doesn't know is logged, and the stream
stays on `auto`.
