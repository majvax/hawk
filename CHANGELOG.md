# Changelog

Each release's section becomes its release notes (see
`.github/workflows/release.yml`). Newest first.

## Unreleased

- **Sign in remotely.** With nobody signed in, after a restart, a crash
  or a sign-out, the view shows the Windows sign-in screen instead of
  nothing. When the session opens, the view follows it on its own.
  Capture also starts again by itself if `hawk-capture` exits.
- **Power ▾** in the live view: lock, sign out, restart and shut down,
  for control and the owner, after a fresh code. The command is end-to-end
  encrypted like input, so the relay can neither read nor forge it.
- A machine restarting from the dashboard shows as **Restarting**, not
  offline, and the view comes back by itself.
- **Sound.** What the machine plays comes with the picture: WASAPI
  loopback on its default output device, Opus at 96 kbit/s, sealed in the
  stream like the video. It follows a change of output device, keeps
  playing on the lock and sign-in screens, and sends nothing while the
  machine is quiet. **Sound on / off** in the live view; `[[audio]] enabled
  = false` in the machine's config keeps it in the room. Firefox for
  Android, which has no WebCodecs, plays it through MSE as Opus in
  fragmented MP4, like its picture.
- Protocol version 4.

## 1.0.0

The first release.

- **Remote desktop through your own relay**, end-to-end encrypted: screen,
  mouse and keyboard, the lock screen and UAC prompts included; clipboard
  sync, file transfer and a shell for `dev` shares, each off unless the
  machine's config allows it.
- **Accounts** by invitation, with TOTP and recovery codes, step-up for
  sensitive actions, email verification and security notices.
- **hawk-setup**, one installer for every part: a window on Windows and a
  CLI everywhere. It installs the machine service (with a preflight that
  checks the relay's pinned key before anything is written), the relay on
  a Linux server (systemd, Let's Encrypt with a stable key), and the
  desktop app.
- **Signed updates** for the machine service, the relay and the app, from
  one release feed, with `notify`, `auto` or `off` per install, `stable`
  and `beta` channels, and rollback when a new version doesn't come up.
  Forks follow their own feed and key with nothing to edit.
- **Desktop app** for Windows and Linux (an AppImage, and a `PKGBUILD` for
  Arch): the dashboard in its own window, signing in to any relay
  that allows it (`HAWK_ALLOWED_ORIGINS`), several relays remembered.
- Machines show their version, and offer an update in the owner's
  dashboard.
- **Analytics and Processes** tabs: CPU (per core), memory, GPU, network
  and disks, live and over 1 hour, 24 hours or 7 days, and every process
  with its CPU and memory. The machine samples itself and keeps the
  history; it's read over the end-to-end encrypted session and never
  stored on the relay. Owners see it; a share sees it only if the owner
  ticked Analytics. Protocol version 2.
