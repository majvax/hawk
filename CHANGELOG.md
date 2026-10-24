# Changelog

Each release's section becomes its release notes (see
`.github/workflows/release.yml`). Newest first.

## Unreleased

- **Touch and phones.** Fingers on the live view have a mapping of their
  own. **Trackpad** (the default on a phone): drag to move the pointer,
  faster for a quick flick, tap to click, two-finger tap to right-click,
  hold then drag to drag, two fingers to scroll; the machine's pointer is
  drawn over the picture. **Touch** (the default on a tablet): tap where
  you click, drag to drag, hold to right-click, two fingers to scroll.
  Remembered in the browser. **Pinch** zooms the picture on your screen
  (not the machine's), clicks still land where they should, and in
  trackpad mode the picture follows the pointer; **Fit** or a two-finger
  double tap goes back. Watching only, you can still zoom. **Keyboard**
  brings up the phone's keyboard, with a row of Esc, Tab, arrows and Ctrl,
  Alt, Shift and Win held for the next key. The mouse and keyboard work as
  before.
- **Typed text arrives as characters.** What a phone's keyboard types
  reaches the machine as the characters themselves (a new `text` input
  event, sealed like the rest, typed with `KEYEVENTF_UNICODE`), so accents,
  emoji and other scripts come out right whatever the machine's keyboard
  layout. Enter, Tab and Backspace are still real keys. A shortcut made
  with the sticky Ctrl, Alt or Win goes as the modifiers and the
  character, and the machine presses the key that types it in its own
  layout, so `Ctrl` then `a` is `Ctrl+A` on AZERTY too. A machine older
  than this release gets US keys instead, without what no US key types.
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
- **Sync to sound** in the live view: the picture waits for the sound of
  the same instant, for watching rather than controlling. Off by default,
  remembered in the browser.
- **Sound ▾** lists the machine's output devices; control and the owner
  can choose which one the stream carries (after a fresh code, as with
  power). The choice lasts until the stream stops.
- **Stats** in the live view lays the stream's numbers over the picture:
  bitrate, frames received, decoded and shown, frames dropped or skipped,
  what's waiting in the decoder and how long decoding takes (on the MSE
  fallback, how far playback runs behind instead), the round trip to the
  machine, and the sound's buffer. Remembered in the browser. The round
  trip is a ping the machine echoes back, sent only while the stats show.
- **Config tab** for a machine: its `config.toml` as a form, built from a
  description the machine sends of each setting (type, range, default,
  whether it applies at once). Control can read it; the owner can change
  it after a fresh code. Changes are end-to-end encrypted, checked by the
  machine against the same rules it starts with, and written over the file
  in one piece, comments kept. The clipboard and sound settings apply at
  once (the stream restarts for a moment); the rest when the service next
  starts. Anything that widens what the machine allows (shell, file
  transfer, the drop folder, the relay, the update feed and key) is locked
  by default: a `[[locked]]` list on the machine says which settings the
  dashboard may only read. A change made against a file that was edited
  on the machine meanwhile is refused.
- Fixed: an `[[audio]]` table in the machine's config made the whole file
  fail to parse, turning the clipboard, file transfer, shell and relay
  connection off.
- **Quality ▾** in the live view: Auto, Low (1 Mbit/s, 30 fps), Balanced
  (4), High (8) or Max (16), for control and the owner, for everyone
  watching, until the stream stops. The machine's default is
  `[[stream]] quality` in its config (`auto` unless set), which applies at
  once. The encoder takes a new bitrate without restarting; a new frame
  rate starts it over. The choice is end-to-end encrypted like input, and
  the machine checks the role again.
- **Auto** adapts the bitrate (0.5 to 12 Mbit/s) to the connection: the
  relay measures how long frames take to arrive from the machine and how
  many wait for each viewer, cuts by 30% on congestion and climbs slowly
  once it's clear. The slowest viewer sets the pace. **Stats** shows the
  preset and the bitrate the machine targets.
- **Ctrl+Alt+Del** in the live view, or `Ctrl+Alt+End` on the screen as in
  Remote Desktop: the machine has Windows press it (`SendSAS`), so a
  sign-in screen that asks for Ctrl+Alt+Del can be signed in to remotely,
  and a signed-in machine shows its security options. For control and the
  owner, end-to-end encrypted like input, and the machine checks the role
  again. Windows only takes it from a service when its
  `SoftwareSASGeneration` policy allows that: `hawk-setup install machine`
  turns services on (1, or 3 where ease of access apps already had it)
  and puts the policy back on uninstall. Updates don't change the policy:
  a machine that updates to this release needs `hawk-setup install machine`
  run on it once to allow it. A machine that doesn't allow it says so in
  the live view, with what to change.
- **Clipboard pictures.** Images go both ways, as text does: paste one into
  the machine (**Clipboard ▾**, or `Ctrl+V` on the screen), copy the
  machine's to yours, or in sync mode have every picture copied there come
  to you, under the same roles and modes. They travel as PNG: the machine
  reads `PNG`, `CF_DIBV5` or `CF_DIB` (encoding bitmaps with WIC) and puts a
  pasted picture on as `PNG`, `CF_DIBV5` and `CF_DIB`, so any app can paste
  it. Up to 8 MB of PNG and 8K pixels; a larger one is skipped with a note,
  never cut. When the clipboard holds text as well, the text goes. Pictures
  travel in 64 KB chunks on a channel of their own, with a few in flight at
  a time, so a large one never holds up input or the picture; the relay
  budgets them apart from text. `[[clipboard]] images = false` keeps the
  clipboard to text. A browser that won't put pictures on its clipboard
  (older Firefox) shows the picture to save or copy by hand; one that won't
  hand them over still sends one with `Ctrl+V` on the screen. Older machines
  and dashboards stay text-only.
- Protocol version 10.

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
