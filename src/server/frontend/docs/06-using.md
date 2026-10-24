# Using a machine

**Machines** lists your machines and the ones shared with you, online or
not. Select one to open it. Its tabs depend on what you're allowed to do:

| Tab | Who gets it |
|---|---|
| **Screen** | Owner, *View only*, *Can control* |
| **Terminal** | Owner, *Shell only* |
| **Files** | Owner, *Can control*, *Shell only* |
| **Config** | Owner (to change it), *Can control* (to read it) |
| **Sharing**, **Machine** | Owner |

The connection to each machine is encrypted end to end before anything
shows. If it can't be secured, the dashboard says why instead of showing
the screen.

## Watching and control

The screen starts streaming as soon as you open it.

To use the mouse and keyboard, **click the screen**. Click outside it,
or press **Release**, to take them back. If the button says **Confirm to
control**, enter a code from your authenticator first (see
[two-factor](/docs/accounts#confirming-sensitive-actions)).

- **Keys are sent as physical keys.** The machine applies its own
  keyboard layout, as if a keyboard were plugged into it.
- **Full screen** also captures the shortcuts the browser normally keeps,
  such as `Alt+Tab`, `Ctrl+W` and `Esc`, in Chromium-based browsers
  (Chrome, Edge). **Hold `Esc`** to leave full screen.
- **`Ctrl+Alt+Del` stays on your computer.** To press it on the machine,
  use the **Ctrl+Alt+Del** button above the screen, or press
  `Ctrl+Alt+End` on the screen, as in Remote Desktop. See
  [Ctrl+Alt+Del](#ctrl-alt-del).
- Your own mouse pointer stands in for the machine's. People only
  watching see no pointer.

If your connection drops, the dashboard reconnects on its own and the
view picks up where it was.

## Stream stats

**Stats** above the screen lays the stream's numbers over the top-left
corner of the picture, each over the last second:

- **Video**: what the picture costs your connection.
- **Quality**: the stream's preset and the bitrate the machine encodes
  at; on *Auto*, its current target. *N/A* from a machine older than
  this dashboard.
- **Frames/s**: frames that arrived, came out of the decoder, and were
  shown. **Lost/s**: decoded but never shown (*dropped*), or thrown away
  before decoding because they piled up (*skipped*); the picture then
  waits for the next keyframe.
- **Waiting**: frames still being decrypted, and inside the decoder.
- **Decode**: how long the decoder takes per frame. On the fallback that
  Firefox for Android uses, the browser doesn't say, so **Behind** shows
  how far its playback runs behind what has arrived instead. Anything a
  decoder can't measure shows as *N/A*.
- **Round trip**: to the machine and back, through the relay. A machine
  older than this dashboard can't answer, and shows *N/A*.
- **Sound**: how much sound is queued ahead of what you hear.

The overlay doesn't take clicks, so you can control the machine through
it. It's remembered in this browser.

## Quality

**Quality ▾** above the screen picks how the picture is encoded, with
control or as the owner (no code needed: it changes nothing but the
picture). Everyone watching shares one stream, so the choice is for all of
them, and lasts until the stream stops; then the machine's own default
(`stream.quality` in its [config](/docs/machine-config#stream-quality))
applies again.

- **Auto** follows the connection: the relay watches how long the
  machine's frames take to reach it and how many are waiting for each
  viewer, cuts the bitrate by 30% when frames pile up, and raises it
  slowly (0.3 Mb/s a second) once things have been clear for a few
  seconds and the picture is using what it has. With several viewers, the
  slowest one sets the pace. Between 0.5 and 12 Mb/s.
- **Low** (1 Mb/s, 30 fps), **Balanced** (4 Mb/s), **High** (8 Mb/s) and
  **Max** (16 Mb/s) hold one bitrate whatever the connection does.

A new bitrate takes effect at once; a new frame rate (to or from Low)
starts the machine's encoder over, so the picture may hitch once.
View-only shares don't get the menu, but see the preset in **Stats**.

## Sound

What the machine plays comes with the picture, from its default output
device, on the lock screen and the sign-in screen too. **Sound on / Sound
off** above the screen mutes it on your side, and is remembered in this
browser. If it says **Click for sound**, your browser is holding the sound
back until you click the page. A quiet machine sends no sound at all.

Picture and sound each play as soon as they arrive, which is what
controlling the machine wants, so they can be a little apart. For
watching something, turn on **Sync to sound** under **Sound ▾**: the
sound gets a slightly deeper buffer and the picture waits for it, at the
cost of a little delay. It's remembered in this browser.

**Sound ▾** also lists the machine's output devices. With control (or as
the owner) you can choose which one you hear, after confirming it's you;
the picture pauses for a moment while the machine switches. It changes
what everyone watching hears, and goes back to the default when the
stream stops.

Sound needs a browser that can decode it (Chrome, Edge, Firefox, on a
phone too, recent Safari). Where it can't, the button doesn't show, and the
picture plays as before. The machine's owner can turn sound off in the
[config file](/docs/machine-config#audio).

## Signing in remotely

When nobody is signed in, after a restart, a crash or a sign-out, the
screen shows the Windows sign-in screen. Click it and type the password
as you would at the PC. When the session opens, the view follows it.

If the PC asks for `Ctrl+Alt+Del` before signing in, press the
**Ctrl+Alt+Del** button above the screen (or `Ctrl+Alt+End`): the
machine has Windows press it, and the password box comes up. Leave that
requirement on: it protects against fake sign-in screens.

## Ctrl+Alt+Del

**Ctrl+Alt+Del** above the screen (needs control, like the mouse and
keyboard) has Windows press `Ctrl+Alt+Del` on the machine, the way the
real keyboard would: the password box at a sign-in screen that asks for
it, or the security options (Lock, Switch user, Sign out, Task Manager)
while someone is signed in. With the screen clicked, `Ctrl+Alt+End` does
the same. A message under the screen says whether it was pressed.

Windows only lets a service press it when its policy allows that, and
`hawk-setup install machine` turns it on. If the message says the machine
doesn't allow it, see
[troubleshooting](/docs/troubleshooting#ctrl-alt-del-does-nothing). A
machine older than this dashboard has no button until it's updated.

## Power

**Power ▾** above the screen (needs control, and a fresh code):

- **Lock** puts the sign-in screen up. The session and its apps wait
  behind it.
- **Sign out** ends the session that's signed in.
- **Restart** restarts the machine. It shows as **Restarting** until it's
  back, then the view comes back by itself at the sign-in screen.
- **Shut down** turns it off. It stays off until someone turns it on.

Sign out, Restart and Shut down close every app, **saved or not**, so
they ask for a second click. A machine older than this dashboard has no
Power menu until it's updated.

## Clipboard

**Clipboard ▾** under the screen:

- **Paste my clipboard to the machine** sends text or a picture from your
  computer to the machine's clipboard (needs control). Then press `Ctrl+V`
  on the machine. If your browser won't hand over your clipboard, a box
  appears to paste the text into.
- **Copy the machine's clipboard to mine** reads it onto your computer:
  its text, or the picture on it.

`Ctrl+V` on the screen does both at once: what's on your clipboard goes
to the machine's, then the machine pastes it. A picture takes a moment to
get there, and the machine pastes once it has; one too large isn't pasted,
and the note under the screen says why.

Pictures go as PNG, up to 8 MB and 8K pixels; larger ones are skipped,
never cut. When your clipboard (or the machine's) holds text as well as a
picture, the text goes. Some browsers handle pictures only partly:

- **Firefox** before version 127 can't put a picture on your clipboard:
  the picture shows under the screen instead, to right-click and copy, or
  save.
- A browser that won't hand the page pictures from your clipboard still
  sends one with `Ctrl+V` on the screen.

What's allowed depends on the machine's
[config file](/docs/machine-config#clipboard).

## Files

**Send files** in the *Files* tab, or **drop files on the screen**, to send
them. They land in the machine's drop folder (the signed-in user's
`Downloads\Hawk` unless the config says otherwise). The tab also lists
what's in that folder, to download.

- A file whose name is taken becomes `name (1).ext`.
- If a transfer is cut off, send or download the same file again and it
  picks up where it stopped.
- Every file is checked with SHA-256 at the end.

File transfer is off unless the machine's
[config file](/docs/machine-config#files) turns it on.

## Terminal

A shell on the machine, running as the signed-in user, with no video at
all: it works over a slow connection. **New shell** opens one; each is a
tab. **Full screen** sends shortcuts like `Ctrl+W` to the shell too.

Shells are off unless the machine's
[config file](/docs/machine-config#shell) turns them on.

## Config

The machine's [config file](/docs/machine-config) as a form, while
connected. With control you can read it; as the owner you can change what
isn't locked, after confirming it's you, and **Save**. The machine checks
every change and says why if it refuses one. Settings marked **after
restart** wait for the machine's service to start again; the rest apply at
once.

## Who's watching

As the owner, you see live who is watching each of your machines.
