# Using a machine

**Machines** lists your machines and the ones shared with you, online or
not. Select one to open it. Its tabs depend on what you're allowed to do:

| Tab | Who gets it |
|---|---|
| **Screen** | Owner, *View only*, *Can control* |
| **Terminal** | Owner, *Shell only* |
| **Files** | Owner, *Can control*, *Shell only* |
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
- **`Ctrl+Alt+Del` can't be sent.** Windows reserves it for the real
  keyboard.
- Your own mouse pointer stands in for the machine's. People only
  watching see no pointer.

If your connection drops, the dashboard reconnects on its own and the
view picks up where it was.

## Sound

What the machine plays comes with the picture, from its default output
device, on the lock screen and the sign-in screen too. **Sound on / Sound
off** above the screen mutes it on your side, and is remembered in this
browser. If it says **Click for sound**, your browser is holding the sound
back until you click the page. A quiet machine sends no sound at all.

Sound needs a browser that can decode it (Chrome, Edge, Firefox on a
computer, recent Safari). Where it can't, the button doesn't show, and the
picture plays as before. The machine's owner can turn sound off in the
[config file](/docs/machine-config#audio).

## Signing in remotely

When nobody is signed in, after a restart, a crash or a sign-out, the
screen shows the Windows sign-in screen. Click it and type the password
as you would at the PC. When the session opens, the view follows it.

This works unless the PC asks for `Ctrl+Alt+Del` before signing in,
because the dashboard can't send it. Turning that requirement off is a
trade-off you have to choose yourself. The requirement protects against
fake sign-in screens from someone at the PC. To turn it off, open
`secpol.msc` > Local Policies > Security Options and enable
**Interactive logon: Do not require CTRL+ALT+DEL**.

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

- **Paste my clipboard to the machine** sends text from your computer to
  the machine's clipboard (needs control). Then press `Ctrl+V` on the
  machine. If your browser won't hand over your clipboard, a box appears
  to paste the text into.
- **Copy the machine's clipboard to mine** reads it onto your computer.

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

## Who's watching

As the owner, you see live who is watching each of your machines.
