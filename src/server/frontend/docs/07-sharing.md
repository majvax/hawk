# Sharing

Every machine has exactly one owner. The owner can share it with other
accounts on the same relay from the machine's **Sharing** tab. The other
person needs an account (the admin invites them) and must have signed in
at least once.

## Access levels

| | Screen | Mouse, keyboard, paste | Files | Shell |
|---|---|---|---|---|
| **View only** | ✓ | | | |
| **Can control** | ✓ | ✓ | ✓ | |
| **Shell only** | | | ✓ | ✓ |
| Owner | ✓ | ✓ | ✓ | ✓ |

Files and shells also have to be allowed by the machine's
[config file](/docs/machine-config). **Shell only** gets no video at all,
which makes it usable over a slow connection.

**Analytics** is a checkbox on its own, with any access level: it lets
them see the machine's [health and processes](/docs/analytics). You can
turn it on or off for an existing share from the list. Like the access
level, it's part of what your browser signs, and the machine checks it
itself.

## Temporary shares

These combine freely:

- **For how long:** from 30 minutes to a week, or until a date and time.
  When it runs out, the share ends and a live viewer is cut off. **+1 h**
  extends it.
- **Scheduled:** the share starts at a chosen time, e.g. tomorrow 9:00 for
  2 hours.
- **One viewing:** the share is used up when the person stops watching,
  or leaves for more than a minute.

Sharing again with the same person replaces the old terms. Changing or
ending a share applies at once, even to someone watching right now.

## Checking who you share with

Your browser signs every share with your identity key, and the machine
checks that signature itself. So the relay alone can't add anyone to
your machine.

The first time you share with someone, your browser remembers their key
and shows its **fingerprint**. Compare it with the one in their
**Settings** (over the phone, say) to be sure it's them. If their key ever
changes, your browser refuses to share until you confirm the new one with
them. That happens if they lose their account and the admin makes a new
one, but it could also mean someone is in between.

The other way round works the same: the first time someone shares a
machine with you, your browser remembers the owner's key, and warns you
if it changes.
