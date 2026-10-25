# Accounts and sign-in

Accounts are by invitation only. There's no open sign-up page.

## The first account

On its first start, with no accounts yet, the relay logs a one-time link:

```
no accounts yet. Create the admin account at: https://relay.example.com/invite/...
```

Open it to create the **admin** account. Only someone who can read the
relay's output can do this. Restarting the relay before the link is used
replaces it with a new one.

## Inviting people

The admin makes invite links in the **Admin** tab. Each works once and
expires after 7 days, and unused ones can be revoked. Send the link to the
person; they choose their own email and password.

Being admin doesn't give access to anyone else's machines. Admins manage
accounts, nothing more.

## Passwords

At least 10 characters. **Your password never leaves your browser.** The
browser derives two keys from it: one that signs you in, and one that
unlocks your **identity key**, which your screen sessions are encrypted
with. The relay stores your identity key only in encrypted form.

That means the admin can't reset your password for you. Change it in
**Settings** while you still know it; that also signs out your other
sessions.

## Two-factor authentication

Strongly recommended. With it, a stolen password isn't enough to reach
your machines. Two kinds of second factor work, and you can have both:

- **A passkey**: a security key (YubiKey, Titan), Windows Hello, Touch ID,
  or your phone. Nothing to type, and it can't be phished: it only answers
  this server's own pages.
- **An authenticator app**: a 6-digit code from Google Authenticator,
  Aegis, 1Password, ...

### Turning it on

1. **Settings → Two-factor authentication → Add a passkey** (or **Set up
   an authenticator app**).
2. For a passkey: name it, enter your password, and follow your browser's
   prompt: it asks where to keep it. For an app: scan the QR code (or type
   the key in) and enter the 6-digit code it shows, and your password.
3. **Save the 10 recovery codes** it gives you (*Copy* or *Download*).
   They're shown only once. Each signs you in once if you lose your
   passkey or your phone.

You can have up to 8 second factors, passkeys and apps together, and any
of them works. Adding or removing one signs out your other sessions, and
needs your password (the first) or a fresh second factor (later ones).

**Passkeys don't work in the desktop app**, and on a dashboard hosted
away from the server's domain (see
[Running the relay](/docs/relay#passkeys)): there, sign in with a code. If
you use the app, keep an authenticator app as well, or your recovery
codes at hand. Passkeys are also tied to the server's domain: if the
admin changes it (or turns passkeys off), yours stop working, and an
account with only passkeys signs in with a recovery code.

### Signing in

After your password, use your passkey (offered first when you have one),
or enter the current code from your app, or one of your recovery codes in
the same box. Each recovery code works once; make a new set in Settings
(**New recovery codes**) when you run low. A passkey is a second factor
here, not a replacement for the password.

### Confirming sensitive actions

Some actions ask for your passkey or a fresh code if you haven't used one
in the last 5 minutes:

- adding, renaming, verifying or removing a machine
- sharing a machine, or changing or ending a share
- changing your password, adding or removing a passkey or an
  authenticator, new recovery codes
- any change in the Admin tab
- **taking control** of a machine, **transferring files**, and **opening a
  shell**: the screen shows **Confirm to control** (or **Confirm**) until
  you do

Watching a screen and reading its clipboard don't ask.

### Lost your phone (or passkey) and your recovery codes?

The admin can **Reset two-factor** for your account in the Admin tab. It
removes every passkey, authenticator and recovery code, and signs you
out. Then sign in with your password and set it up again.

The admin can't reset their own. Keep your recovery codes somewhere safe.

### Requiring it for everyone

In the Admin tab, **Require two-factor** sends everyone who doesn't have it
to set it up (a passkey or an authenticator app) as soon as they sign in.
They can't do anything else until they have. The admin needs it first
before turning this on.

## Email confirmation

If the relay has a mail server (see
[Running the relay](/docs/relay#email)), new accounts get a link to
confirm their address. It works for 24 hours, in any browser.

Until the address is confirmed, the account can sign in, but **can't add
machines, and no one can share a machine with it**. The dashboard shows a
banner with **Send the link again**, usable once a minute.

The relay also emails you when your sign-in settings change: a passkey or
an authenticator added or removed, new recovery codes, a sign-in with a
recovery code, a password change, or a reset by the admin. If you didn't
make the change, change your password and check your sessions.

## Sessions

A sign-in lasts 30 days in that browser. **Settings → Sessions** lists
every browser you're signed into, with the IP address each signed in from.
You can end any one, or all but this one.

Signing in on a new browser asks for your password again. That's what
unlocks your identity key in that browser.

## Activity

The relay keeps a log of who did what, and from which address:

- **Settings → Activity**: your sign-ins (and failed ones, with the
  address they came from), changes to your password and second factors,
  what you did on any machine, and everything anyone did on the machines
  you own.
- **A machine's Activity tab**: for its owner, every view of it and what
  was done in it. Someone it's shared with sees only their own.
- **Admin → Activity**: everything, for the admin, including failed
  sign-ins for addresses that have no account.

What's recorded: sign-ins and failures, wrong second-factor codes and
passkey answers, step-ups (and whether with a passkey, a code or a recovery
code), password and two-factor changes (which kind of factor), invites, accounts disabled,
machines enrolled, renamed and removed, shares granted and revoked; each
view's start, end and length, when it took control, and the first time it
used a shell, files or pasted a picture, with how much shell and file
traffic went each way; power actions, Ctrl+Alt+Del, config changes and
update installs. Not what any of it carried: the relay can't read it.
Never a password, a code or a key.

Events are kept 90 days unless the relay's operator sets otherwise. The
address is the one the relay sees: behind a reverse proxy, the proxy's.
It's shown to whoever it was, the owner of the machine it was on, and the
admin; not to the account something was done to (a shared user doesn't see
the owner's address on the share).

## Disabling an account

The admin can disable an account in the Admin tab. It's signed out at
once, and the machines it owns are disconnected until it's enabled again.

Failed sign-ins are limited to 10 per 15 minutes from one address.
