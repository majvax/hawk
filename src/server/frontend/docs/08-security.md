# Security model

Hawk is built so that the relay you run is a messenger, not a party you
have to trust with your screen.

## What the relay can't do

- **Read your screen, input, clipboard, files or shells.** They're
  encrypted between your browser and the machine with AES-256-GCM, under
  keys only the two of them hold. The keys change when a viewer leaves.
- **Learn your password.** Your browser derives what it sends from it.
  The relay stores a hash of that, and your identity key encrypted.
- **Give anyone access to your machine.** The machine checks your signed
  shares itself, so a relay that tried to add a viewer would be refused.
- **Pose as your machine.** The machine's key lives in its TPM, where it
  can't be copied off. Your browser verifies it when you enroll it, and
  viewers check every stream against your verification.

## What the relay can do

- **See who watches what, and when.** It routes the traffic, so it knows
  who's connected. It keeps that as the activity log: who signed in,
  watched, used a shell or files, from which address, and how many
  encrypted bytes went through, but never what they said.
- **Refuse service:** drop connections, or not pass messages on. It can
  delay a revocation, but not past the share's end time.
- **Serve a modified dashboard.** The dashboard you load comes from the
  relay. A compromised relay could send one that leaks your keys. That's
  the main limit of a web app, and why the planned native app and
  separately hosted dashboard matter.

## The machine side

- **The service runs as SYSTEM**, so it can capture the lock screen and
  UAC prompts. That's what makes them controllable remotely.
- **Shells and files run as the signed-in user**, never as SYSTEM.
- **It connects out only.** Nothing listens on the PC, so there's nothing
  to reach from outside.
- **It pins the relay's key**, so a rogue certificate authority or an
  intercepting proxy can't pose as your relay.
- **It only lets in viewers the owner signed a share for**, and only for
  what that share allows. It also enforces its own config file, whatever
  the dashboard shows.

## Protecting your account

The relay is the one gate in front of your machines. Use a long password,
[turn on two-factor](/docs/accounts#two-factor-authentication) and keep
your recovery codes safe. Check **Settings → Sessions** now and then for
browsers you don't recognize.

Prefer a **passkey** to an authenticator app where you can. A code can be
typed into a look-alike page and passed on within its 30 seconds; a
passkey can't be: the browser binds it to this server's domain and signs
the page's address into every answer, so a passkey used on a phishing page
gives that page nothing it can use here. The relay keeps only its public
key, so a copy of the database doesn't give it away either. It checks the
key's signature counter too: a counter that goes backwards means a copied
key, and is refused (passkeys synced between devices don't count, and
aren't affected).
