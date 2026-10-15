# Troubleshooting

The two logs worth checking first:

- **The relay's output**, wherever you run it.
- **The machine's log**, `C:\ProgramData\HawkService\hawk-service.log`.

## A machine never shows up, or stays offline

Look at the end of the machine's log.

- **Is the service running?** `Get-Service HawkService` in PowerShell.
  Start it with `Start-Service HawkService`.
- **Is it pointed at your relay?** The log says `relay: connected to ...`
  or which address failed; `hawk-setup status` shows the address too.
  Change it with `hawk-setup install machine --relay <address>`.
- **`refusing ...: server key <pin> is not pinned`:** the relay's TLS key
  isn't the one the machine was given. Either the relay's key changed (a
  new certificate made without reusing the key), or a proxy in between
  presents its own. Set the right pin:
  `hawk-setup install machine --pin <pin from the relay's log>`. The
  machine retries every 30 seconds.
- **Certificate errors:** a machine without a pin checks the relay's
  certificate against Windows' trusted roots, which a self-signed one
  isn't in. Give the machine the relay's pin.
- **The relay is listening on 127.0.0.1:** other computers can't reach
  it. Set `HOST=0.0.0.0` (or `bun run dev:relay:lan` in development), and
  allow the port in the firewall.
- **The relay has no TLS:** machines only connect over `wss://`. Give the
  relay a certificate.
- **Enrollment code expired or used:** codes last an hour and work once.
  Make a new one with **Add machine** and run the install command again.

## The machine says "Re-enroll needed"

It was enrolled before machines had their own keys. Remove it and enroll
it again with a new code.

## The machine shows "Unverified"

Its key hasn't been checked, so nobody can watch it. See
[Verify it](/docs/machine#4-verify-it-if-needed).

## The screen stays black or never starts

- **Nobody is signed in at the PC.** An up-to-date machine shows the
  sign-in screen (see [signing in remotely](/docs/using#signing-in-remotely)).
  An older one needs someone to sign in at the PC, or an update.
- Check that `hawk-capture.exe` sits beside `hawk-service.exe`, and look
  in the machine's log for why capture didn't start.

## "The machine refused this connection"

The machine checked your share and said no. The reason follows the
message. Usually the share ended or changed: ask the owner.

## Clipboard, Files or Terminal is missing or says it's off

Either your access level doesn't include it (see
[Sharing](/docs/sharing#access-levels)), or the machine's
[config file](/docs/machine-config) doesn't allow it. Remember to restart
the service after editing the config, and check the log for `config:`
lines if a change didn't take.

## "Confirm to control" or "needs a fresh code"

You have two-factor on, and taking control, files and shells need a code
from the last 5 minutes. Press the button and enter the code from your
app.

## Sign-in problems

- **Lost your authenticator and recovery codes:** ask the admin to
  **Reset two-factor** for your account.
- **Too many attempts:** sign-in is limited after 10 failures in 15
  minutes. Wait, then try again.
- **"this account is disabled":** ask the admin.
- **Forgot your password:** it can't be reset, not even by the admin,
  because it's what unlocks your identity key. The way back is a new
  account from a new invite, with your machines enrolled again under it.

## The verification email never arrives

- Check spam.
- The relay's log shows `mail: sending failed` with the reason if the
  mail server refused it.
- `PUBLIC_URL` must be set for the link to point to the right address.
- **Send the link again** works once a minute, 5 times an hour.

## Browser warns about the certificate

The relay uses a self-signed certificate. Import `certs/dev-cert.pem` into
this computer's trusted roots, or give the relay a certificate from a real
CA.
