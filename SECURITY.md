# Security

Hawk gives remote control of a computer, so a flaw in it can be serious.
Please report one privately, not in a public issue: use **Report a
vulnerability** under the repository's *Security* tab. Say what's affected
and how to reproduce it; a fix and an advisory follow, and credit if you
want it.

## What is supported

Only the newest release gets fixes. Installs update themselves from the
signed release feed unless their update policy is `off`.

## How releases are trusted

Every install trusts one minisign key, baked in at build time. Releases
are built by CI from a tag but signed offline, so the key that ships code
to every install never sits in CI. An install only ever moves forward,
and only to files whose SHA-256 is in a manifest that key signed. The
design is described in `src/update/src/lib.rs` and the main README.
