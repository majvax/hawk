# Updates

Every part of Hawk updates from the same place: a **release feed** of
signed manifests, one per channel, that lists each file of the newest
release with its SHA-256. A file is only ever installed when its hash
matches a manifest whose signature checks out against the key the install
trusts. Nothing ever moves backwards: an old release, even a validly
signed one, is never installed over a newer one.

## What updates how

| Part | How | Where to set it |
|---|---|---|
| Machine service | `hawk-setup` (installed beside the service) checks once a day, and installs when the policy says so or when you press **Update** in the dashboard. If the new service doesn't come back up, it rolls back. | `[[update]]` in `C:\ProgramData\HawkService\config.toml` |
| Relay and dashboard | A daily systemd timer runs `hawk-setup update relay`. The database is backed up before each update, and the previous version and database come back if the new relay doesn't answer `/healthz`. | `/etc/hawk/update.toml` |
| Desktop app | The app checks when it starts. | The app's **Settings → App updates** |

## Policies

- **`notify`** (the default): look, and say so. A machine shows **Update
  to …** in its owner's dashboard; the relay writes it to its log
  (`journalctl -u hawk-update`); the app shows a banner. Nothing installs
  until someone says so.
- **`auto`**: look, and install. The app installs at start, before
  anything is open, so it never restarts in the middle of a session.
- **`off`**: never look.

On a machine:

```toml
[[update]]
policy = "notify"   # off | notify | auto
channel = "stable"  # stable | beta
check_hours = 24
```

On the relay, `/etc/hawk/update.toml`:

```toml
[update]
policy = "notify"
channel = "stable"
```

Or by hand, any time: `hawk-setup update machine` on a PC, `hawk-setup
update relay` on the server, and `--check` to only look.

## Channels

**stable** gets releases like `1.2.0`. **beta** also gets release
candidates like `1.3.0-rc.1`, and every stable release too.

## Forks and your own builds

Each build looks at the feed of the repository it was built from, and
trusts the key that repository's releases are signed with. A fork's
release workflow builds installs that follow the fork, with nothing to
change but its own signing key.

To point an existing install at another feed, set `manifest_url` and
`public_key` next to `policy`. For the app, set **Release feed** and
**Release key** in its settings. `manifest_url` is a URL with `{channel}`
in it, e.g.
`https://github.com/you/hawk/releases/download/feed/hawk-{channel}.json`,
and `public_key` is a minisign public key.

## Versions that don't match

The dashboard, the relay and the machines speak a versioned protocol. When
the relay is older or newer than the dashboard, the dashboard says so at
the top of the page, and which one to update.
