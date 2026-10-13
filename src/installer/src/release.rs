//! Where an install or update gets its files: the release feed (the
//! default), or a folder holding a downloaded release for an offline
//! install. Either way the manifest's signature is checked against the
//! trusted key and every file against the manifest, so a folder someone
//! handed you is held to the same standard as the feed.

use std::path::{Path, PathBuf};

use hawk_update::{Channel, Feed, Manifest};

use crate::report::Report;

/// What the person (or the component's config) said about where to look.
#[derive(Debug, Clone, Default)]
pub struct Source {
    /// A folder with `hawk-<channel>.json`, its `.minisig` and the artifacts.
    pub from: Option<PathBuf>,
    pub feed_url: String,
    pub public_key: String,
    pub channel: Channel,
}

/// What the command line says about the source, on top of what the
/// component's own config says.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub from: Option<PathBuf>,
    pub feed_url: String,
    pub public_key: String,
    pub channel: Option<Channel>,
}

impl Overrides {
    /// The source, from these choices over the config's (empty means unset).
    pub fn over(&self, feed_url: &str, public_key: &str, channel: Channel) -> Source {
        let pick = |first: &str, second: &str| if first.is_empty() { second.to_owned() } else { first.to_owned() };
        Source {
            from: self.from.clone(),
            feed_url: pick(&self.feed_url, feed_url),
            public_key: pick(&self.public_key, public_key),
            channel: self.channel.unwrap_or(channel),
        }
    }
}

/// A release, checked, and the means to fetch its files.
pub struct Release {
    pub manifest: Manifest,
    from: Option<PathBuf>,
}

impl Source {
    pub fn feed(&self) -> Result<Feed, String> {
        Feed::configured(&self.feed_url, &self.public_key, self.channel).map_err(|error| error.to_string())
    }

    pub fn resolve(&self, report: &Report) -> Result<Release, String> {
        let feed = self.feed().or_else(|error| match &self.from {
            // A folder still needs a key to check it against, but not a URL.
            Some(_) if !self.public_key.is_empty() || hawk_update::DEFAULT_PUBLIC_KEY.is_some() => Ok(Feed {
                url: String::new(),
                public_key: if self.public_key.is_empty() {
                    hawk_update::DEFAULT_PUBLIC_KEY.unwrap_or_default().to_owned()
                } else {
                    self.public_key.clone()
                },
                channel: self.channel,
            }),
            _ => Err(error),
        })?;
        let manifest = match &self.from {
            Some(folder) => {
                let name = format!("hawk-{}.json", self.channel.as_str());
                report.detail(format!("Reading the release in {}", folder.display()));
                let body = std::fs::read(folder.join(&name)).map_err(|error| format!("{name}: {error}"))?;
                let signature = std::fs::read_to_string(folder.join(format!("{name}.minisig")))
                    .map_err(|error| format!("{name}.minisig: {error}"))?;
                feed.verify(&body, &signature).map_err(|error| error.to_string())?
            }
            None => {
                report.detail(format!("Checking {}", feed.manifest_url()));
                feed.fetch().map_err(|error| error.to_string())?
            }
        };
        report.detail(format!("Release {} ({}), signature verified", manifest.version, manifest.channel.as_str()));
        Ok(Release { manifest, from: self.from.clone() })
    }
}

impl Release {
    /// Fetches artifact `name` into `directory`, checked against the manifest.
    pub fn fetch(&self, name: &str, directory: &Path, report: &Report) -> Result<PathBuf, String> {
        let artifact = self.manifest.artifact(name).map_err(|error| error.to_string())?;
        let file_name = artifact.url.rsplit('/').next().filter(|file| !file.is_empty()).unwrap_or(name).to_owned();
        let saved = match &self.from {
            Some(folder) => hawk_update::copy_local(artifact, &folder.join(&file_name), directory, &file_name),
            None => {
                report.detail(format!("Downloading {file_name} ({})", human_size(artifact.size)));
                hawk_update::download(artifact, directory, &file_name)
            }
        };
        saved.map_err(|error| error.to_string())
    }
}

pub fn human_size(bytes: u64) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    if bytes as f64 >= MIB { format!("{:.1} MiB", bytes as f64 / MIB) } else { format!("{} KiB", bytes.div_ceil(1024)) }
}

/// A scratch folder for one run, removed when dropped.
pub struct Staging(pub PathBuf);

impl Staging {
    pub fn new() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!("hawk-setup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        Ok(Self(path))
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use sha2::Digest;

    /// A release folder as make-manifest.py and release-sign.py leave it:
    /// accepted with the right key, refused with another, and its files
    /// checked against the manifest.
    #[test]
    fn installs_from_a_signed_folder() {
        let keys = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let folder = std::env::temp_dir().join(format!("hawk-setup-release-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&folder);
        std::fs::create_dir_all(&folder).unwrap();

        let payload = b"pretend zip".to_vec();
        std::fs::write(folder.join("hawk-machine-1.2.0-windows-x64.zip"), &payload).unwrap();
        let digest: String =
            sha2::Sha256::digest(&payload).iter().map(|byte| format!("{byte:02x}")).collect();
        let manifest = serde_json::json!({
            "version": "1.2.0",
            "channel": "stable",
            "protocol": 1,
            "released_at": "2026-10-13T00:00:00Z",
            "notes_url": "https://github.com/o/r/releases/tag/v1.2.0",
            "artifacts": {
                "machine-windows-x64": {
                    "url": "https://github.com/o/r/releases/download/v1.2.0/hawk-machine-1.2.0-windows-x64.zip",
                    "sha256": digest,
                    "size": payload.len(),
                }
            }
        });
        let body = serde_json::to_vec_pretty(&manifest).unwrap();
        std::fs::write(folder.join("hawk-stable.json"), &body).unwrap();
        let signature = minisign::sign(Some(&keys.pk), &keys.sk, Cursor::new(&body), Some("hawk 1.2.0 stable"), None)
            .unwrap()
            .to_string();
        std::fs::write(folder.join("hawk-stable.json.minisig"), signature).unwrap();

        let report = Report::terminal(true);
        let source = Source {
            from: Some(folder.clone()),
            feed_url: String::new(),
            public_key: keys.pk.to_base64(),
            channel: Channel::Stable,
        };
        let release = source.resolve(&report).unwrap();
        assert_eq!(release.manifest.version, "1.2.0");
        let out = folder.join("out");
        let fetched = release.fetch("machine-windows-x64", &out, &report).unwrap();
        assert_eq!(std::fs::read(fetched).unwrap(), payload);

        let stranger = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let wrong = Source { public_key: stranger.pk.to_base64(), ..source.clone() };
        assert!(wrong.resolve(&report).is_err());

        std::fs::write(folder.join("hawk-machine-1.2.0-windows-x64.zip"), b"swapped zip").unwrap();
        assert!(release.fetch("machine-windows-x64", &folder.join("out2"), &report).is_err());
        let _ = std::fs::remove_dir_all(&folder);
    }
}
