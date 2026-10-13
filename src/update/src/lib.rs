//! Finds, verifies and downloads Hawk releases.
//!
//! A release feed is a JSON manifest per channel (`hawk-stable.json`,
//! `hawk-beta.json`) with a minisign signature beside it (`.minisig`). The
//! manifest lists every artifact of the release with its SHA-256 and size,
//! so the one signature covers them all: an artifact is only ever accepted
//! when its hash matches a manifest whose signature checked out against the
//! public key this build trusts (or the one the machine's own config names).
//!
//! The feed URL and the key are baked in at build time from
//! `HAWK_UPDATE_URL` and `HAWK_UPDATE_PUBKEY`, which the release workflow
//! sets from the repository it runs in: a fork's builds follow the fork's
//! feed and trust the fork's key, with nothing to edit. Both can be
//! overridden at run time from the component's config.
//!
//! Nothing here moves backwards: a manifest whose version isn't newer than
//! what's installed is "no update", so an old, validly signed manifest
//! replayed by whoever sits between us and the feed can't downgrade a
//! machine.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use minisign_verify::{PublicKey, Signature};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The feed this build follows, unless configured otherwise. `{channel}` is
/// replaced by the channel's name.
pub const DEFAULT_FEED_URL: Option<&str> = option_env!("HAWK_UPDATE_URL");
/// The minisign public key (base64) this build trusts, unless configured
/// otherwise.
pub const DEFAULT_PUBLIC_KEY: Option<&str> = option_env!("HAWK_UPDATE_PUBKEY");

/// The largest manifest or signature read.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
/// The largest artifact downloaded, whatever a manifest says.
const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug)]
pub enum Error {
    /// No feed URL or key: a development build, or a config that cleared them.
    NotConfigured(&'static str),
    Network(String),
    /// The signature is missing, malformed or doesn't match the key.
    BadSignature(String),
    BadManifest(String),
    /// A download doesn't match the manifest.
    BadArtifact(String),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured(what) => write!(f, "updates aren't set up in this build: no {what}"),
            Self::Network(detail) => write!(f, "couldn't reach the release feed: {detail}"),
            Self::BadSignature(detail) => write!(f, "the release feed's signature doesn't check out: {detail}"),
            Self::BadManifest(detail) => write!(f, "the release feed is malformed: {detail}"),
            Self::BadArtifact(detail) => write!(f, "the download doesn't match the release: {detail}"),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    #[default]
    Stable,
    Beta,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name.trim() {
            "" | "stable" => Some(Self::Stable),
            "beta" => Some(Self::Beta),
            _ => None,
        }
    }
}

/// One file of a release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub url: String,
    /// Lowercase hex.
    pub sha256: String,
    pub size: u64,
}

/// What a feed announces: the newest release on a channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub channel: Channel,
    /// The dashboard/machine protocol this release speaks.
    pub protocol: u32,
    /// RFC 3339.
    pub released_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes_url: Option<String>,
    /// By name: `machine-windows-x64`, `relay-linux-x64`, `setup-windows-x64`…
    pub artifacts: BTreeMap<String, Artifact>,
}

impl Manifest {
    pub fn version(&self) -> Result<Version, Error> {
        Version::parse(&self.version).map_err(|error| Error::BadManifest(format!("version {}: {error}", self.version)))
    }

    /// Whether this release is newer than `current`.
    pub fn is_newer_than(&self, current: &str) -> Result<bool, Error> {
        let current =
            Version::parse(current).map_err(|error| Error::BadManifest(format!("installed version {current}: {error}")))?;
        Ok(self.version()? > current)
    }

    pub fn artifact(&self, name: &str) -> Result<&Artifact, Error> {
        self.artifacts
            .get(name)
            .ok_or_else(|| Error::BadManifest(format!("release {} has no {name}", self.version)))
    }
}

/// Where to look and whom to believe.
#[derive(Debug, Clone)]
pub struct Feed {
    /// With `{channel}` in it, or a plain URL to one manifest.
    pub url: String,
    /// minisign public key, base64 (the second line of a `.pub` file).
    pub public_key: String,
    pub channel: Channel,
}

impl Feed {
    /// The build's defaults, with whatever the config sets on top. Empty
    /// strings mean "the default".
    pub fn configured(url: &str, public_key: &str, channel: Channel) -> Result<Self, Error> {
        let url = if url.trim().is_empty() { DEFAULT_FEED_URL.unwrap_or("") } else { url.trim() };
        let public_key = if public_key.trim().is_empty() { DEFAULT_PUBLIC_KEY.unwrap_or("") } else { public_key.trim() };
        if url.is_empty() {
            return Err(Error::NotConfigured("release feed URL"));
        }
        if public_key.is_empty() {
            return Err(Error::NotConfigured("release signing key"));
        }
        Ok(Self { url: url.to_owned(), public_key: public_key.to_owned(), channel })
    }

    pub fn manifest_url(&self) -> String {
        self.url.replace("{channel}", self.channel.as_str())
    }

    /// Downloads the channel's manifest and its signature, and returns the
    /// manifest once the signature checks out.
    pub fn fetch(&self) -> Result<Manifest, Error> {
        let url = self.manifest_url();
        let body = get_bytes(&url, MAX_MANIFEST_BYTES)?;
        let signature = get_bytes(&format!("{url}.minisig"), MAX_MANIFEST_BYTES)?;
        let signature =
            String::from_utf8(signature).map_err(|_| Error::BadSignature("the signature isn't text".into()))?;
        self.verify(&body, &signature)
    }

    /// Checks `body` against `signature` (a `.minisig` file's text) and
    /// parses it. The manifest must be for this feed's channel, so a beta
    /// manifest can't be passed off as a stable one.
    pub fn verify(&self, body: &[u8], signature: &str) -> Result<Manifest, Error> {
        verify_signature(&self.public_key, body, signature)?;
        let manifest: Manifest =
            serde_json::from_slice(body).map_err(|error| Error::BadManifest(error.to_string()))?;
        if manifest.channel != self.channel {
            return Err(Error::BadManifest(format!(
                "asked for the {} channel, got {}",
                self.channel.as_str(),
                manifest.channel.as_str()
            )));
        }
        manifest.version()?;
        Ok(manifest)
    }
}

/// Checks a minisign signature over `data`.
pub fn verify_signature(public_key: &str, data: &[u8], signature: &str) -> Result<(), Error> {
    let key = PublicKey::from_base64(public_key.trim())
        .map_err(|error| Error::BadSignature(format!("the configured key is invalid: {error}")))?;
    let signature = Signature::decode(signature).map_err(|error| Error::BadSignature(error.to_string()))?;
    key.verify(data, &signature, false).map_err(|error| Error::BadSignature(error.to_string()))
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30 * 60)))
        .timeout_connect(Some(Duration::from_secs(20)))
        .user_agent(concat!("hawk-update/", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .build()
        .into()
}

fn get_bytes(url: &str, limit: u64) -> Result<Vec<u8>, Error> {
    let mut response = agent().get(url).call().map_err(|error| Error::Network(format!("{url}: {error}")))?;
    response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|error| Error::Network(format!("{url}: {error}")))
}

/// Downloads `artifact` into `directory` as `name`, checking its size and
/// hash on the way. The file only appears under its name once it matches;
/// a failed download leaves nothing behind.
pub fn download(artifact: &Artifact, directory: &Path, name: &str) -> Result<PathBuf, Error> {
    if artifact.size > MAX_ARTIFACT_BYTES {
        return Err(Error::BadArtifact(format!("{name} is {} bytes, more than allowed", artifact.size)));
    }
    let mut response =
        agent().get(&artifact.url).call().map_err(|error| Error::Network(format!("{}: {error}", artifact.url)))?;
    let reader = response.body_mut().with_config().limit(artifact.size + 1).reader();
    save_checked(reader, artifact, directory, name)
}

/// Copies `artifact` from a local release folder (an offline install)
/// into `directory`, checked the same way as a download.
pub fn copy_local(artifact: &Artifact, source: &Path, directory: &Path, name: &str) -> Result<PathBuf, Error> {
    save_checked(File::open(source)?, artifact, directory, name)
}

fn save_checked(mut reader: impl Read, artifact: &Artifact, directory: &Path, name: &str) -> Result<PathBuf, Error> {
    fs::create_dir_all(directory)?;
    let target = directory.join(name);
    let partial = directory.join(format!("{name}.partial"));
    let result = (|| {
        let mut file = File::create(&partial)?;
        let mut hasher = Sha256::new();
        let mut written: u64 = 0;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer).map_err(|error| Error::Network(error.to_string()))?;
            if read == 0 {
                break;
            }
            written += read as u64;
            if written > artifact.size {
                return Err(Error::BadArtifact(format!("{name} is larger than the release says")));
            }
            hasher.update(&buffer[..read]);
            file.write_all(&buffer[..read])?;
        }
        file.sync_all()?;
        if written != artifact.size {
            return Err(Error::BadArtifact(format!("{name} is {written} bytes, the release says {}", artifact.size)));
        }
        let digest = hex(&hasher.finalize());
        if !digest.eq_ignore_ascii_case(&artifact.sha256) {
            return Err(Error::BadArtifact(format!("{name} has the wrong SHA-256")));
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&partial);
        return Err(error);
    }
    fs::rename(&partial, &target)?;
    Ok(target)
}

/// SHA-256 of a file, lowercase hex.
pub fn sha256_file(path: &Path) -> Result<String, Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The artifact name for a component on the platform this was built for,
/// e.g. `machine-windows-x64`.
pub fn artifact_name(component: &str) -> String {
    let os = if cfg!(windows) { "windows" } else if cfg!(target_os = "macos") { "macos" } else { "linux" };
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "x64" };
    format!("{component}-{os}-{arch}")
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    struct Signer {
        keys: minisign::KeyPair,
    }

    impl Signer {
        fn new() -> Self {
            Self { keys: minisign::KeyPair::generate_unencrypted_keypair().unwrap() }
        }

        fn public_key(&self) -> String {
            self.keys.pk.to_base64()
        }

        fn sign(&self, data: &[u8]) -> String {
            minisign::sign(Some(&self.keys.pk), &self.keys.sk, Cursor::new(data), Some("hawk test"), None)
                .unwrap()
                .to_string()
        }
    }

    fn manifest(version: &str, channel: Channel, artifact: &[u8]) -> Manifest {
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "machine-windows-x64".to_owned(),
            Artifact {
                url: "https://example.com/machine.zip".into(),
                sha256: hex(&Sha256::digest(artifact)),
                size: artifact.len() as u64,
            },
        );
        Manifest {
            version: version.into(),
            channel,
            protocol: 1,
            released_at: "2026-10-13T00:00:00Z".into(),
            notes_url: None,
            artifacts,
        }
    }

    fn feed(signer: &Signer, channel: Channel) -> Feed {
        Feed { url: "https://example.com/hawk-{channel}.json".into(), public_key: signer.public_key(), channel }
    }

    #[test]
    fn accepts_a_signed_manifest() {
        let signer = Signer::new();
        let body = serde_json::to_vec(&manifest("1.2.0", Channel::Stable, b"zip")).unwrap();
        let parsed = feed(&signer, Channel::Stable).verify(&body, &signer.sign(&body)).unwrap();
        assert_eq!(parsed.version, "1.2.0");
        assert!(parsed.is_newer_than("1.1.9").unwrap());
        assert!(!parsed.is_newer_than("1.2.0").unwrap());
        assert!(!parsed.is_newer_than("1.3.0").unwrap(), "never a downgrade");
        assert!(parsed.is_newer_than("1.2.0-rc.1").unwrap());
    }

    #[test]
    fn rejects_a_tampered_manifest() {
        let signer = Signer::new();
        let body = serde_json::to_vec(&manifest("1.2.0", Channel::Stable, b"zip")).unwrap();
        let signature = signer.sign(&body);
        let tampered = serde_json::to_vec(&manifest("9.9.9", Channel::Stable, b"evil")).unwrap();
        assert!(matches!(feed(&signer, Channel::Stable).verify(&tampered, &signature), Err(Error::BadSignature(_))));
    }

    #[test]
    fn rejects_another_key() {
        let signer = Signer::new();
        let other = Signer::new();
        let body = serde_json::to_vec(&manifest("1.2.0", Channel::Stable, b"zip")).unwrap();
        assert!(matches!(feed(&other, Channel::Stable).verify(&body, &signer.sign(&body)), Err(Error::BadSignature(_))));
    }

    #[test]
    fn rejects_the_wrong_channel() {
        let signer = Signer::new();
        let body = serde_json::to_vec(&manifest("1.2.0-rc.1", Channel::Beta, b"zip")).unwrap();
        assert!(matches!(feed(&signer, Channel::Stable).verify(&body, &signer.sign(&body)), Err(Error::BadManifest(_))));
    }

    #[test]
    fn checks_artifacts() {
        let directory = std::env::temp_dir().join(format!("hawk-update-test-{}", std::process::id()));
        let good = manifest("1.2.0", Channel::Stable, b"the real zip");
        let artifact = good.artifact("machine-windows-x64").unwrap();

        let saved = save_checked(Cursor::new(b"the real zip".to_vec()), artifact, &directory, "ok.zip").unwrap();
        assert_eq!(fs::read(&saved).unwrap(), b"the real zip");

        let wrong = save_checked(Cursor::new(b"the fake zip".to_vec()), artifact, &directory, "bad.zip");
        assert!(matches!(wrong, Err(Error::BadArtifact(_))));
        assert!(!directory.join("bad.zip").exists() && !directory.join("bad.zip.partial").exists());

        let longer = save_checked(Cursor::new(b"the real zip, and more".to_vec()), artifact, &directory, "long.zip");
        assert!(matches!(longer, Err(Error::BadArtifact(_))));
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn feed_urls() {
        let feed = Feed {
            url: "https://github.com/o/r/releases/download/feed/hawk-{channel}.json".into(),
            public_key: String::new(),
            channel: Channel::Beta,
        };
        assert_eq!(feed.manifest_url(), "https://github.com/o/r/releases/download/feed/hawk-beta.json");
        assert_eq!(Channel::parse(""), Some(Channel::Stable));
        assert_eq!(Channel::parse("nightly"), None);
    }
}
