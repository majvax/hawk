//! The relay on Linux: `hawk-relay` and the dashboard under /opt/hawk,
//! running as its own `hawk` user under systemd, with its database in
//! /var/lib/hawk and its settings and TLS key in /etc/hawk.
//!
//! The TLS key is what every enrolled machine pins, so it's kept across
//! everything this does: renewals reuse it, updates never touch it, and a
//! reinstall finds and keeps it.

use std::fs;
use std::os::unix::fs::{PermissionsExt, chown};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::probe::{self, RelayAddress};
use crate::release::{Overrides, Staging};
use crate::report::Report;

const INSTALL_DIR: &str = "/opt/hawk";
const DATA_DIR: &str = "/var/lib/hawk";
const CONFIG_DIR: &str = "/etc/hawk";
const USER: &str = "hawk";
const UNIT: &str = "hawk-relay.service";
const UPDATE_UNIT: &str = "hawk-update.service";
const UPDATE_TIMER: &str = "hawk-update.timer";

fn install_dir() -> PathBuf {
    PathBuf::from(INSTALL_DIR)
}
fn tls_dir() -> PathBuf {
    Path::new(CONFIG_DIR).join("tls")
}
fn env_path() -> PathBuf {
    Path::new(CONFIG_DIR).join("relay.env")
}
fn update_path() -> PathBuf {
    Path::new(CONFIG_DIR).join("update.toml")
}

fn artifact() -> String {
    hawk_update::artifact_name("relay")
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and can't fail.
    unsafe { libc::geteuid() == 0 }
}

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program).args(args).output().map_err(|error| format!("running {program}: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{program} {} failed: {}", args.join(" "), stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn systemctl(args: &[&str]) -> Result<String, String> {
    run("systemctl", args)
}

fn write_file(path: &Path, contents: &str, mode: u32) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let partial = path.with_extension("partial");
    fs::write(&partial, contents).map_err(|error| format!("{}: {error}", partial.display()))?;
    fs::set_permissions(&partial, fs::Permissions::from_mode(mode)).map_err(|error| error.to_string())?;
    fs::rename(&partial, path).map_err(|error| format!("{}: {error}", path.display()))
}

/// The hawk user's uid and gid.
fn hawk_ids() -> Result<(u32, u32), String> {
    let uid = run("id", &["-u", USER])?.trim().parse().map_err(|_| "unreadable uid".to_owned())?;
    let gid = run("id", &["-g", USER])?.trim().parse().map_err(|_| "unreadable gid".to_owned())?;
    Ok((uid, gid))
}

/// Readable by root and the hawk group only.
fn give_to_hawk_group(path: &Path, mode: u32) -> Result<(), String> {
    let (_, gid) = hawk_ids()?;
    chown(path, Some(0), Some(gid)).map_err(|error| format!("{}: {error}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| error.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Installed {
    version: String,
}

pub fn installed_version() -> Option<String> {
    let text = fs::read_to_string(install_dir().join("install.json")).ok()?;
    serde_json::from_str::<Installed>(&text).ok().map(|installed| installed.version)
}

fn save_installed(version: &str) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&Installed { version: version.to_owned() }).map_err(|e| e.to_string())?;
    write_file(&install_dir().join("install.json"), &json, 0o644)
}

// ---- settings -------------------------------------------------------------------

/// /etc/hawk/update.toml.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateFile {
    #[serde(default)]
    pub update: UpdateSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSettings {
    /// off, notify (log that one is out) or auto (install it).
    #[serde(default = "default_policy")]
    pub policy: String,
    #[serde(default)]
    pub channel: String,
    #[serde(default)]
    pub manifest_url: String,
    #[serde(default)]
    pub public_key: String,
}

fn default_policy() -> String {
    "notify".into()
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self { policy: default_policy(), channel: String::new(), manifest_url: String::new(), public_key: String::new() }
    }
}

fn read_update_settings() -> UpdateSettings {
    fs::read_to_string(update_path())
        .ok()
        .and_then(|text| toml::from_str::<UpdateFile>(&text).ok())
        .map(|file| file.update)
        .unwrap_or_default()
}

fn source(overrides: &Overrides, settings: &UpdateSettings) -> Result<crate::release::Source, String> {
    let channel = hawk_update::Channel::parse(&settings.channel)
        .ok_or_else(|| format!("{}: channel \"{}\" isn't stable or beta", update_path().display(), settings.channel))?;
    Ok(overrides.over(&settings.manifest_url, &settings.public_key, channel))
}

// ---- TLS ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tls {
    /// Made here; machines pin it, browsers warn until it's accepted.
    SelfSigned,
    /// Let's Encrypt through certbot, renewing with the same key.
    Certbot { email: String },
    /// Files the person already has.
    Existing { cert: PathBuf, key: PathBuf },
}

fn cert_path() -> PathBuf {
    tls_dir().join("cert.pem")
}
fn key_path() -> PathBuf {
    tls_dir().join("key.pem")
}

fn set_up_tls(tls: &Tls, host: &str, report: &Report) -> Result<(), String> {
    fs::create_dir_all(tls_dir()).map_err(|error| error.to_string())?;
    give_to_hawk_group(&tls_dir(), 0o750)?;
    match tls {
        Tls::SelfSigned => {
            // An existing key is kept, so machines that pinned it still connect.
            let key = match fs::read_to_string(key_path()) {
                Ok(pem) => {
                    report.detail("Keeping the existing TLS key (enrolled machines pin it)");
                    rcgen::KeyPair::from_pem(&pem).map_err(|error| format!("{}: {error}", key_path().display()))?
                }
                Err(_) => rcgen::KeyPair::generate().map_err(|error| error.to_string())?,
            };
            let mut params =
                rcgen::CertificateParams::new(vec![host.to_owned()]).map_err(|error| error.to_string())?;
            params.not_before = rcgen::date_time_ymd(2024, 1, 1);
            params.not_after = rcgen::date_time_ymd(2099, 12, 31);
            params.distinguished_name.push(rcgen::DnType::CommonName, host);
            let cert = params.self_signed(&key).map_err(|error| error.to_string())?;
            write_file(&cert_path(), &cert.pem(), 0o640)?;
            write_file(&key_path(), &key.serialize_pem(), 0o640)?;
            report.detail(format!("Self-signed certificate for {host}"));
        }
        Tls::Existing { cert, key } => {
            let cert_pem = fs::read_to_string(cert).map_err(|error| format!("{}: {error}", cert.display()))?;
            let key_pem = fs::read_to_string(key).map_err(|error| format!("{}: {error}", key.display()))?;
            write_file(&cert_path(), &cert_pem, 0o640)?;
            write_file(&key_path(), &key_pem, 0o640)?;
            report.detail(format!("Using the certificate from {}", cert.display()));
        }
        Tls::Certbot { email } => {
            if Command::new("certbot").arg("--version").output().is_err() {
                return Err("certbot isn't installed (apt install certbot, or dnf install certbot)".into());
            }
            // Let's Encrypt checks over port 80, now and at every renewal.
            open_firewall(80, report);
            report.detail(format!("Asking Let's Encrypt for a certificate for {host} (port 80 must be reachable)"));
            let hook = format!("{INSTALL_DIR}/hawk-setup relay-cert-deploy");
            run(
                "certbot",
                &[
                    "certonly", "--standalone", "--non-interactive", "--agree-tos", "--email", email.as_str(), "-d",
                    host,
                    // Machines pin the key, not the certificate: renewals keep it.
                    "--reuse-key", "--deploy-hook", hook.as_str(),
                ],
            )?;
            deploy_certbot(&Path::new("/etc/letsencrypt/live").join(host))?;
        }
    }
    give_to_hawk_group(&cert_path(), 0o640)?;
    give_to_hawk_group(&key_path(), 0o640)?;
    Ok(())
}

/// certbot's deploy hook: copies a renewed certificate where the relay
/// (which can't read /etc/letsencrypt) finds it, and restarts it.
pub fn deploy_certbot(lineage: &Path) -> Result<(), String> {
    let read = |name: &str| fs::read_to_string(lineage.join(name)).map_err(|error| format!("{name}: {error}"));
    write_file(&cert_path(), &read("fullchain.pem")?, 0o640)?;
    write_file(&key_path(), &read("privkey.pem")?, 0o640)?;
    give_to_hawk_group(&cert_path(), 0o640)?;
    give_to_hawk_group(&key_path(), 0o640)?;
    if systemctl(&["is-active", "--quiet", UNIT]).is_ok() {
        systemctl(&["restart", UNIT])?;
    }
    Ok(())
}

pub fn deploy_hook() -> Result<(), String> {
    let lineage = std::env::var_os("RENEWED_LINEAGE").ok_or("RENEWED_LINEAGE isn't set: certbot runs this")?;
    deploy_certbot(Path::new(&lineage))
}

fn current_pin() -> Result<String, String> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let cert = CertificateDer::pem_file_iter(cert_path())
        .map_err(|error| error.to_string())?
        .next()
        .ok_or("no certificate")?
        .map_err(|error| error.to_string())?;
    probe::spki_pin(&cert)
}

// ---- units -------------------------------------------------------------------------------

fn relay_unit() -> String {
    format!(
        r"[Unit]
Description=Hawk relay
Documentation=https://github.com/
After=network-online.target
Wants=network-online.target

[Service]
User={USER}
Group={USER}
EnvironmentFile={env}
ExecStart={INSTALL_DIR}/hawk-relay
Restart=on-failure
RestartSec=5
# Lets it listen on 443 without being root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
UMask=0077
ProtectSystem=strict
ReadWritePaths={DATA_DIR}
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
",
        env = env_path().display()
    )
}

fn update_units() -> (String, String) {
    let service = format!(
        r"[Unit]
Description=Hawk relay update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={INSTALL_DIR}/hawk-setup update relay --scheduled
# Its scratch folder away from the /tmp every user of the server shares.
PrivateTmp=true
"
    );
    let timer = r"[Unit]
Description=Look for Hawk relay updates daily

[Timer]
OnBootSec=15min
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
"
    .to_owned();
    (service, timer)
}

fn unit_path(name: &str) -> PathBuf {
    Path::new("/etc/systemd/system").join(name)
}

// ---- install --------------------------------------------------------------------------

pub struct InstallOptions {
    /// The address people and machines reach the relay at.
    pub public_url: String,
    /// What it listens on, when that isn't the public URL's port (behind a
    /// proxy or a port forward).
    pub listen_port: Option<u16>,
    pub tls: Tls,
    /// Other origins allowed to use the relay (the desktop app, a hosted
    /// dashboard).
    pub origins: Vec<String>,
    pub smtp_url: Option<String>,
    pub mail_from: Option<String>,
    pub policy: Option<String>,
    pub overrides: Overrides,
}

/// The desktop app's origins: on Windows, then macOS and Linux.
pub const APP_ORIGINS: [&str; 2] = ["http://tauri.localhost", "tauri://localhost"];

pub fn install(options: InstallOptions, report: &Report) -> Result<(), String> {
    report.step("Checking this server");
    if !is_root() {
        return Err("run hawk-setup as root (sudo)".into());
    }
    if systemctl(&["--version"]).is_err() {
        return Err("this server doesn't use systemd, which hawk-setup needs".into());
    }
    let address = RelayAddress::parse(&options.public_url)?;
    let listen_port = options.listen_port.unwrap_or(address.port);
    let public_url = if address.port == 443 {
        format!("https://{}", address.host)
    } else {
        format!("https://{}:{}", address.host, address.port)
    };
    if let Some(policy) = &options.policy
        && !matches!(policy.as_str(), "off" | "notify" | "auto")
    {
        return Err(format!("update policy \"{policy}\" isn't off, notify or auto"));
    }
    report.ok(format!("Relay at {public_url}, listening on port {listen_port}"));

    report.step("Getting the release");
    let mut settings = read_update_settings();
    if let Some(policy) = &options.policy {
        settings.policy.clone_from(policy);
    }
    let release = source(&options.overrides, &settings)?.resolve(report)?;
    let staging = Staging::new()?;
    let archive = release.fetch(&artifact(), &staging.0, report)?;
    let unpacked = staging.0.join("relay");
    crate::archive::extract(&archive, &unpacked)?;
    for needed in ["hawk-relay", "hawk-setup", "dashboard/index.html"] {
        if !unpacked.join(needed).exists() {
            return Err(format!("the release is missing {needed}"));
        }
    }

    report.step(format!("Installing Hawk relay {}", release.manifest.version));
    if run("id", &["-u", USER]).is_err() {
        report.detail(format!("Creating the {USER} system user"));
        run("useradd", &["--system", "--user-group", "--home-dir", DATA_DIR, "--shell", "/usr/sbin/nologin", USER])?;
    }
    fs::create_dir_all(DATA_DIR).map_err(|error| error.to_string())?;
    let (uid, gid) = hawk_ids()?;
    chown(DATA_DIR, Some(uid), Some(gid)).map_err(|error| error.to_string())?;
    fs::set_permissions(DATA_DIR, fs::Permissions::from_mode(0o700)).map_err(|error| error.to_string())?;
    fs::create_dir_all(CONFIG_DIR).map_err(|error| error.to_string())?;

    let was_running = systemctl(&["is-active", "--quiet", UNIT]).is_ok();
    if was_running {
        systemctl(&["stop", UNIT])?;
    }
    swap_in(&unpacked)?;

    set_up_tls(&options.tls, &address.host, report)?;
    let mut origins: Vec<String> = options.origins.clone();
    for origin in APP_ORIGINS {
        if !origins.iter().any(|known| known == origin) {
            origins.push(origin.to_owned());
        }
    }
    let mut env = format!(
        "# Hawk relay settings (see the relay docs). Restart after a change:\n\
         #   systemctl restart hawk-relay\n\
         # [::] is IPv6 and IPv4 both (a name with an AAAA record needs both).\n\
         HOST=[::]\nPORT={listen_port}\nPUBLIC_URL={public_url}\n\
         FRONTEND_DIST={INSTALL_DIR}/dashboard\nTLS_CERT_PATH={}\nTLS_KEY_PATH={}\n\
         HAWK_DB_PATH={DATA_DIR}/hawk.db\nHAWK_SECRET_KEY_PATH={DATA_DIR}/secret.key\n\
         # The desktop app, and any separately hosted dashboard.\nHAWK_ALLOWED_ORIGINS={}\n",
        cert_path().display(),
        key_path().display(),
        origins.join(",")
    );
    if let (Some(smtp), Some(from)) = (&options.smtp_url, &options.mail_from) {
        env.push_str(&format!("HAWK_SMTP_URL={smtp}\nHAWK_MAIL_FROM={from}\n"));
    }
    write_file(&env_path(), &env, 0o640)?;
    give_to_hawk_group(&env_path(), 0o640)?;

    let update_file = UpdateFile { update: settings };
    write_file(&update_path(), &toml::to_string(&update_file).map_err(|error| error.to_string())?, 0o644)?;

    write_file(&unit_path(UNIT), &relay_unit(), 0o644)?;
    let (update_service, update_timer) = update_units();
    write_file(&unit_path(UPDATE_UNIT), &update_service, 0o644)?;
    write_file(&unit_path(UPDATE_TIMER), &update_timer, 0o644)?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", "--now", UNIT])?;
    systemctl(&["enable", "--now", UPDATE_TIMER])?;
    save_installed(&release.manifest.version)?;
    open_firewall(listen_port, report);

    report.step("Starting");
    wait_healthy(listen_port)?;
    report.ok("The relay is up");
    let pin = current_pin()?;
    report.ok(format!("TLS key pin (machines check this): {pin}"));
    match admin_invite() {
        Some(link) => report.ok(format!("Create the admin account (link works once, for 7 days): {link}")),
        None if was_running => report.detail("Existing accounts were kept"),
        None => report.warn("No admin invite in the log yet: see journalctl -u hawk-relay"),
    }
    if options.tls == Tls::SelfSigned {
        report.warn(
            "The certificate is self-signed: browsers warn until it's accepted, and the desktop app can't connect \
             to it. Use --tls certbot with a domain for both.",
        );
    }
    Ok(())
}

/// Puts the release's files in /opt/hawk, keeping the previous ones as
/// `.old` for a rollback.
fn swap_in(unpacked: &Path) -> Result<(), String> {
    let target = install_dir();
    fs::create_dir_all(&target).map_err(|error| error.to_string())?;
    for name in ["hawk-relay", "hawk-setup", "dashboard"] {
        let destination = target.join(name);
        let old = target.join(format!("{name}.old"));
        let _ = fs::remove_dir_all(&old);
        let _ = fs::remove_file(&old);
        if destination.exists() {
            fs::rename(&destination, &old).map_err(|error| format!("setting aside {name}: {error}"))?;
        }
        copy_tree(&unpacked.join(name), &destination)?;
    }
    for binary in ["hawk-relay", "hawk-setup"] {
        fs::set_permissions(target.join(binary), fs::Permissions::from_mode(0o755)).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn roll_back() -> Result<(), String> {
    let target = install_dir();
    for name in ["hawk-relay", "hawk-setup", "dashboard"] {
        let old = target.join(format!("{name}.old"));
        if old.exists() {
            let destination = target.join(name);
            let _ = fs::remove_dir_all(&destination);
            let _ = fs::remove_file(&destination);
            fs::rename(&old, &destination).map_err(|error| format!("restoring {name}: {error}"))?;
        }
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), String> {
    if source.is_dir() {
        fs::create_dir_all(destination).map_err(|error| error.to_string())?;
        for entry in fs::read_dir(source).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            copy_tree(&entry.path(), &destination.join(entry.file_name()))?;
        }
        fs::set_permissions(destination, fs::Permissions::from_mode(0o755)).map_err(|error| error.to_string())
    } else {
        fs::copy(source, destination).map_err(|error| format!("{}: {error}", source.display()))?;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o644)).map_err(|error| error.to_string())
    }
}

fn open_firewall(port: u16, report: &Report) {
    let rule = format!("{port}/tcp");
    if run("ufw", &["status"]).is_ok_and(|status| status.contains("Status: active")) {
        match run("ufw", &["allow", &rule]) {
            Ok(_) => report.detail(format!("Opened {rule} in ufw")),
            Err(error) => report.warn(error),
        }
    } else if run("firewall-cmd", &["--state"]).is_ok() {
        let permanent = format!("--add-port={rule}");
        match run("firewall-cmd", &["--permanent", &permanent]).and_then(|_| run("firewall-cmd", &["--reload"])) {
            Ok(_) => report.detail(format!("Opened {rule} in firewalld")),
            Err(error) => report.warn(error),
        }
    }
}

fn local(port: u16) -> RelayAddress {
    RelayAddress { host: "127.0.0.1".into(), port }
}

fn listen_port() -> u16 {
    fs::read_to_string(env_path())
        .ok()
        .and_then(|env| env.lines().find_map(|line| line.strip_prefix("PORT=").and_then(|port| port.trim().parse().ok())))
        .unwrap_or(443)
}

fn wait_healthy(port: u16) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last = String::from("no answer");
    while Instant::now() < deadline {
        match probe::http_status(&local(port), "/healthz") {
            Ok(204) => return Ok(()),
            Ok(status) => last = format!("/healthz answered {status}"),
            Err(error) => last = error,
        }
        if systemctl(&["is-failed", "--quiet", UNIT]).is_ok() {
            return Err(format!("the relay exited; see journalctl -u {UNIT}"));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!("the relay didn't come up within a minute ({last})"))
}

/// The one-time admin invite the relay logs on its first start.
fn admin_invite() -> Option<String> {
    let log = run("journalctl", &["-u", UNIT, "--no-pager", "-o", "cat", "-n", "200"]).ok()?;
    let line = log.lines().rev().find(|line| line.contains("/invite/"))?;
    let start = line.find("https://").or_else(|| line.find("http://"))?;
    Some(line[start..].split_whitespace().next()?.to_owned())
}

// ---- update ------------------------------------------------------------------------------

pub enum UpdateOutcome {
    UpToDate,
    Available(String),
    Updated,
    Skipped,
}

/// `scheduled`: run by the timer, which follows the policy in update.toml.
pub fn update(check_only: bool, scheduled: bool, overrides: &Overrides, report: &Report) -> Result<UpdateOutcome, String> {
    if !is_root() {
        return Err("run hawk-setup as root (sudo)".into());
    }
    let current = installed_version().ok_or("the relay isn't installed")?;
    let settings = read_update_settings();
    if scheduled && settings.policy == "off" {
        return Ok(UpdateOutcome::Skipped);
    }
    report.step("Looking for an update");
    let release = source(overrides, &settings)?.resolve(report)?;
    let available = release.manifest.version.clone();
    if !release.manifest.is_newer_than(&current).map_err(|error| error.to_string())? {
        report.ok(format!("Up to date ({current})"));
        return Ok(UpdateOutcome::UpToDate);
    }
    if check_only || (scheduled && settings.policy != "auto") {
        report.ok(format!("{available} is available (installed: {current}). Install it with: hawk-setup update relay"));
        return Ok(UpdateOutcome::Available(available));
    }

    let staging = Staging::new()?;
    let archive = release.fetch(&artifact(), &staging.0, report)?;
    let unpacked = staging.0.join("relay");
    crate::archive::extract(&archive, &unpacked)?;

    report.step(format!("Updating {current} to {available}"));
    systemctl(&["stop", UNIT])?;
    let backup = back_up_database(&current, report)?;
    swap_in(&unpacked)?;
    systemctl(&["start", UNIT])?;
    if let Err(error) = wait_healthy(listen_port()) {
        report.warn(format!("The new version didn't come up: {error}"));
        let _ = systemctl(&["stop", UNIT]);
        roll_back()?;
        if let Some(backup) = &backup {
            restore_database(backup)?;
        }
        systemctl(&["start", UNIT])?;
        report.warn("Rolled back to the previous version and database");
        return Err(format!("update to {available} failed and was rolled back"));
    }
    save_installed(&available)?;
    report.ok(format!("Updated to {available}"));
    Ok(UpdateOutcome::Updated)
}

const DATABASE_FILES: [&str; 3] = ["hawk.db", "hawk.db-wal", "hawk.db-shm"];

/// Copies the database (stopped, so the copy is consistent) aside before an
/// update: a newer relay migrates it, and an older one refuses a migrated
/// database. Keeps the last three.
fn back_up_database(version: &str, report: &Report) -> Result<Option<PathBuf>, String> {
    let data = Path::new(DATA_DIR);
    if !data.join("hawk.db").exists() {
        return Ok(None);
    }
    let stamp = time_stamp();
    let backup = data.join("backups").join(format!("{stamp}-{version}"));
    fs::create_dir_all(&backup).map_err(|error| error.to_string())?;
    for name in DATABASE_FILES {
        let source = data.join(name);
        if source.exists() {
            fs::copy(&source, backup.join(name)).map_err(|error| format!("backing up {name}: {error}"))?;
        }
    }
    let (uid, gid) = hawk_ids()?;
    chown(data.join("backups"), Some(uid), Some(gid)).map_err(|error| error.to_string())?;
    report.detail(format!("Database backed up to {}", backup.display()));

    let mut backups: Vec<PathBuf> = fs::read_dir(data.join("backups"))
        .map_err(|error| error.to_string())?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    backups.sort();
    while backups.len() > 3 {
        let _ = fs::remove_dir_all(backups.remove(0));
    }
    Ok(Some(backup))
}

fn restore_database(backup: &Path) -> Result<(), String> {
    let data = Path::new(DATA_DIR);
    let (uid, gid) = hawk_ids()?;
    for name in DATABASE_FILES {
        let target = data.join(name);
        let _ = fs::remove_file(&target);
        if backup.join(name).exists() {
            fs::copy(backup.join(name), &target).map_err(|error| format!("restoring {name}: {error}"))?;
            chown(&target, Some(uid), Some(gid)).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn time_stamp() -> String {
    let seconds = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("{seconds}")
}

// ---- uninstall ---------------------------------------------------------------------------------

pub fn uninstall(delete_data: bool, report: &Report) -> Result<(), String> {
    if !is_root() {
        return Err("run hawk-setup as root (sudo)".into());
    }
    report.step("Removing the relay");
    for unit in [UPDATE_TIMER, UNIT] {
        let _ = systemctl(&["disable", "--now", unit]);
    }
    for unit in [UNIT, UPDATE_UNIT, UPDATE_TIMER] {
        let _ = fs::remove_file(unit_path(unit));
    }
    let _ = systemctl(&["daemon-reload"]);
    let _ = fs::remove_dir_all(INSTALL_DIR);
    if delete_data {
        let _ = fs::remove_dir_all(DATA_DIR);
        let _ = fs::remove_dir_all(CONFIG_DIR);
        let _ = run("userdel", &[USER]);
        report.ok("Removed, with its database, settings and TLS key");
    } else {
        report.ok(format!(
            "Removed. The database ({DATA_DIR}) and settings and TLS key ({CONFIG_DIR}) were kept: a reinstall picks \
             them up. --delete-data removes them too."
        ));
    }
    Ok(())
}

// ---- status ---------------------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct Summary {
    pub installed: bool,
    pub version: Option<String>,
    pub active: bool,
    pub pin: Option<String>,
    pub update_policy: String,
}

pub fn summary() -> Summary {
    Summary {
        installed: install_dir().join("hawk-relay").exists(),
        version: installed_version(),
        active: systemctl(&["is-active", "--quiet", UNIT]).is_ok(),
        pin: current_pin().ok(),
        update_policy: read_update_settings().policy,
    }
}
