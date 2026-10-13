//! The machine side on Windows: hawk-service and hawk-capture as the
//! `HawkService` service, running as LocalSystem from Program Files\Hawk\Service
//! (Program Files\Hawk itself is the desktop app's), with
//! its settings and keys in ProgramData (readable and writable by SYSTEM and
//! administrators only).

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::machine_config::{self, UpdateSettings};
use crate::probe::{self, RelayAddress};
use crate::release::{Overrides, Release, Staging};
use crate::report::Report;
use crate::windows;

pub const SERVICE_NAME: &str = "HawkService";
const DISPLAY_NAME: &str = "Hawk Remote Service";
const DESCRIPTION: &str = "Hawk remote desktop: keeps this PC reachable from your relay, end-to-end encrypted.";
const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\HawkMachine";
const ARTIFACT: &str = "machine-windows-x64";
/// What the release's zip must hold.
const PROGRAM_FILES: [&str; 3] = ["hawk-service.exe", "hawk-capture.exe", "hawk-setup.exe"];
/// The oldest Windows with what the service relies on (ConPTY): 10 1809.
const MIN_BUILD: u32 = 17763;

/// Program Files\Hawk, shared with the desktop app, which installs there.
fn hawk_dir() -> PathBuf {
    let base = std::env::var_os("ProgramFiles").map_or_else(|| PathBuf::from(r"C:\Program Files"), PathBuf::from);
    base.join("Hawk")
}

/// Where the service is: Program Files\Hawk\Service. Releases before
/// 1.0.0-rc.6 used Program Files\Hawk itself, the app's folder too, so
/// uninstalling the machine took the app with it; such an install stays
/// where it is until its next install or update moves it
/// (move_from_old_folder).
pub fn install_dir() -> PathBuf {
    let service = hawk_dir().join("Service");
    if !service.join("hawk-service.exe").exists() && hawk_dir().join("hawk-service.exe").exists() {
        return hawk_dir();
    }
    service
}

/// Moves an install from before 1.0.0-rc.6 into Program Files\Hawk\Service,
/// with the service stopped; register_service then points it there. A
/// rename, so it works on the running hawk-setup.exe too.
fn move_from_old_folder(report: &Report) -> Result<(), String> {
    let old = hawk_dir();
    if install_dir() != old {
        return Ok(());
    }
    let new = old.join("Service");
    fs::create_dir_all(&new).map_err(|error| format!("{}: {error}", new.display()))?;
    let names = PROGRAM_FILES.iter().flat_map(|name| [(*name).to_owned(), format!("{name}.old")]);
    for name in names.chain(["install.json".to_owned()]) {
        let from = old.join(&name);
        if from.exists() {
            let to = new.join(&name);
            let _ = fs::remove_file(&to);
            fs::rename(&from, &to).map_err(|error| format!("moving {name} to {}: {error}", new.display()))?;
        }
    }
    report.detail(format!("Moved the service to {}", new.display()));
    Ok(())
}

pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    base.join("HawkService")
}

fn config_path() -> PathBuf {
    data_dir().join("config.toml")
}

/// What was installed, kept beside the binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Installed {
    version: String,
}

fn installed() -> Option<Installed> {
    let text = fs::read_to_string(install_dir().join("install.json")).ok()?;
    serde_json::from_str(&text).ok()
}

fn save_installed(version: &str) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&Installed { version: version.to_owned() }).map_err(|e| e.to_string())?;
    fs::write(install_dir().join("install.json"), json).map_err(|error| format!("install.json: {error}"))
}

/// What the service last said it was doing (see WriteStatus in the
/// service's main.cpp).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub state: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub at: i64,
}

pub fn service_status() -> Option<ServiceStatus> {
    let text = fs::read_to_string(data_dir().join("status.json")).ok()?;
    serde_json::from_str(&text).ok()
}

/// Plain words for a status.
pub fn describe(status: &ServiceStatus) -> String {
    let detail = if status.detail.is_empty() { String::new() } else { format!(" ({})", status.detail) };
    match status.state.as_str() {
        "connecting" => format!("connecting to the relay{detail}"),
        "connected" => "connected to the relay".into(),
        "enrolled" => "enrolled: the machine is in your dashboard".into(),
        "not_enrolled" => "waiting for an enrollment code".into(),
        "unreachable" => format!("can't reach the relay{detail}"),
        "pin_mismatch" => format!("the relay's key doesn't match the pin{detail}"),
        "rejected" => format!("the relay refused the enrollment{detail}"),
        "refused" => format!("the relay refused this machine{detail}"),
        "misconfigured" => format!("not set up{detail}"),
        other => format!("{other}{detail}"),
    }
}

// ---- checks -----------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    /// A problem that doesn't stop the install.
    pub warning: bool,
    pub detail: String,
}

impl Check {
    fn pass(name: &str, detail: impl Into<String>) -> Self {
        Self { name: name.into(), ok: true, warning: false, detail: detail.into() }
    }
    fn warn(name: &str, detail: impl Into<String>) -> Self {
        Self { name: name.into(), ok: true, warning: true, detail: detail.into() }
    }
    fn fail(name: &str, detail: impl Into<String>) -> Self {
        Self { name: name.into(), ok: false, warning: false, detail: detail.into() }
    }
}

/// Everything checked before anything is written, in plain words.
pub fn preflight(relay: Option<&RelayAddress>, pins: &[String]) -> Vec<Check> {
    let mut checks = Vec::new();
    checks.push(if windows::is_admin() {
        Check::pass("Administrator", "running with administrator rights")
    } else {
        Check::fail("Administrator", "run hawk-setup as an administrator")
    });
    checks.push(match windows::build_number() {
        Some(build) if build >= MIN_BUILD => Check::pass("Windows", format!("build {build}")),
        Some(build) => Check::fail("Windows", format!("build {build}; Windows 10 1809 (build {MIN_BUILD}) or later is needed")),
        None => Check::warn("Windows", "couldn't tell which version this is"),
    });
    checks.push(match windows::tpm_version() {
        Some(version) => Check::pass("TPM", format!("TPM {version}: the machine key is made inside it")),
        None => Check::warn(
            "TPM",
            "no usable TPM: the machine key is kept in Windows' software key store instead, which a copy of the \
             disk could take",
        ),
    });
    if let Some(relay) = relay {
        checks.push(match probe::relay_pin(relay) {
            Ok(pin) if pins.is_empty() => Check::warn(
                "Relay",
                format!(
                    "{} answers, but no pin was given, so its key isn't checked. Its key is {pin}: compare it with \
                     the one the dashboard shows",
                    relay.display()
                ),
            ),
            Ok(pin) if pins.iter().any(|known| known.trim() == pin) => {
                Check::pass("Relay", format!("{} answers with the pinned key", relay.display()))
            }
            Ok(pin) => Check::fail(
                "Relay",
                format!(
                    "{} answers with key {pin}, which isn't the pin you gave. Check the address, and that nobody is \
                     in between",
                    relay.display()
                ),
            ),
            Err(error) => Check::fail("Relay", error),
        });
    }
    checks
}

// ---- the service --------------------------------------------------------------

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager, String> {
    ServiceManager::local_computer(None::<&str>, access).map_err(|error| format!("opening the service manager: {error}"))
}

fn service_info() -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: install_dir().join("hawk-service.exe"),
        launch_arguments: vec![],
        dependencies: vec![],
        // LocalSystem: what capturing the secure desktop takes (see the README).
        account_name: None,
        account_password: None,
    }
}

pub fn service_state() -> Option<ServiceState> {
    let manager = manager(ServiceManagerAccess::CONNECT).ok()?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS).ok()?;
    service.query_status().ok().map(|status| status.current_state)
}

fn stop_service(report: &Report) -> Result<(), String> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let Ok(service) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP) else {
        return Ok(()); // not installed
    };
    let state = service.query_status().map_err(|error| error.to_string())?.current_state;
    if state == ServiceState::Stopped {
        return Ok(());
    }
    report.detail("Stopping the service");
    if state != ServiceState::StopPending {
        service.stop().map_err(|error| format!("stopping the service: {error}"))?;
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if service.query_status().map_err(|error| error.to_string())?.current_state == ServiceState::Stopped {
            // The process may linger a moment after it reports stopped.
            std::thread::sleep(Duration::from_millis(500));
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err("the service didn't stop within a minute".into())
}

fn start_service() -> Result<(), String> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::START | ServiceAccess::QUERY_STATUS)
        .map_err(|error| format!("opening the service: {error}"))?;
    if service.query_status().map_err(|error| error.to_string())?.current_state == ServiceState::Running {
        return Ok(());
    }
    service.start::<&str>(&[]).map_err(|error| format!("starting the service: {error}"))
}

/// Creates the service, or brings an existing one's settings up to date.
fn register_service(report: &Report) -> Result<(), String> {
    let manager = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::QUERY_CONFIG;
    let info = service_info();
    let service = match manager.open_service(SERVICE_NAME, access) {
        Ok(service) => {
            service.change_config(&info).map_err(|error| format!("updating the service: {error}"))?;
            service
        }
        Err(_) => {
            report.detail(format!("Registering the {SERVICE_NAME} service (LocalSystem, starts at boot)"));
            manager.create_service(&info, access).map_err(|error| format!("creating the service: {error}"))?
        }
    };
    service.set_description(DESCRIPTION).map_err(|error| format!("describing the service: {error}"))?;
    // Restarted if it ever crashes: a remote machine nobody can reach is
    // the one failure that can't be fixed remotely.
    let restart = |seconds| ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(seconds) };
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![restart(5), restart(30), restart(120)]),
        })
        .map_err(|error| format!("setting the service to restart on failure: {error}"))?;
    Ok(())
}

fn delete_service(report: &Report) -> Result<(), String> {
    stop_service(report)?;
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    if let Ok(service) = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE) {
        report.detail("Removing the service");
        service.delete().map_err(|error| format!("removing the service: {error}"))?;
    }
    Ok(())
}

// ---- files --------------------------------------------------------------------

/// Makes the settings folder SYSTEM's and the administrators' alone, before
/// anything in it is read. ProgramData lets any user of the PC make a
/// folder there, or files in one an administrator made, so on a PC Hawk was
/// never installed on someone could have left a config.toml naming their
/// own update feed and signing key, or turning the shell on. Anything in it
/// that another account owns means just that, and stops the install.
fn secure_data_dir(report: &Report) -> Result<(), String> {
    let dir = data_dir();
    match fs::create_dir(&dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("{}: {error}", dir.display())),
    }
    // The folder's owner first: it could undo the lockdown.
    check_owner(&dir)?;
    // What's in it before icacls goes through it: a junction left there
    // would have icacls lock whatever folder it points to.
    check_contents(&dir)?;
    report.detail(format!("Restricting {} to SYSTEM and administrators", dir.display()));
    // The folder alone, so no one else can add to it from here on...
    lock_down(&dir, false)?;
    // ...what's in it again, for anything added meanwhile...
    check_contents(&dir)?;
    // ...and then all of it.
    lock_down(&dir, true)
}

fn check_contents(dir: &Path) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|error| format!("{}: {error}", dir.display()))?.path();
        if let Some(metadata) = check_owner(&path)?
            && metadata.is_dir()
        {
            check_contents(&path)?;
        }
    }
    Ok(())
}

fn untrusted(path: &Path) -> String {
    format!(
        "{} belongs to an account that isn't an administrator, or is a link, so Hawk can't trust what's in {}.          If you didn't put it there, someone else on this PC may have: delete {} and run hawk-setup again.",
        path.display(),
        data_dir().display(),
        data_dir().display()
    )
}

/// Opens the entry itself, never what a link there points to, and only
/// when SYSTEM or the administrators own it; None when it's not there.
fn open_checked(path: &Path, contents: bool) -> Result<Option<(fs::File, fs::Metadata)>, String> {
    let file = match windows::open_unfollowed(path, contents) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    let metadata = file.metadata().map_err(|error| format!("{}: {error}", path.display()))?;
    let owned = windows::owned_by_admins(&file).map_err(|error| format!("reading who owns {}: {error}", path.display()))?;
    if windows::is_reparse_point(&metadata) || !owned {
        return Err(untrusted(path));
    }
    Ok(Some((file, metadata)))
}

fn check_owner(path: &Path) -> Result<Option<fs::Metadata>, String> {
    Ok(open_checked(path, false)?.map(|(_, metadata)| metadata))
}

/// A settings file, read from the handle that was checked.
fn read_checked(path: &Path) -> Result<Option<String>, String> {
    use std::io::Read;
    let Some((mut file, _)) = open_checked(path, true)? else { return Ok(None) };
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(Some(text))
}

/// Only SYSTEM and administrators may read or change the machine's
/// settings and keys. ProgramData's default would let any user of the PC
/// create files there: a config.toml that turns the shell on, say. `tree`
/// does what's in the folder too.
fn lock_down(dir: &Path, tree: bool) -> Result<(), String> {
    let mut command = Command::new("icacls");
    command.arg(dir).args(["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/C", "/Q"]);
    if tree {
        command.arg("/T");
    }
    let output = command.output().map_err(|error| format!("running icacls: {error}"))?;
    if !output.status.success() {
        return Err(format!("icacls failed: {}", String::from_utf8_lossy(&output.stdout).trim()));
    }
    Ok(())
}

/// Puts the release's files in place, keeping the ones they replace as
/// `.old` for a rollback. The running hawk-setup.exe can be renamed but not
/// overwritten, which is why it's a rename and a copy rather than a copy.
fn swap_in(staged: &Path, report: &Report) -> Result<(), String> {
    let target = install_dir();
    fs::create_dir_all(&target).map_err(|error| format!("{}: {error}", target.display()))?;
    for name in PROGRAM_FILES {
        let source = staged.join(name);
        let destination = target.join(name);
        let old = target.join(format!("{name}.old"));
        let _ = fs::remove_file(&old);
        if destination.exists() {
            fs::rename(&destination, &old).map_err(|error| format!("setting aside {name}: {error}"))?;
        }
        fs::copy(&source, &destination).map_err(|error| format!("copying {name}: {error}"))?;
    }
    report.detail(format!("Installed to {}", target.display()));
    Ok(())
}

fn roll_back(report: &Report) -> Result<(), String> {
    let target = install_dir();
    for name in PROGRAM_FILES {
        let old = target.join(format!("{name}.old"));
        if old.exists() {
            let destination = target.join(name);
            // The running hawk-setup.exe is the new one only when it was
            // started from here; moving it aside works either way.
            let aside = target.join(format!("{name}.failed"));
            let _ = fs::remove_file(&aside);
            let _ = fs::rename(&destination, &aside);
            fs::rename(&old, &destination).map_err(|error| format!("restoring {name}: {error}"))?;
        }
    }
    report.warn("Rolled back to the previous version");
    Ok(())
}

/// `.old` and `.failed` copies from an earlier run, once nothing runs them,
/// and the scratch folders of runs that didn't get to remove theirs. One
/// made in the last half hour may be a running update's.
pub fn clean_leftovers() {
    let target = install_dir();
    for name in PROGRAM_FILES {
        for suffix in ["old", "failed"] {
            let _ = fs::remove_file(target.join(format!("{name}.{suffix}")));
        }
    }
    let Ok(entries) = fs::read_dir(&target) else { return };
    for entry in entries.flatten() {
        let stale = entry
            .metadata()
            .and_then(|metadata| metadata.created())
            .is_ok_and(|at| at.elapsed().unwrap_or_default() > Duration::from_secs(30 * 60));
        if stale && entry.file_name().to_string_lossy().starts_with("hawk-setup-") {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

fn register_uninstall(version: &str) -> Result<(), String> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let setup = install_dir().join("hawk-setup.exe");
    let (key, _) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .create_subkey(UNINSTALL_KEY)
        .map_err(|error| format!("registering in Apps & features: {error}"))?;
    let set = |name: &str, value: String| key.set_value(name, &value).map_err(|error| error.to_string());
    set("DisplayName", "Hawk (machine service)".into())?;
    set("DisplayVersion", version.to_owned())?;
    set("Publisher", "Hawk".into())?;
    set("InstallLocation", install_dir().display().to_string())?;
    set("DisplayIcon", setup.display().to_string())?;
    set("UninstallString", format!("\"{}\" uninstall machine", setup.display()))?;
    set("QuietUninstallString", format!("\"{}\" uninstall machine --quiet", setup.display()))?;
    key.set_value("NoModify", &1u32).map_err(|error| error.to_string())?;
    key.set_value("NoRepair", &1u32).map_err(|error| error.to_string())?;
    Ok(())
}

fn unregister_uninstall() {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let _ = RegKey::predef(HKEY_LOCAL_MACHINE).delete_subkey_all(UNINSTALL_KEY);
}

/// Refused when someone other than SYSTEM or the administrators owns it:
/// its update feed and key decide what runs as SYSTEM.
fn read_config() -> Result<toml_edit::DocumentMut, String> {
    match read_checked(&config_path())? {
        Some(text) => machine_config::parse(&text),
        None => machine_config::parse(machine_config::NEW_CONFIG),
    }
}

fn write_atomically(path: &Path, contents: &str) -> Result<(), String> {
    let partial = path.with_extension("tmp");
    fs::write(&partial, contents).map_err(|error| format!("{}: {error}", partial.display()))?;
    fs::rename(&partial, path).map_err(|error| format!("{}: {error}", path.display()))
}

/// Scratch space where only administrators can write, so the checked
/// release can't be swapped before it's installed or run elevated.
/// SYSTEM's temporary folder may be C:\Windows\Temp, where any user can
/// make folders, and an administrator's own is open to every program they
/// run unelevated.
pub fn staging() -> Result<Staging, String> {
    staging_in(&install_dir())
}

/// The same, for the desktop app's installer: in Program Files\Hawk, the
/// app's own folder, so a PC with only the app gets no empty Service folder.
pub fn app_staging() -> Result<Staging, String> {
    staging_in(&hawk_dir())
}

fn staging_in(target: &Path) -> Result<Staging, String> {
    fs::create_dir_all(target).map_err(|error| format!("{}: {error}", target.display()))?;
    Staging::under(target)
}

/// Stops an install that took the release from a folder of loose binaries
/// rather than a signed release. Only in development builds.
fn stage_files(release: &Staged, staging: &Staging, report: &Report) -> Result<PathBuf, String> {
    let unpacked = staging.0.join("machine");
    match release {
        Staged::Release(release) => {
            let archive = release.fetch(ARTIFACT, &staging.0, report)?;
            crate::archive::extract(&archive, &unpacked)?;
        }
        Staged::Unsigned(folder) => {
            report.warn(format!("Installing unsigned files from {} (development build)", folder.display()));
            fs::create_dir_all(&unpacked).map_err(|error| error.to_string())?;
            for name in PROGRAM_FILES {
                let source = folder.join(name);
                let source = if name == "hawk-setup.exe" && !source.exists() {
                    std::env::current_exe().map_err(|error| error.to_string())?
                } else {
                    source
                };
                fs::copy(&source, unpacked.join(name)).map_err(|error| format!("{}: {error}", source.display()))?;
            }
        }
    }
    for name in PROGRAM_FILES {
        if !unpacked.join(name).exists() {
            return Err(format!("the release is missing {name}"));
        }
    }
    Ok(unpacked)
}

pub enum Staged {
    Release(Release),
    /// Loose files, unchecked: development builds only.
    Unsigned(PathBuf),
}

impl Staged {
    fn version(&self) -> String {
        match self {
            Self::Release(release) => release.manifest.version.clone(),
            Self::Unsigned(_) => env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

// ---- install --------------------------------------------------------------------

pub struct InstallOptions {
    /// Needed for a new install; a repair keeps the configured one.
    pub relay: Option<String>,
    pub pins: Vec<String>,
    pub code: Option<String>,
    pub policy: Option<String>,
    pub overrides: Overrides,
    /// Development builds only: install these binaries, unchecked.
    pub unsigned_from: Option<PathBuf>,
    /// How long to watch the service connect and enroll.
    pub wait: Duration,
}

pub fn install(options: InstallOptions, report: &Report) -> Result<(), String> {
    if !windows::is_admin() {
        return Err("run hawk-setup as an administrator".into());
    }
    clean_leftovers();
    secure_data_dir(report)?;
    let mut config = read_config()?;
    let relay_text = options.relay.clone().or_else(|| machine_config::relay_url(&config));
    let Some(relay_text) = relay_text else {
        return Err("which relay? Pass --relay relay.example.com (shown in the dashboard with the code)".into());
    };
    let relay = RelayAddress::parse(&relay_text)?;
    let pins: Vec<String> = options.pins.iter().map(|pin| pin.trim().to_owned()).filter(|pin| !pin.is_empty()).collect();
    if let Some(bad) = pins.iter().find(|pin| !probe::valid_pin(pin)) {
        return Err(format!("\"{bad}\" doesn't look like a relay pin (44 characters ending in '=')"));
    }
    let code = options.code.as_deref().map(str::trim).filter(|code| !code.is_empty()).map(str::to_uppercase);
    if let Some(code) = &code
        && !code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(format!("\"{code}\" doesn't look like an enrollment code"));
    }
    if let Some(policy) = &options.policy
        && !matches!(policy.as_str(), "off" | "notify" | "auto")
    {
        return Err(format!("update policy \"{policy}\" isn't off, notify or auto"));
    }

    report.step("Checking this PC");
    let known_pins = if pins.is_empty() { existing_pins() } else { pins.clone() };
    let checks = preflight(Some(&relay), &known_pins);
    for check in &checks {
        if check.ok && !check.warning {
            report.ok(format!("{}: {}", check.name, check.detail));
        } else {
            report.warn(format!("{}: {}", check.name, check.detail));
        }
    }
    if checks.iter().any(|check| !check.ok) {
        return Err("fix the problems above, then run hawk-setup again. Nothing was changed.".into());
    }

    report.step("Getting the release");
    let staging = staging()?;
    let staged = match &options.unsigned_from {
        Some(folder) if cfg!(debug_assertions) => Staged::Unsigned(folder.clone()),
        Some(_) => return Err("--unsigned-from only exists in development builds".into()),
        None => {
            let settings = machine_config::update_settings(&config);
            let source = settings.source(&options.overrides)?;
            Staged::Release(source.resolve(report)?)
        }
    };
    let version = staged.version();
    let unpacked = stage_files(&staged, &staging, report)?;

    report.step(format!("Installing Hawk {version}"));
    stop_service(report)?;
    move_from_old_folder(report)?;
    swap_in(&unpacked, report)?;

    machine_config::set_relay_url(&mut config, &relay.socket_url());
    let mut update = UpdateSettings { policy: options.policy.clone(), ..UpdateSettings::default() };
    if let Some(channel) = options.overrides.channel {
        update.channel = Some(channel.as_str().to_owned());
    }
    if !options.overrides.feed_url.is_empty() {
        update.manifest_url = Some(options.overrides.feed_url.clone());
    }
    if !options.overrides.public_key.is_empty() {
        update.public_key = Some(options.overrides.public_key.clone());
    }
    machine_config::set_update(&mut config, &update);
    write_atomically(&config_path(), &config.to_string())?;
    report.detail(format!("Relay: {}", relay.socket_url()));
    if !pins.is_empty() {
        write_atomically(&data_dir().join("relay-pins.txt"), &(pins.join("\n") + "\n"))?;
        report.detail(format!("Pinned the relay's key ({} pin{})", pins.len(), if pins.len() == 1 { "" } else { "s" }));
    }
    if let Some(code) = &code {
        write_atomically(&data_dir().join("enroll-code.txt"), code)?;
    }

    register_service(report)?;
    save_installed(&version)?;
    register_uninstall(&version)?;
    // Whatever status a previous install left would read as this one's.
    let _ = fs::remove_file(data_dir().join("status.json"));
    start_service()?;
    report.ok(format!("The {SERVICE_NAME} service is running"));
    clean_leftovers_soon();

    report.step(if code.is_some() { "Enrolling" } else { "Connecting" });
    watch(&version, code.is_some(), options.wait, report)
}

fn existing_pins() -> Vec<String> {
    read_checked(&data_dir().join("relay-pins.txt"))
        .ok()
        .flatten()
        .map(|text| text.lines().map(str::trim).filter(|line| !line.is_empty()).map(str::to_owned).collect())
        .unwrap_or_default()
}

/// Follows the service's status until it's connected (and enrolled, when
/// a code was given), it fails for good, or `wait` runs out.
fn watch(version: &str, enrolling: bool, wait: Duration, report: &Report) -> Result<(), String> {
    let deadline = Instant::now() + wait;
    let mut last = String::new();
    while Instant::now() < deadline {
        if let Some(status) = service_status().filter(|status| status.version == version)
            && status.state != last
        {
            last = status.state.clone();
            match status.state.as_str() {
                "enrolled" => {
                    report.ok("Enrolled. The machine is in your dashboard: open it there to check its key.");
                    return Ok(());
                }
                "connected" if !enrolling => {
                    report.ok("Connected to the relay");
                    return Ok(());
                }
                "rejected" | "pin_mismatch" | "misconfigured" => return Err(describe(&status)),
                "not_enrolled" if !enrolling => {
                    report.warn("The machine isn't enrolled: run hawk-setup again with --code from the dashboard");
                    return Ok(());
                }
                _ => report.detail(describe(&status)),
            }
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    report.warn(format!(
        "Still {} after {}s. The service keeps trying; its log is {}",
        if last.is_empty() { "starting".to_owned() } else { describe(&service_status().unwrap_or_default()) },
        wait.as_secs(),
        data_dir().join("hawk-service.log").display()
    ));
    Ok(())
}

/// Removes the `.old` copies once this process (which may be one of them)
/// has exited.
fn clean_leftovers_soon() {
    let target = install_dir();
    let mut script = String::from("ping -n 4 127.0.0.1 >nul");
    for name in PROGRAM_FILES {
        script.push_str(&format!(" & del /f /q \"{}\" 2>nul", target.join(format!("{name}.old")).display()));
    }
    windows::run_detached("cmd.exe", &["/d", "/c", &script]);
}

// ---- update ---------------------------------------------------------------------

pub enum UpdateOutcome {
    UpToDate,
    Available(String),
    Updated,
}

pub fn installed_version() -> Option<String> {
    if let Some(installed) = installed() {
        return Some(installed.version);
    }
    let output = Command::new(install_dir().join("hawk-service.exe")).arg("--version").output().ok()?;
    String::from_utf8_lossy(&output.stdout).split_whitespace().nth(1).map(str::to_owned)
}

pub fn update(check_only: bool, overrides: &Overrides, report: &Report) -> Result<UpdateOutcome, String> {
    let current = installed_version().ok_or("the machine isn't installed")?;
    let _lock = UpdateLock::take()?;
    let config = read_config()?;
    let source = machine_config::update_settings(&config).source(overrides)?;
    report.step("Looking for an update");
    let release = source.resolve(report)?;
    let available = release.manifest.version.clone();
    if !release.manifest.is_newer_than(&current).map_err(|error| error.to_string())? {
        report.ok(format!("Up to date ({current})"));
        return Ok(UpdateOutcome::UpToDate);
    }
    if check_only {
        report.ok(format!("{available} is available (installed: {current})"));
        return Ok(UpdateOutcome::Available(available));
    }

    let staging = staging()?;
    let unpacked = stage_files(&Staged::Release(release), &staging, report)?;
    report.step(format!("Updating {current} to {available}"));
    stop_service(report)?;
    if install_dir() == hawk_dir() {
        move_from_old_folder(report)?;
        // The service still points at the old folder.
        register_service(report)?;
    }
    swap_in(&unpacked, report)?;
    let _ = fs::remove_file(data_dir().join("status.json"));
    if let Err(error) = start_service().and_then(|()| healthy(&available)) {
        report.warn(format!("The new version didn't come up: {error}"));
        let _ = stop_service(report);
        roll_back(report)?;
        start_service()?;
        return Err(format!("update to {available} failed and was rolled back"));
    }
    save_installed(&available)?;
    register_uninstall(&available)?;
    clean_leftovers_soon();
    report.ok(format!("Updated to {available}"));
    Ok(UpdateOutcome::Updated)
}

/// The new service is up: it wrote its status as the new version and is
/// still running a little later. Whether the relay is reachable right now
/// isn't the update's doing, so that doesn't count against it.
fn healthy(version: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if service_status().is_some_and(|status| status.version == version) {
            std::thread::sleep(Duration::from_secs(5));
            return match service_state() {
                Some(ServiceState::Running) => Ok(()),
                state => Err(format!("the service stopped ({state:?})")),
            };
        }
        if matches!(service_state(), Some(ServiceState::Stopped) | None) {
            return Err("the service exited".into());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("the service didn't report in within 90s".into())
}

/// One update at a time: the service's own and one run by hand could
/// otherwise race. A lock older than half an hour is a crashed run's.
struct UpdateLock(PathBuf);

impl UpdateLock {
    fn take() -> Result<Self, String> {
        let path = install_dir().join("update.lock");
        if let Ok(metadata) = fs::metadata(&path)
            && metadata.modified().is_ok_and(|at| at.elapsed().unwrap_or_default() > Duration::from_secs(30 * 60))
        {
            let _ = fs::remove_file(&path);
        }
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| "another update is already running".to_owned())?;
        Ok(Self(path))
    }
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

// ---- uninstall --------------------------------------------------------------------

pub fn uninstall(keep_data: bool, report: &Report) -> Result<(), String> {
    if !windows::is_admin() {
        return Err("run hawk-setup as an administrator".into());
    }
    report.step("Removing the machine service");
    delete_service(report)?;
    if !keep_data {
        let service = install_dir().join("hawk-service.exe");
        if service.exists() {
            report.detail("Deleting the machine key and enrollment");
            let status = Command::new(&service).arg("--remove-identity").status();
            if !status.is_ok_and(|status| status.success()) {
                report.warn("Couldn't delete the machine key; remove the machine in the dashboard too");
            }
        }
        let data = data_dir();
        if data.exists() {
            fs::remove_dir_all(&data).map_err(|error| format!("{}: {error}", data.display()))?;
            report.detail(format!("Removed {}", data.display()));
        }
    }
    unregister_uninstall();
    remove_program_files(report)?;
    report.ok(if keep_data {
        "Removed. Settings and the machine key were kept for a reinstall."
    } else {
        "Removed. Remove the machine in the dashboard too, if you haven't."
    });
    Ok(())
}

/// Deletes the service's folder, and Program Files\Hawk once it's empty:
/// the desktop app may be installed there, and stays. When this
/// hawk-setup.exe is the one in there, what's left goes once it has exited.
fn remove_program_files(report: &Report) -> Result<(), String> {
    let target = install_dir();
    if !target.exists() {
        return Ok(());
    }
    let running_from_there = std::env::current_exe().is_ok_and(|exe| exe.starts_with(&target));
    let parent = hawk_dir();
    if target == parent {
        // An install from before 1.0.0-rc.6, in the app's folder: only the
        // service's own files go.
        remove_service_files(&target);
        if running_from_there {
            let script = format!(
                "ping -n 4 127.0.0.1 >nul & del /f /q \"{}\" & rmdir \"{}\"",
                target.join("hawk-setup.exe").display(),
                target.display()
            );
            windows::run_detached("cmd.exe", &["/d", "/c", &script]);
        } else {
            let _ = fs::remove_dir(&target);
        }
    } else if running_from_there {
        let script =
            format!("ping -n 4 127.0.0.1 >nul & rmdir /s /q \"{}\" & rmdir \"{}\"", target.display(), parent.display());
        windows::run_detached("cmd.exe", &["/d", "/c", &script]);
    } else {
        fs::remove_dir_all(&target).map_err(|error| format!("{}: {error}", target.display()))?;
        let _ = fs::remove_dir(&parent);
    }
    report.detail(format!("Removed {}", target.display()));
    Ok(())
}

/// The service's files in `folder`, and nothing else that's there.
fn remove_service_files(folder: &Path) {
    for name in PROGRAM_FILES {
        for file in [(*name).to_owned(), format!("{name}.old"), format!("{name}.failed")] {
            let _ = fs::remove_file(folder.join(file));
        }
    }
    for file in ["install.json", "update.lock"] {
        let _ = fs::remove_file(folder.join(file));
    }
    if let Ok(entries) = fs::read_dir(folder) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with("hawk-setup-") {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
}

// ---- status -------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct Summary {
    pub installed: bool,
    pub version: Option<String>,
    pub service: Option<String>,
    pub status: Option<ServiceStatus>,
    pub relay: Option<String>,
    pub update_policy: Option<String>,
}

pub fn summary() -> Summary {
    let config = fs::read_to_string(config_path()).ok().and_then(|text| machine_config::parse(&text).ok());
    Summary {
        installed: install_dir().join("hawk-service.exe").exists(),
        version: installed_version(),
        service: service_state().map(|state| format!("{state:?}").to_lowercase()),
        status: service_status(),
        relay: config.as_ref().and_then(machine_config::relay_url),
        update_policy: config.as_ref().map(|config| machine_config::update_settings(config).policy.unwrap_or("notify".into())),
    }
}
