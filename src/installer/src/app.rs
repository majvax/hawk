//! The desktop app on Windows. Its own installer (built by Tauri) does the
//! work: hawk-setup fetches it from the release, checks it like any other
//! artifact, and runs it silently. Once installed, the app updates itself
//! from the same feed.

use std::process::Command;

use crate::release::Overrides;
use crate::report::Report;

const ARTIFACT: &str = "app-windows-x64";
/// The app's uninstall entry, as its NSIS installer writes it (per machine).
const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Hawk";

fn uninstall_entry() -> Option<winreg::RegKey> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER].into_iter().find_map(|root| RegKey::predef(root).open_subkey(UNINSTALL_KEY).ok())
}

pub fn installed_version() -> Option<String> {
    uninstall_entry()?.get_value("DisplayVersion").ok()
}

pub fn install(overrides: &Overrides, report: &Report) -> Result<(), String> {
    // Its installer is per machine, so it runs elevated.
    if !crate::windows::is_admin() {
        return Err("run hawk-setup as an administrator".into());
    }
    report.step("Getting the desktop app");
    // No channel set: the build's own, so a release candidate finds itself.
    let source = overrides.over("", "", hawk_update::Channel::of_this_build());
    let release = source.resolve(report)?;
    if let Some(current) = installed_version()
        && !release.manifest.is_newer_than(&current).map_err(|error| error.to_string())?
    {
        report.ok(format!("The app is already installed ({current})"));
        return Ok(());
    }
    let staging = crate::machine::app_staging()?;
    let setup = release.fetch(ARTIFACT, &staging.0, report)?;
    report.step(format!("Installing the app {}", release.manifest.version));
    let status = Command::new(&setup).arg("/S").status().map_err(|error| format!("running the app's installer: {error}"))?;
    if !status.success() {
        return Err(format!("the app's installer failed ({status})"));
    }
    report.ok("Installed. Start Hawk from the Start menu and enter your relay's address.");
    Ok(())
}

pub fn uninstall(report: &Report) -> Result<(), String> {
    let Some(entry) = uninstall_entry() else {
        report.ok("The app isn't installed");
        return Ok(());
    };
    let command: String = entry.get_value("QuietUninstallString").or_else(|_| entry.get_value("UninstallString")).map_err(|error| error.to_string())?;
    report.step("Removing the desktop app");
    let status = Command::new("cmd.exe")
        .args(["/d", "/c", &command, "/S"])
        .status()
        .map_err(|error| format!("running the app's uninstaller: {error}"))?;
    if !status.success() {
        return Err(format!("the app's uninstaller failed ({status})"));
    }
    report.ok("Removed");
    Ok(())
}
