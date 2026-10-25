//! The installer's window: the same steps as the command line, for someone
//! who double-clicked hawk-setup.exe. The page (ui/) uses the dashboard's
//! look; everything it does goes through the commands below, which call the
//! same code the command line does and stream its progress lines to it.

use std::process::ExitCode;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use crate::machine;
use crate::release::Overrides;
use crate::report::{Kind, Report, Sink};
use crate::windows;

struct Events(AppHandle);

#[derive(Clone, Serialize)]
struct Line {
    kind: Kind,
    text: String,
}

impl Sink for Events {
    fn line(&self, kind: Kind, text: &str) {
        let _ = self.0.emit("progress", Line { kind, text: text.to_owned() });
    }
}

#[derive(Serialize)]
struct Status {
    setup_version: &'static str,
    machine: machine::Summary,
    status_text: Option<String>,
    app: Option<String>,
    feed_configured: bool,
}

#[tauri::command]
fn status() -> Status {
    let machine = machine::summary();
    let status_text = machine.status.as_ref().map(machine::describe);
    Status {
        setup_version: env!("CARGO_PKG_VERSION"),
        machine,
        status_text,
        app: crate::app::installed_version(),
        feed_configured: hawk_update::DEFAULT_FEED_URL.is_some() && hawk_update::DEFAULT_PUBLIC_KEY.is_some(),
    }
}

#[tauri::command(async)]
fn preflight(relay: String, pins: Vec<String>) -> Result<Vec<machine::Check>, String> {
    let address = crate::probe::RelayAddress::parse(&relay)?;
    let pins: Vec<String> = pins.into_iter().map(|pin| pin.trim().to_owned()).filter(|pin| !pin.is_empty()).collect();
    Ok(machine::preflight(Some(&address), &pins))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MachineForm {
    relay: String,
    pin: String,
    code: String,
    policy: String,
    files: bool,
    shell: bool,
}

#[tauri::command(async)]
fn install_machine(app: AppHandle, form: MachineForm) -> Result<(), String> {
    let report = Report::new(Events(app));
    let pins = form.pin.split([',', ' ', '\n']).map(str::trim).filter(|pin| !pin.is_empty()).map(str::to_owned).collect();
    machine::install(
        machine::InstallOptions {
            relay: Some(form.relay),
            pins,
            code: Some(form.code).filter(|code| !code.trim().is_empty()),
            policy: Some(form.policy),
            files: Some(form.files),
            shell: Some(form.shell),
            overrides: Overrides::default(),
            unsigned_from: None,
            wait: std::time::Duration::from_secs(90),
        },
        &report,
    )
}

#[tauri::command(async)]
fn install_app(app: AppHandle) -> Result<(), String> {
    crate::app::install(&Overrides::default(), &Report::new(Events(app)))
}

/// The newer version available, or None when up to date.
#[tauri::command(async)]
fn check_update(app: AppHandle) -> Result<Option<String>, String> {
    match machine::update(true, &Overrides::default(), &Report::new(Events(app)))? {
        machine::UpdateOutcome::Available(version) => Ok(Some(version)),
        _ => Ok(None),
    }
}

#[tauri::command(async)]
fn update_machine(app: AppHandle) -> Result<(), String> {
    machine::update(false, &Overrides::default(), &Report::new(Events(app))).map(|_| ())
}

#[tauri::command(async)]
fn uninstall_machine(app: AppHandle, keep_data: bool) -> Result<(), String> {
    machine::uninstall(keep_data, &Report::new(Events(app)))
}

/// Closes the console Windows opened for a double-click; a console the
/// person started this from stays theirs.
fn release_console() {
    use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
    let mut processes = [0u32; 2];
    // SAFETY: the buffer is valid for the length passed.
    let attached = unsafe { GetConsoleProcessList(processes.as_mut_ptr(), processes.len() as u32) };
    if attached == 1 {
        // SAFETY: no arguments; detaching from our own console.
        unsafe { FreeConsole() };
    }
}

pub fn run() -> ExitCode {
    // Installing a service takes an administrator; ask once, up front.
    // Development builds can skip that to look at the window.
    let skip = cfg!(debug_assertions) && std::env::var_os("HAWK_SETUP_NO_ELEVATE").is_some();
    if !windows::is_admin() && !skip {
        return if windows::relaunch_elevated() { ExitCode::SUCCESS } else { ExitCode::FAILURE };
    }
    release_console();
    let result = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            status,
            preflight,
            install_machine,
            install_app,
            check_update,
            update_machine,
            uninstall_machine
        ])
        .run(tauri::generate_context!());
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
