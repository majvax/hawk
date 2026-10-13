//! The few Windows calls the installer needs beyond the service manager.

use std::os::windows::process::CommandExt;
use std::process::Command;

use windows_sys::Win32::System::TpmBaseServices::{TBS_SUCCESS, TPM_DEVICE_INFO, Tbsi_GetDeviceInfo};
use windows_sys::Win32::UI::Shell::IsUserAnAdmin;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DETACHED_PROCESS: u32 = 0x0000_0008;

pub fn is_admin() -> bool {
    // SAFETY: takes no arguments and only reads the process token.
    unsafe { IsUserAnAdmin() != 0 }
}

/// Windows' build number, e.g. 19045.
pub fn build_number() -> Option<u32> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let key = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion").ok()?;
    let build: String = key.get_value("CurrentBuildNumber").ok()?;
    build.parse().ok()
}

/// "2.0" when there's a TPM Windows can use, None otherwise.
pub fn tpm_version() -> Option<&'static str> {
    let mut info = TPM_DEVICE_INFO { structVersion: 0, tpmVersion: 0, tpmInterfaceType: 0, tpmImpRevision: 0 };
    // SAFETY: `info` is a valid, writable TPM_DEVICE_INFO of the size passed.
    let result = unsafe { Tbsi_GetDeviceInfo(size_of::<TPM_DEVICE_INFO>() as u32, (&raw mut info).cast()) };
    if result != TBS_SUCCESS {
        return None;
    }
    match info.tpmVersion {
        1 => Some("1.2"),
        2 => Some("2.0"),
        _ => None,
    }
}

/// Starts a program that outlives this one, with no window.
pub fn run_detached(program: &str, args: &[&str]) {
    let _ = Command::new(program).args(args).creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS).spawn();
}

/// Starts this program again elevated (a UAC prompt), with the same
/// arguments. Returns false if the person said no.
#[cfg_attr(not(feature = "gui"), allow(dead_code))]
pub fn relaunch_elevated() -> bool {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let Ok(exe) = std::env::current_exe() else { return false };
    let args: Vec<String> = std::env::args().skip(1).map(|arg| format!("\"{}\"", arg.replace('"', "\\\""))).collect();
    let wide = |text: &str| text.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let verb = wide("runas");
    let file = wide(&exe.display().to_string());
    let parameters = wide(&args.join(" "));
    // SAFETY: every string is NUL-terminated UTF-16 that outlives the call.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            parameters.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    result as isize > 32
}
