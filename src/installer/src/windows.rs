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

/// Opens `path` itself, never what a link or junction there points to, for
/// reading who owns it, and its contents too when `contents`. Folders open
/// as well.
pub fn open_unfollowed(path: &std::path::Path, contents: bool) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
    };

    std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | if contents { GENERIC_READ } else { 0 })
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Whether SYSTEM or the administrators own the open file or folder. Any
/// other owner can change who may write to it, whatever its permissions
/// say now; that includes the account running this, since what it makes
/// unelevated is its own and any program it runs can change it.
pub fn owned_by_admins(file: &std::fs::File) -> std::io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, WinBuiltinAdministratorsSid,
        WinLocalSystemSid,
    };

    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the handle is open for the call's length, and the two
    // out-pointers are valid; the parts not asked for may be null.
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if result != 0 {
        return Err(std::io::Error::from_raw_os_error(result as i32));
    }
    // SAFETY: `owner` points into `descriptor`, which lives until the
    // LocalFree below.
    let trusted =
        unsafe { IsWellKnownSid(owner, WinLocalSystemSid) != 0 || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0 };
    // SAFETY: `descriptor` was allocated by GetSecurityInfo for us.
    unsafe { LocalFree(descriptor) };
    Ok(trusted)
}

/// Whether the open entry is a link, a junction or another reparse point.
pub fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tells_who_owns_a_folder() {
        let owned = |path: std::path::PathBuf| owned_by_admins(&open_unfollowed(&path, false).unwrap()).unwrap();
        let folder = |name: &str, default: &str| std::env::var_os(name).map_or_else(|| default.into(), std::path::PathBuf::from);
        // SYSTEM's.
        assert!(owned(folder("ProgramData", r"C:\ProgramData")));
        // TrustedInstaller's: not one of the two.
        assert!(!owned(folder("SystemRoot", r"C:\Windows")));
        let missing = std::env::temp_dir().join(format!("hawk-setup-missing-{}", std::process::id()));
        assert_eq!(open_unfollowed(&missing, false).unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }
}
