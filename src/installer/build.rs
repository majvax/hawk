fn main() {
    // The window's frontend and Windows resources only exist with the gui
    // feature; the command-line build needs neither.
    #[cfg(feature = "gui")]
    tauri_build::build();
}
