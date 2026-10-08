//! Wire messages. The JSON shapes must stay identical to
//! `frontend/src/protocol.ts` and to the hello / RelayCommand handling in
//! `src/service/main.cpp`.

use serde::{Deserialize, Serialize};

use crate::db::Role;

/// The first (and only text) message a device sends after connecting. It
/// carries either the machine's credential or, the first time, a one-time
/// enrollment code from the owner's dashboard.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeviceMessage {
    Hello {
        /// The machine's hostname, shown to the owner.
        machine_id: String,
        #[serde(default)]
        credential: Option<String>,
        #[serde(default)]
        enroll_code: Option<String>,
    },
}

/// Messages the relay sends down to a device.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeviceCommand {
    /// Reply to a hello with a valid enrollment code: the credential to send
    /// from now on. Shown once; the relay keeps only its hash.
    Enrolled { machine_id: String, credential: String },
    StartCapture,
    StopCapture,
}

/// Messages a dashboard sends up to start/stop watching a machine's screen.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", rename_all_fields = "camelCase")]
pub enum DashboardCommand {
    StartView { device_id: String },
    StopView { device_id: String },
}

/// A machine as one dashboard's user sees it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineView {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub owner_email: String,
    pub role: Role,
    pub online: bool,
    /// RFC 3339; set while online.
    pub connected_at: Option<String>,
    /// Unix seconds.
    pub last_seen_at: Option<i64>,
    /// Who is watching right now. Only sent to the owner.
    pub viewers: Option<Vec<String>>,
}

/// Messages pushed to connected dashboards.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", rename_all_fields = "camelCase")]
pub enum DashboardEvent {
    Snapshot { machines: Vec<MachineView> },
    /// Added to this user's list, or changed (renamed, role, online state).
    MachineUpdated { machine: MachineView },
    /// No longer accessible: deleted, or the share was revoked.
    MachineRemoved { id: String },
    /// The machine went away (or never had a capture running) while this
    /// dashboard was viewing it; the viewer should tear its decoder down.
    CaptureEnded { device_id: String },
}

/// Binary video frame produced by hawk-service (BuildVideoFrame):
///   [0]     u8  kind (0x01 = H.264 Annex B)
///   [1]     u8  flags (bit 0 = keyframe)
///   [2..9]  i64 timestamp, microseconds, little-endian
///   [10..]      the access unit
/// The relay forwards frames verbatim and only reads the keyframe flag.
pub fn is_keyframe(frame: &[u8]) -> bool {
    frame.get(1).is_some_and(|flags| flags & 0x01 != 0)
}
