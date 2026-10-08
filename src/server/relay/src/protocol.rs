//! Wire messages. The JSON shapes must stay identical to
//! `frontend/src/protocol.ts` and to the hello / RelayCommand handling in
//! `src/service/main.cpp`.

use serde::{Deserialize, Serialize};

use crate::db::Role;

/// Text messages a device sends. A connection opens with a hello, the relay
/// answers with a challenge, and the device signs it with its machine key:
///
/// - an enrolled machine names itself (`machine`) and signs with the key it
///   enrolled with;
/// - a new machine sends a one-time `enroll_code` plus the public half of a
///   key it just created, and signs with that key to prove it holds it.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeviceMessage {
    Hello {
        /// The machine's hostname, shown to the owner.
        machine_id: String,
        /// The relay-assigned id of an enrolled machine.
        #[serde(default)]
        machine: Option<String>,
        #[serde(default)]
        enroll_code: Option<String>,
        /// Base64 uncompressed P-256 point; enrollment only.
        #[serde(default)]
        public_key: Option<String>,
        /// "tpm" or "software"; enrollment only.
        #[serde(default)]
        key_storage: Option<String>,
    },
    Proof {
        /// Base64 ECDSA P-256 signature, r||s, over
        /// [`machine_auth_message`] for the challenge.
        signature: String,
    },
}

/// Messages the relay sends down to a device.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeviceCommand {
    /// Base64 32 random bytes, fresh per connection.
    Challenge { nonce: String },
    /// The enrollment went through; `machine_id` is what to send as
    /// `machine` in future hellos.
    Enrolled { machine_id: String },
    StartCapture,
    StopCapture,
}

/// What a device signs to answer a challenge. The fixed prefix keeps the
/// signature from being valid for anything else the key might sign.
pub fn machine_auth_message(nonce: &[u8]) -> Vec<u8> {
    [b"hawk-machine-auth-v1\0".as_slice(), nonce].concat()
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
    /// Where the machine keeps its key, as it reports it: "tpm" or
    /// "software". None means it must be re-enrolled before it can connect.
    pub key_storage: Option<String>,
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
