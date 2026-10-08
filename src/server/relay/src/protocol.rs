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
    /// Mouse or keyboard from a viewer allowed to control the machine.
    Input {
        #[serde(flatten)]
        event: InputEvent,
    },
    /// Let go of every key and button input has pressed: the viewer who
    /// pressed them stopped watching or lost control.
    ReleaseInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

/// One input event, as the dashboard sends it and the device receives it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InputEvent {
    /// Pointer position as a fraction of the captured screen, 0..=1 from the
    /// top-left corner, so neither side needs the other's resolution.
    MouseMove { x: f64, y: f64 },
    MouseButton { button: MouseButton, down: bool },
    /// In WHEEL_DELTA units (120 per notch); positive is up / right.
    Wheel { dx: i32, dy: i32 },
    /// A physical key, named by `KeyboardEvent.code` ("KeyA", "ShiftLeft").
    Key { code: String, down: bool },
}

/// Beyond this a wheel event is either a bug or an attempt to spin the
/// remote page; ten notches covers any real flick.
const MAX_WHEEL: i32 = 1200;
/// hawk-service hands the code to hawk-capture in a 32-byte, NUL-terminated
/// field (common/input_pipe.hpp), which leaves room for 31 characters.
const MAX_KEY_CODE_LEN: usize = 31;

impl InputEvent {
    /// Letting go of a key or button, as opposed to pressing one or moving.
    pub fn is_release(&self) -> bool {
        matches!(self, Self::MouseButton { down: false, .. } | Self::Key { down: false, .. })
    }

    /// The event with its values brought into range, or None if it can't
    /// be made sense of.
    pub fn sanitized(self) -> Option<Self> {
        match self {
            Self::MouseMove { x, y } if x.is_finite() && y.is_finite() => {
                Some(Self::MouseMove { x: x.clamp(0.0, 1.0), y: y.clamp(0.0, 1.0) })
            }
            Self::MouseMove { .. } => None,
            Self::Wheel { dx, dy } => {
                Some(Self::Wheel { dx: dx.clamp(-MAX_WHEEL, MAX_WHEEL), dy: dy.clamp(-MAX_WHEEL, MAX_WHEEL) })
            }
            Self::Key { code, down } => {
                let valid = !code.is_empty()
                    && code.len() <= MAX_KEY_CODE_LEN
                    && code.bytes().all(|byte| byte.is_ascii_alphanumeric());
                valid.then_some(Self::Key { code, down })
            }
            button @ Self::MouseButton { .. } => Some(button),
        }
    }
}

/// What a device signs to answer a challenge. The fixed prefix keeps the
/// signature from being valid for anything else the key might sign.
pub fn machine_auth_message(nonce: &[u8]) -> Vec<u8> {
    [b"hawk-machine-auth-v1\0".as_slice(), nonce].concat()
}

/// Messages a dashboard sends up: start/stop watching a machine, and input.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", rename_all_fields = "camelCase")]
pub enum DashboardCommand {
    StartView { device_id: String },
    StopView { device_id: String },
    /// Only acted on while viewing the machine with a control (or owner) role.
    Input { device_id: String, event: InputEvent },
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
    /// Unix seconds when this user's temporary share ends; None for the
    /// owner and open-ended shares.
    pub access_expires_at: Option<i64>,
    /// This user's share is used up by one viewing.
    pub single_view: bool,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_input_parses() {
        let command: DashboardCommand = serde_json::from_str(
            r#"{"type":"input","deviceId":"m1","event":{"kind":"key","code":"KeyA","down":true}}"#,
        )
        .unwrap();
        let DashboardCommand::Input { device_id, event } = command else { panic!("not input") };
        assert_eq!(device_id, "m1");
        assert_eq!(event, InputEvent::Key { code: "KeyA".into(), down: true });
    }

    #[test]
    fn device_input_is_flat() {
        let json = serde_json::to_value(DeviceCommand::Input {
            event: InputEvent::MouseButton { button: MouseButton::Right, down: false },
        })
        .unwrap();
        assert_eq!(json, serde_json::json!({"type":"input","kind":"mouse_button","button":"right","down":false}));
        assert_eq!(serde_json::to_value(DeviceCommand::ReleaseInput).unwrap(), serde_json::json!({"type":"release_input"}));
    }

    #[test]
    fn sanitizing_clamps_and_rejects() {
        assert_eq!(
            InputEvent::MouseMove { x: -0.5, y: 2.0 }.sanitized(),
            Some(InputEvent::MouseMove { x: 0.0, y: 1.0 })
        );
        assert_eq!(InputEvent::MouseMove { x: f64::NAN, y: 0.5 }.sanitized(), None);
        assert_eq!(
            InputEvent::Wheel { dx: -99_999, dy: 99_999 }.sanitized(),
            Some(InputEvent::Wheel { dx: -MAX_WHEEL, dy: MAX_WHEEL })
        );
        assert_eq!(InputEvent::Key { code: String::new(), down: true }.sanitized(), None);
        assert_eq!(InputEvent::Key { code: "Key A".into(), down: true }.sanitized(), None);
        assert_eq!(InputEvent::Key { code: "K".repeat(32), down: true }.sanitized(), None);
        assert!(InputEvent::Key { code: "K".repeat(31), down: true }.sanitized().is_some());
        assert!(InputEvent::Key { code: "ShiftLeft".into(), down: true }.sanitized().is_some());
    }
}
