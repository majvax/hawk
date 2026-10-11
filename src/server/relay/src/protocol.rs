//! Wire messages. The JSON shapes must stay identical to
//! `frontend/src/protocol.ts` and to the hello / RelayCommand handling in
//! `src/service/main.cpp`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::db::{Role, Signed};

/// Text messages a device sends. A connection opens with a hello, the relay
/// answers with a challenge, and the device signs it with its machine key:
///
/// - an enrolled machine names itself (`machine`) and signs with the key it
///   enrolled with;
/// - a new machine sends the hash of a one-time enrollment code plus the
///   public half of a key it just created, and signs with that key to
///   prove it holds it.
///
/// After that it answers viewers' join requests. Those answers are for the
/// viewer's browser, which checks the machine's signature on them; the
/// relay only routes them by `viewer`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeviceMessage {
    Hello {
        /// The machine's hostname, shown to the owner.
        machine_id: String,
        /// The relay-assigned id of an enrolled machine.
        #[serde(default)]
        machine: Option<String>,
        /// Base64 SHA-256 of the enrollment code's canonical form. The code
        /// itself never leaves the machine: it keys the bindings below.
        #[serde(default)]
        enroll_code_hash: Option<String>,
        /// Base64 uncompressed P-256 point; enrollment only.
        #[serde(default)]
        public_key: Option<String>,
        /// "tpm" or "software"; enrollment only.
        #[serde(default)]
        key_storage: Option<String>,
        /// Base64 HMAC of `public_key` under a key derived from the
        /// enrollment code, which the relay never sees; enrollment only.
        /// The owner's browser checks it before vouching for the key.
        #[serde(default)]
        binding: Option<String>,
    },
    Proof {
        /// Base64 ECDSA P-256 signature, r||s, over
        /// [`machine_auth_message`] for the challenge.
        signature: String,
    },
    /// The machine accepted a viewer: its signed half of the key exchange,
    /// and the stream key wrapped for that viewer alone.
    ViewerAccept { viewer: u64, statement: String, signature: String, wrapped_key: String },
    /// The machine refused a viewer (no valid grant, revoked, expired...).
    ViewerReject { viewer: u64, reason: String },
    /// A new stream key, wrapped for one viewer: sent to every remaining
    /// viewer when one leaves, so the one who left can't read what follows.
    StreamKey { viewer: u64, wrapped_key: String },
}

/// Messages the relay sends down to a device.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeviceCommand {
    /// Base64 32 random bytes, fresh per connection.
    Challenge { nonce: String },
    /// The enrollment went through; `machine_id` is what to send as
    /// `machine` in future hellos. `owner_key` is the owner's identity key
    /// and `owner_binding` its HMAC under the enrollment code, which the
    /// machine checks before pinning the key as its owner's.
    Enrolled { machine_id: String, owner_key: String, owner_binding: String },
    StartCapture,
    StopCapture,
    /// A viewer asks for the stream: its signed join request, and the grant
    /// the owner signed for it (none when the viewer is the owner). The
    /// machine checks both and answers with a viewer_accept or
    /// viewer_reject. `viewer` is the relay's name for this viewer, only
    /// used to route the answer.
    ViewerJoin {
        viewer: u64,
        statement: String,
        signature: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        grant: Option<SignedView>,
    },
    /// The viewer stopped watching: the machine lets go of whatever its
    /// input holds and moves the others to a new stream key.
    ViewerLeft { viewer: u64 },
    /// Input sealed by the viewer for the machine; the relay can't read it.
    Input { viewer: u64, sealed: String },
    /// Every revocation the owner has signed for this machine.
    Revocations { revocations: Vec<SignedView> },
}

/// A signed statement on the wire (see crate::e2e).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedView {
    pub statement: String,
    /// Base64 r || s.
    pub signature: String,
}

impl From<&Signed> for SignedView {
    fn from(signed: &Signed) -> Self {
        Self { statement: signed.statement.clone(), signature: BASE64.encode(&signed.signature) }
    }
}

impl SignedView {
    /// None if the signature isn't base64, or either part is unreasonably
    /// long for what it carries.
    pub fn decode(&self) -> Option<Signed> {
        if self.statement.len() > MAX_STATEMENT_LEN || self.signature.len() > 128 {
            return None;
        }
        Some(Signed { statement: self.statement.clone(), signature: BASE64.decode(&self.signature).ok()? })
    }
}

/// Longer than any statement the dashboard or the machine writes.
pub const MAX_STATEMENT_LEN: usize = 1024;
/// A sealed input event: a JSON event of a few dozen bytes, plus counter
/// and tag, in base64.
pub const MAX_SEALED_INPUT_LEN: usize = 512;
/// What the machine sends a viewer: a signed accept and a wrapped key.
const MAX_ANSWER_LEN: usize = 2048;

/// True when everything the machine sent for a viewer is of a sane size;
/// the relay passes it on without reading it.
pub fn answer_fits(parts: &[&str]) -> bool {
    parts.iter().map(|part| part.len()).sum::<usize>() <= MAX_ANSWER_LEN
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
    /// `join` is the viewer's signed half of the key exchange, for the
    /// machine; the relay adds the viewer's grant from its records.
    StartView { device_id: String, join: SignedView },
    StopView { device_id: String },
    /// Sealed for the machine. Only passed on while viewing the machine
    /// with a control (or owner) role; the machine checks that again.
    Input { device_id: String, sealed: String },
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
    /// Base64 keys: the machine's, and its owner's identity key. None for a
    /// machine that must be re-enrolled.
    pub public_key: Option<String>,
    pub owner_public_key: Option<String>,
    /// Base64 signature of the owner over the machine's key (see
    /// crate::e2e::machine_statement), once the owner checked it.
    pub endorsement: Option<String>,
    /// Owner only, until endorsed: base64 hash of the enrollment code the
    /// machine used and the HMAC it answered with, for the browser that
    /// made the code to check.
    pub enroll_code_hash: Option<String>,
    pub enroll_binding: Option<String>,
    /// Shares only: whether the owner has signed a grant for this user yet.
    /// Without one the machine refuses them.
    pub granted: bool,
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
    /// The machine's answer to this dashboard's join: its signed half of the
    /// key exchange and the stream key, wrapped for this viewer.
    ViewAccepted { device_id: String, statement: String, signature: String, wrapped_key: String },
    /// The machine refused to stream to this viewer.
    ViewRejected { device_id: String, reason: String },
    /// The stream moved to a new key, wrapped for this viewer.
    StreamKey { device_id: String, wrapped_key: String },
}

/// Binary video frame produced by hawk-service (BuildVideoFrame):
///   [0]     u8  kind (0x02 = H.264 Annex B, encrypted)
///   [1]     u8  flags (bit 0 = keyframe)
///   [2..9]  i64 timestamp, microseconds, little-endian
///   [10..]      key id, nonce and the encrypted access unit
/// The relay forwards frames verbatim and only reads the keyframe flag,
/// which stays readable so it can start new viewers on a keyframe.
pub fn is_keyframe(frame: &[u8]) -> bool {
    frame.get(1).is_some_and(|flags| flags & 0x01 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_commands_parse() {
        let command: DashboardCommand = serde_json::from_str(
            r#"{"type":"input","deviceId":"m1","sealed":"AAAA"}"#,
        )
        .unwrap();
        let DashboardCommand::Input { device_id, sealed } = command else { panic!("not input") };
        assert_eq!((device_id.as_str(), sealed.as_str()), ("m1", "AAAA"));

        let command: DashboardCommand = serde_json::from_str(
            r#"{"type":"start_view","deviceId":"m1","join":{"statement":"s","signature":"AAAA"}}"#,
        )
        .unwrap();
        assert!(matches!(command, DashboardCommand::StartView { .. }));
    }

    #[test]
    fn device_commands_serialize() {
        let json = serde_json::to_value(DeviceCommand::Input { viewer: 7, sealed: "x".into() }).unwrap();
        assert_eq!(json, serde_json::json!({"type":"input","viewer":7,"sealed":"x"}));
        let json = serde_json::to_value(DeviceCommand::ViewerJoin {
            viewer: 1,
            statement: "s".into(),
            signature: "g".into(),
            grant: None,
        })
        .unwrap();
        assert_eq!(json, serde_json::json!({"type":"viewer_join","viewer":1,"statement":"s","signature":"g"}));
    }

    #[test]
    fn device_answers_parse() {
        let message: DeviceMessage =
            serde_json::from_str(r#"{"type":"viewer_reject","viewer":3,"reason":"no grant"}"#).unwrap();
        assert!(matches!(message, DeviceMessage::ViewerReject { viewer: 3, .. }));
    }

    #[test]
    fn oversized_statements_are_refused() {
        let view = SignedView { statement: "x".repeat(MAX_STATEMENT_LEN + 1), signature: String::new() };
        assert!(view.decode().is_none());
        let view = SignedView { statement: "ok".into(), signature: "not base64!".into() };
        assert!(view.decode().is_none());
    }
}
