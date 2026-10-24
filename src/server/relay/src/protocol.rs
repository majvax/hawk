//! Wire messages. The JSON shapes must stay identical to
//! `frontend/src/protocol.ts` and to the hello / RelayCommand handling in
//! `src/service/main.cpp`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::db::{Role, Signed};
use crate::quality::Preset;

/// Bumped when a message changes in a way an older dashboard or machine
/// can't follow. Must match `PROTOCOL_VERSION` in `frontend/src/protocol.ts`
/// and `kProtocolVersion` in `src/service/main.cpp`.
pub const PROTOCOL_VERSION: u32 = 7;

/// The first protocol whose machines take power actions.
pub const POWER_PROTOCOL: u32 = 3;

/// The first protocol whose machines list their output devices and let a
/// viewer choose one.
pub const AUDIO_DEVICES_PROTOCOL: u32 = 5;

/// The first protocol whose machines answer a ping.
pub const PING_PROTOCOL: u32 = 5;

/// The first protocol whose machines show their config and let the owner
/// change it.
pub const CONFIG_PROTOCOL: u32 = 6;

/// The first protocol whose machines take a quality preset from a viewer,
/// say what they stream at, and follow the relay's bitrate on Auto.
pub const QUALITY_PROTOCOL: u32 = 7;

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
        /// The service's release, e.g. "1.0.0", shown to the owner.
        #[serde(default)]
        version: Option<String>,
        /// The protocol the machine speaks; absent from one older than it.
        #[serde(default)]
        protocol: Option<u32>,
    },
    /// The release the machine's updater found and is waiting to install
    /// (the machine's config says to ask first), or None once there's none.
    UpdateStatus {
        #[serde(default)]
        available: Option<String>,
    },
    Proof {
        /// Base64 ECDSA P-256 signature, r||s, over
        /// [`machine_auth_message`] for the challenge.
        signature: String,
    },
    /// The machine accepted a viewer: its signed half of the key exchange,
    /// and the stream key wrapped for that viewer alone. `clipboard` is what
    /// the machine's config lets this viewer do with its clipboard ("off",
    /// "pull" or "sync"), for the dashboard's buttons; absent from a machine
    /// that predates it.
    ViewerAccept {
        viewer: u64,
        statement: String,
        signature: String,
        wrapped_key: String,
        #[serde(default)]
        clipboard: Option<String>,
        /// Whether this viewer may send and fetch files.
        #[serde(default)]
        files: Option<bool>,
        /// Whether this viewer may open shells.
        #[serde(default)]
        shell: Option<bool>,
        /// Whether this viewer may read the machine's analytics.
        #[serde(default)]
        analytics: Option<bool>,
    },
    /// The machine refused a viewer (no valid grant, revoked, expired...).
    ViewerReject { viewer: u64, reason: String },
    /// A new stream key, wrapped for one viewer: sent to every remaining
    /// viewer when one leaves, so the one who left can't read what follows.
    StreamKey { viewer: u64, wrapped_key: String },
    /// Clipboard text sealed for one viewer: the answer to its request, or
    /// a copy made on the machine (sync mode). The relay can't read it.
    Clipboard { viewer: u64, sealed: String },
    /// A file-channel message sealed for one viewer: a listing, a transfer's
    /// progress, or a chunk of file data. Queued apart from everything else.
    File { viewer: u64, sealed: String },
    /// A shell-channel message sealed for one viewer: a shell's output, or
    /// that it opened or exited. Queued with file data.
    Shell { viewer: u64, sealed: String },
    /// A metrics-channel message sealed for one viewer: a sample, a range of
    /// history, the process list. Queued with file data.
    Metrics { viewer: u64, sealed: String },
    /// The machine's output devices, sealed for one viewer: the answer to
    /// its asking for them, or to its choosing one.
    Audio { viewer: u64, sealed: String },
    /// The machine's config and its schema, sealed for one viewer: the
    /// answer to its asking, or to its changing it.
    Config { viewer: u64, sealed: String },
    /// The echo of a viewer's ping, for its round trip.
    Pong { viewer: u64, nonce: String },
    /// What the stream is encoded at now: the preset (a viewer's choice,
    /// or the machine's config), its bitrate in bits per second (Auto's
    /// current target) and frame rate. Sent when capture starts and
    /// whenever one of them changes. Not sealed: the relay sees roughly
    /// this from the frames' sizes anyway, and runs Auto on it.
    Quality { preset: Preset, bitrate: u32, fps: u32 },
    /// The machine is about to restart (or shut down): Windows has accepted
    /// it, and the connection drops shortly. Only ever about the machine
    /// itself, so nothing a viewer could be misled by.
    GoingDown {
        #[serde(default)]
        restart: bool,
    },
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
    /// `audio`: this relay passes the machine's sound on, so it may send
    /// it. A machine never sends it to a relay that didn't say so, whose
    /// dashboards would take it for video.
    StartCapture { audio: bool },
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
    /// A clipboard request sealed by the viewer (set or get); the machine
    /// decides whether the viewer's role and its config allow it.
    Clipboard { viewer: u64, sealed: String },
    /// A file-channel message sealed by the viewer (list, offer, a chunk of
    /// an upload, fetch, ack, cancel). Only passed on for control.
    File { viewer: u64, sealed: String },
    /// A shell-channel message sealed by the viewer (open, keystrokes,
    /// resize, ack, close). Only passed on for roles that may open shells.
    Shell { viewer: u64, sealed: String },
    /// A metrics-channel request sealed by the viewer. Only passed on for
    /// the owner and shares with analytics.
    Metrics { viewer: u64, sealed: String },
    /// A power action (lock, sign out, restart, shut down) sealed by the
    /// viewer. Only passed on for control, elevated; the machine checks the
    /// role again before acting on it.
    Power { viewer: u64, sealed: String },
    /// A request for the output devices, sealed by the viewer. Passed on
    /// for anyone watching; the machine checks the role.
    AudioDevices { viewer: u64, sealed: String },
    /// A choice of output device, sealed by the viewer. Only passed on for
    /// control, elevated; the machine checks the role again.
    AudioSelect { viewer: u64, sealed: String },
    /// A request for the config, sealed by the viewer. Passed on for
    /// control and the owner; the machine checks the role.
    ConfigGet { viewer: u64, sealed: String },
    /// A change to the config, sealed by the viewer. Only passed on for the
    /// owner, elevated; the machine checks the role again, and every value.
    ConfigSet { viewer: u64, sealed: String },
    /// A viewer's ping, for the machine to echo straight back as a pong.
    Ping { viewer: u64, nonce: String },
    /// A quality preset, sealed by the viewer. Only passed on for control
    /// (no fresh factor needed: it changes nothing but the picture); the
    /// machine checks the role again.
    Quality { viewer: u64, sealed: String },
    /// Auto's new target, in bits per second, from the relay's controller
    /// (crate::quality). The machine ignores it on any other preset and
    /// keeps it within Auto's range: all a relay could do with it is make
    /// the picture worse, which it can by dropping frames anyway.
    Bitrate { bitrate: u32 },
    /// Every revocation the owner has signed for this machine.
    Revocations { revocations: Vec<SignedView> },
    /// The owner asks the machine to install the update it's holding now.
    /// The machine still checks the release's signature, and only ever
    /// moves forward, so a relay sending this on its own gains nothing.
    InstallUpdate,
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
/// A sealed power request: counter, one byte saying which action, and the
/// tag, in base64.
pub const MAX_SEALED_POWER_LEN: usize = (8 + 1 + 16_usize).div_ceil(3) * 4;
/// A sealed clipboard message, either way: counter, one byte saying what it
/// is, up to 256 KB of text and the tag, in base64.
pub const MAX_SEALED_CLIPBOARD_LEN: usize = (8 + 1 + 256 * 1024 + 16_usize).div_ceil(3) * 4;
/// A sealed file-channel message, either way: counter, op, header length,
/// a header of up to 64 KB (a listing) and up to 64 KB of file data, and
/// the tag, in base64.
pub const MAX_SEALED_FILE_LEN: usize = (8 + 3 + 65_535 + 65_536 + 16_usize).div_ceil(3) * 4;
/// A sealed shell-channel message, either way: counter, op, header length,
/// a small header, up to 16 KB of terminal bytes, and the tag, in base64.
pub const MAX_SEALED_SHELL_LEN: usize = (8 + 3 + 1024 + 16 * 1024 + 16_usize).div_ceil(3) * 4;
/// A sealed metrics-channel message from the machine: counter, op, header
/// length, a small header, a JSON body of up to 512 KB (a history range,
/// the process list), and the tag, in base64.
pub const MAX_SEALED_METRICS_LEN: usize = (8 + 3 + 1024 + 512 * 1024 + 16_usize).div_ceil(3) * 4;
/// A viewer's metrics request: only a small header.
pub const MAX_SEALED_METRICS_REQUEST_LEN: usize = (8 + 3 + 1024 + 16_usize).div_ceil(3) * 4;
/// A viewer's audio request: counter, an endpoint id (or nothing), and the
/// tag, in base64.
pub const MAX_SEALED_AUDIO_REQUEST_LEN: usize = (8 + 256 + 16_usize).div_ceil(3) * 4;
/// The machine's device list: counter, op, header length, a JSON header
/// of up to 64 KB, and the tag, in base64.
pub const MAX_SEALED_AUDIO_LEN: usize = (8 + 3 + 65_535 + 16_usize).div_ceil(3) * 4;
/// A viewer's config request: counter, a JSON change of up to 16 KB (or
/// nothing, to read it), and the tag, in base64.
pub const MAX_SEALED_CONFIG_REQUEST_LEN: usize = (8 + 16 * 1024 + 16_usize).div_ceil(3) * 4;
/// The machine's config: counter, op, header length, a JSON header of up to
/// 64 KB, and the tag, in base64.
pub const MAX_SEALED_CONFIG_LEN: usize = (8 + 3 + 65_535 + 16_usize).div_ceil(3) * 4;
/// A viewer's quality preset: counter, its name, and the tag, in base64.
pub const MAX_SEALED_QUALITY_LEN: usize = (8 + 16 + 16_usize).div_ceil(3) * 4;
/// A ping's nonce, either way: a counter, in decimal.
pub const MAX_PING_NONCE_LEN: usize = 32;
/// What the machine sends a viewer: a signed accept and a wrapped key.
const MAX_ANSWER_LEN: usize = 2048;

/// What the machine said a viewer may do with its clipboard, as the
/// dashboard is told it: anything unexpected (or nothing) is "off".
pub fn clipboard_access(said: Option<&str>) -> &'static str {
    match said {
        Some("pull") => "pull",
        Some("sync") => "sync",
        _ => "off",
    }
}

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
    /// Asks for input, files and shells on the view of this machine, which
    /// takes a recently proved second factor; answered with an elevation.
    Elevate { device_id: String },
    /// Sealed for the machine. Only passed on while viewing the machine
    /// with a control (or owner) role; the machine checks that again.
    Input { device_id: String, sealed: String },
    /// A sealed clipboard request. Passed on while viewing the machine with
    /// any role: whether a view share may read the clipboard is the
    /// machine's config to say, and the machine checks every request.
    Clipboard { device_id: String, sealed: String },
    /// A sealed file-channel message. Only passed on while viewing the
    /// machine with a control (or owner) role.
    File { device_id: String, sealed: String },
    /// A sealed shell-channel message. Only passed on while viewing the
    /// machine with a role that may open shells (dev or owner).
    Shell { device_id: String, sealed: String },
    /// A sealed metrics request. Only passed on while viewing the machine
    /// as its owner, or with a share that allows analytics.
    Metrics { device_id: String, sealed: String },
    /// A sealed power action. Only passed on while viewing the machine
    /// with a control (or owner) role, elevated.
    Power { device_id: String, sealed: String },
    /// A sealed request for the output devices. Only passed on while
    /// viewing the machine.
    AudioDevices { device_id: String, sealed: String },
    /// A sealed choice of output device. Only passed on while viewing the
    /// machine with a control (or owner) role, elevated.
    AudioSelect { device_id: String, sealed: String },
    /// A sealed request for the machine's config. Only passed on while
    /// viewing the machine with a control (or owner) role.
    ConfigGet { device_id: String, sealed: String },
    /// A sealed change to the config. Only passed on while viewing the
    /// machine as its owner, elevated.
    ConfigSet { device_id: String, sealed: String },
    /// Asks the machine to echo `nonce` back, to time the round trip. Not
    /// sealed: it carries nothing. Only passed on while viewing the machine.
    Ping { device_id: String, nonce: String },
    /// A sealed quality preset. Only passed on while viewing the machine
    /// with a control (or owner) role.
    Quality { device_id: String, sealed: String },
    /// The owner asks the machine to install the update it's holding.
    InstallUpdate { device_id: String },
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
    /// May read the machine's analytics: always for the owner.
    pub analytics: bool,
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
    /// Owner only, while online: the service's release, and a newer one
    /// its updater found and is holding until the owner says so.
    pub version: Option<String>,
    pub update_available: Option<String>,
    /// The machine said it's restarting, and hasn't come back yet. Cleared
    /// when it reconnects, or some minutes on if it doesn't.
    pub restarting: bool,
    /// While online: the machine takes power actions, and this user's role
    /// may ask for them.
    pub power: bool,
    /// While online: the machine lists its output devices, and lets
    /// control choose one.
    pub audio_devices: bool,
    /// While online: the machine answers pings.
    pub ping: bool,
    /// While online: the machine shows its config to this user's role
    /// (control or owner), and lets the owner change it.
    pub config: bool,
    /// While online: the machine takes a quality preset from this user's
    /// role (control or owner).
    pub quality: bool,
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
    ViewAccepted {
        device_id: String,
        statement: String,
        signature: String,
        wrapped_key: String,
        /// "off", "pull" or "sync": what the machine lets this viewer do
        /// with its clipboard. Only for showing the right buttons.
        clipboard: &'static str,
        /// Whether the machine lets this viewer send and fetch files.
        files: bool,
        /// Whether the machine lets this viewer open shells.
        shell: bool,
        /// Whether the machine lets this viewer read its analytics.
        analytics: bool,
    },
    /// The machine refused to stream to this viewer.
    ViewRejected { device_id: String, reason: String },
    /// Whether this view passes on input, files and shells. When it doesn't,
    /// the dashboard asks for a code, steps up and sends elevate.
    Elevation { device_id: String, elevated: bool },
    /// The stream moved to a new key, wrapped for this viewer.
    StreamKey { device_id: String, wrapped_key: String },
    /// Clipboard text the machine sealed for this viewer.
    Clipboard { device_id: String, sealed: String },
    /// A file-channel message the machine sealed for this viewer.
    File { device_id: String, sealed: String },
    /// A shell-channel message the machine sealed for this viewer.
    Shell { device_id: String, sealed: String },
    /// A metrics-channel message the machine sealed for this viewer.
    Metrics { device_id: String, sealed: String },
    /// The machine's output devices, sealed for this viewer.
    Audio { device_id: String, sealed: String },
    /// The machine's config, sealed for this viewer.
    Config { device_id: String, sealed: String },
    /// The machine's echo of this dashboard's ping.
    Pong { device_id: String, nonce: String },
    /// What the stream this dashboard watches is encoded at (see
    /// DeviceMessage::Quality): when it starts watching, and on every change.
    Quality { device_id: String, preset: Preset, bitrate: u32, fps: u32 },
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

/// An Opus packet rather than video: the flag is in the clear, like the
/// keyframe one, so the relay can treat it apart.
pub fn is_audio(frame: &[u8]) -> bool {
    frame.get(1).is_some_and(|flags| flags & 0x02 != 0)
}

/// When the frame was captured, on the stream's clock: in the clear too,
/// for Auto to tell how long frames take to get here (crate::quality).
pub fn timestamp_us(frame: &[u8]) -> Option<i64> {
    frame.get(2..10).and_then(|bytes| bytes.try_into().ok()).map(i64::from_le_bytes)
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
    fn clipboard_messages_round_trip() {
        let command: DashboardCommand =
            serde_json::from_str(r#"{"type":"clipboard","deviceId":"m1","sealed":"AAAA"}"#).unwrap();
        assert!(matches!(command, DashboardCommand::Clipboard { .. }));
        let json = serde_json::to_value(DeviceCommand::Clipboard { viewer: 7, sealed: "x".into() }).unwrap();
        assert_eq!(json, serde_json::json!({"type":"clipboard","viewer":7,"sealed":"x"}));
        let message: DeviceMessage =
            serde_json::from_str(r#"{"type":"clipboard","viewer":3,"sealed":"AAAA"}"#).unwrap();
        assert!(matches!(message, DeviceMessage::Clipboard { viewer: 3, .. }));
        let json = serde_json::to_value(DashboardEvent::Clipboard { device_id: "m1".into(), sealed: "x".into() })
            .unwrap();
        assert_eq!(json, serde_json::json!({"type":"clipboard","deviceId":"m1","sealed":"x"}));
    }

    #[test]
    fn accepts_carry_clipboard_access() {
        let message: DeviceMessage = serde_json::from_str(
            r#"{"type":"viewer_accept","viewer":1,"statement":"s","signature":"g","wrapped_key":"k"}"#,
        )
        .unwrap();
        let DeviceMessage::ViewerAccept { clipboard, .. } = message else { panic!("not an accept") };
        assert_eq!(clipboard_access(clipboard.as_deref()), "off");
        assert_eq!(clipboard_access(Some("sync")), "sync");
        assert_eq!(clipboard_access(Some("everything")), "off");
    }

    /// What the machine allows reaches the dashboard: a field dropped here
    /// leaves its tab saying the machine refused.
    #[test]
    fn accepts_carry_what_the_machine_allows() {
        let message: DeviceMessage = serde_json::from_str(
            r#"{"type":"viewer_accept","viewer":1,"statement":"s","signature":"g","wrapped_key":"k",
                "files":true,"shell":true,"analytics":true}"#,
        )
        .unwrap();
        let DeviceMessage::ViewerAccept { files, shell, analytics, .. } = message else { panic!("not an accept") };
        let json = serde_json::to_value(DashboardEvent::ViewAccepted {
            device_id: "m1".into(),
            statement: "s".into(),
            signature: "g".into(),
            wrapped_key: "k".into(),
            clipboard: "off",
            files: files.unwrap_or(false),
            shell: shell.unwrap_or(false),
            analytics: analytics.unwrap_or(false),
        })
        .unwrap();
        assert_eq!(json["files"], true);
        assert_eq!(json["shell"], true);
        assert_eq!(json["analytics"], true);
    }

    /// The largest text the dashboard or the machine sends fits; a byte
    /// more of ciphertext doesn't.
    #[test]
    fn clipboard_cap_fits_the_largest_text() {
        let largest = BASE64.encode(vec![0u8; 8 + 1 + 256 * 1024 + 16]);
        assert!(largest.len() <= MAX_SEALED_CLIPBOARD_LEN);
        let over = BASE64.encode(vec![0u8; 8 + 1 + 256 * 1024 + 16 + 3]);
        assert!(over.len() > MAX_SEALED_CLIPBOARD_LEN);
    }

    #[test]
    fn file_messages_round_trip() {
        let command: DashboardCommand =
            serde_json::from_str(r#"{"type":"file","deviceId":"m1","sealed":"AAAA"}"#).unwrap();
        assert!(matches!(command, DashboardCommand::File { .. }));
        let message: DeviceMessage = serde_json::from_str(r#"{"type":"file","viewer":3,"sealed":"AAAA"}"#).unwrap();
        assert!(matches!(message, DeviceMessage::File { viewer: 3, .. }));
        let largest = BASE64.encode(vec![0u8; 8 + 3 + 65_535 + 65_536 + 16]);
        assert!(largest.len() <= MAX_SEALED_FILE_LEN);
    }

    #[test]
    fn shell_messages_round_trip() {
        let command: DashboardCommand =
            serde_json::from_str(r#"{"type":"shell","deviceId":"m1","sealed":"AAAA"}"#).unwrap();
        assert!(matches!(command, DashboardCommand::Shell { .. }));
        let message: DeviceMessage = serde_json::from_str(r#"{"type":"shell","viewer":3,"sealed":"AAAA"}"#).unwrap();
        assert!(matches!(message, DeviceMessage::Shell { viewer: 3, .. }));
        let largest = BASE64.encode(vec![0u8; 8 + 3 + 1024 + 16 * 1024 + 16]);
        assert!(largest.len() <= MAX_SEALED_SHELL_LEN);
    }

    #[test]
    fn config_messages_round_trip() {
        let command: DashboardCommand =
            serde_json::from_str(r#"{"type":"config_set","deviceId":"m1","sealed":"AAAA"}"#).unwrap();
        assert!(matches!(command, DashboardCommand::ConfigSet { .. }));
        let command: DashboardCommand =
            serde_json::from_str(r#"{"type":"config_get","deviceId":"m1","sealed":"AAAA"}"#).unwrap();
        assert!(matches!(command, DashboardCommand::ConfigGet { .. }));
        let json = serde_json::to_value(DeviceCommand::ConfigSet { viewer: 3, sealed: "x".into() }).unwrap();
        assert_eq!(json, serde_json::json!({"type":"config_set","viewer":3,"sealed":"x"}));
        let message: DeviceMessage = serde_json::from_str(r#"{"type":"config","viewer":3,"sealed":"AAAA"}"#).unwrap();
        assert!(matches!(message, DeviceMessage::Config { viewer: 3, .. }));
        let json = serde_json::to_value(DashboardEvent::Config { device_id: "m1".into(), sealed: "x".into() }).unwrap();
        assert_eq!(json, serde_json::json!({"type":"config","deviceId":"m1","sealed":"x"}));
        let largest = BASE64.encode(vec![0u8; 8 + 16 * 1024 + 16]);
        assert!(largest.len() <= MAX_SEALED_CONFIG_REQUEST_LEN);
    }

    #[test]
    fn pings_round_trip() {
        let command: DashboardCommand =
            serde_json::from_str(r#"{"type":"ping","deviceId":"m1","nonce":"7"}"#).unwrap();
        assert!(matches!(command, DashboardCommand::Ping { .. }));
        let json = serde_json::to_value(DeviceCommand::Ping { viewer: 3, nonce: "7".into() }).unwrap();
        assert_eq!(json, serde_json::json!({"type":"ping","viewer":3,"nonce":"7"}));
        let message: DeviceMessage = serde_json::from_str(r#"{"type":"pong","viewer":3,"nonce":"7"}"#).unwrap();
        assert!(matches!(message, DeviceMessage::Pong { viewer: 3, .. }));
        let json = serde_json::to_value(DashboardEvent::Pong { device_id: "m1".into(), nonce: "7".into() }).unwrap();
        assert_eq!(json, serde_json::json!({"type":"pong","deviceId":"m1","nonce":"7"}));
    }

    #[test]
    fn quality_round_trips() {
        let command: DashboardCommand =
            serde_json::from_str(r#"{"type":"quality","deviceId":"m1","sealed":"AAAA"}"#).unwrap();
        assert!(matches!(command, DashboardCommand::Quality { .. }));
        let json = serde_json::to_value(DeviceCommand::Bitrate { bitrate: 2_000_000 }).unwrap();
        assert_eq!(json, serde_json::json!({"type":"bitrate","bitrate":2_000_000}));
        let message: DeviceMessage =
            serde_json::from_str(r#"{"type":"quality","preset":"auto","bitrate":4000000,"fps":60}"#).unwrap();
        assert!(matches!(message, DeviceMessage::Quality { preset: Preset::Auto, bitrate: 4_000_000, fps: 60 }));
        assert!(serde_json::from_str::<DeviceMessage>(r#"{"type":"quality","preset":"x","bitrate":1,"fps":1}"#).is_err());
        let event = DashboardEvent::Quality { device_id: "m1".into(), preset: Preset::Low, bitrate: 1_000_000, fps: 30 };
        assert_eq!(
            serde_json::to_value(event).unwrap(),
            serde_json::json!({"type":"quality","deviceId":"m1","preset":"low","bitrate":1_000_000,"fps":30})
        );
    }

    #[test]
    fn frames_say_when_they_were_captured() {
        let mut frame = vec![2, 1];
        frame.extend_from_slice(&1_234_567_i64.to_le_bytes());
        frame.push(9);
        assert_eq!(timestamp_us(&frame), Some(1_234_567));
        assert_eq!(timestamp_us(&frame[..9]), None);
    }

    #[test]
    fn oversized_statements_are_refused() {
        let view = SignedView { statement: "x".repeat(MAX_STATEMENT_LEN + 1), signature: String::new() };
        assert!(view.decode().is_none());
        let view = SignedView { statement: "ok".into(), signature: "not base64!".into() };
        assert!(view.decode().is_none());
    }
}
