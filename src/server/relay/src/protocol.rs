//! Wire messages. The JSON shapes must stay identical to
//! `frontend/src/protocol.ts` and to the RelayCommand / hello parsing in
//! `src/service/main.cpp`.

use serde::{Deserialize, Serialize};

/// The first (and only text) message a device sends after connecting.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeviceMessage {
    Hello { machine_id: String },
}

/// Commands the relay sends down to a device to control capture.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeviceCommand {
    StartCapture,
    StopCapture,
}

/// Messages a dashboard sends up to start/stop watching a device's screen.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", rename_all_fields = "camelCase")]
pub enum DashboardCommand {
    StartView { device_id: String },
    StopView { device_id: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSnapshot {
    pub id: String,
    pub machine_id: String,
    pub connected_at: String, // RFC 3339
}

/// Messages pushed to connected dashboards.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", rename_all_fields = "camelCase")]
pub enum DashboardEvent {
    Snapshot { devices: Vec<DeviceSnapshot> },
    DeviceConnected { device: DeviceSnapshot },
    DeviceDisconnected { id: String },
    /// The device went away (or never had a capture running) while a
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
