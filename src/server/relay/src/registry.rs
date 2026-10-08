//! Live state: which devices are connected, which dashboards are open, and
//! which dashboards are watching which device. Nothing here is persisted; a
//! restart drops everyone back to "disconnected".

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::mpsc;

use crate::protocol::{DashboardEvent, DeviceCommand, DeviceSnapshot, is_keyframe};

pub type DashboardId = u64;

/// What the relay pushes to a dashboard's socket task besides frames.
pub enum Outbound {
    Event(DashboardEvent),
    /// The session behind this dashboard ended (logout, account disabled):
    /// close the socket.
    Close,
}

/// How a dashboard's socket task is reached, and who is behind it. Events
/// are rare and must not be lost, so their queue is unbounded; frames are
/// bounded so a slow viewer can't make the relay buffer video without limit.
#[derive(Clone)]
pub struct DashboardHandle {
    pub events: mpsc::UnboundedSender<Outbound>,
    pub frames: mpsc::Sender<Bytes>,
    pub user_id: i64,
    pub session_id: i64,
    /// Until machines have owners, only the admin may see or view devices.
    pub sees_devices: bool,
}

impl DashboardHandle {
    fn send(&self, event: DashboardEvent) {
        let _ = self.events.send(Outbound::Event(event));
    }
}

struct Viewer {
    frames: mpsc::Sender<Bytes>,
    // Set for a new viewer and whenever its queue overflowed: a dropped
    // frame breaks every delta after it, so skip ahead to the next keyframe.
    awaiting_keyframe: bool,
}

struct Device {
    machine_id: String,
    connected_at: OffsetDateTime,
    commands: mpsc::UnboundedSender<DeviceCommand>,
    viewers: HashMap<DashboardId, Viewer>,
}

impl Device {
    fn snapshot(&self, id: &str) -> DeviceSnapshot {
        DeviceSnapshot {
            id: id.to_owned(),
            machine_id: self.machine_id.clone(),
            connected_at: self.connected_at.format(&Rfc3339).unwrap_or_default(),
        }
    }
}

#[derive(Default)]
struct Inner {
    devices: HashMap<String, Device>,
    dashboards: HashMap<DashboardId, DashboardHandle>,
}

impl Inner {
    /// Device connect/disconnect events, to the dashboards allowed to see devices.
    fn broadcast(&self, event: &DashboardEvent) {
        for dashboard in self.dashboards.values().filter(|dashboard| dashboard.sees_devices) {
            dashboard.send(event.clone());
        }
    }

    fn remove_dashboard(&mut self, id: DashboardId) -> Option<DashboardHandle> {
        let handle = self.dashboards.remove(&id)?;
        for device in self.devices.values_mut() {
            detach(device, id);
        }
        Some(handle)
    }

    /// Detaches and closes every dashboard matching `predicate`.
    fn close_where(&mut self, predicate: impl Fn(&DashboardHandle) -> bool) {
        let ids: Vec<DashboardId> =
            self.dashboards.iter().filter(|(_, handle)| predicate(handle)).map(|(id, _)| *id).collect();
        for id in ids {
            if let Some(handle) = self.remove_dashboard(id) {
                let _ = handle.events.send(Outbound::Close);
            }
        }
    }
}

#[derive(Default)]
pub struct Registry {
    inner: Mutex<Inner>,
    next_dashboard_id: AtomicU64,
}

impl Registry {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding the lock leaves plain maps behind, which are
        // still consistent enough to keep serving.
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn snapshot(&self) -> Vec<DeviceSnapshot> {
        let inner = self.lock();
        inner.devices.iter().map(|(id, device)| device.snapshot(id)).collect()
    }

    pub fn add_device(&self, machine_id: String, commands: mpsc::UnboundedSender<DeviceCommand>) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let device = Device { machine_id, connected_at: OffsetDateTime::now_utc(), commands, viewers: HashMap::new() };
        let mut inner = self.lock();
        inner.broadcast(&DashboardEvent::DeviceConnected { device: device.snapshot(&id) });
        inner.devices.insert(id.clone(), device);
        id
    }

    pub fn remove_device(&self, id: &str) {
        let mut inner = self.lock();
        let Some(device) = inner.devices.remove(id) else { return };
        // Let anyone watching tear down their decoder; the frames stop here.
        for dashboard_id in device.viewers.keys() {
            if let Some(dashboard) = inner.dashboards.get(dashboard_id) {
                dashboard.send(DashboardEvent::CaptureEnded { device_id: id.to_owned() });
            }
        }
        inner.broadcast(&DashboardEvent::DeviceDisconnected { id: id.to_owned() });
    }

    /// Registers a dashboard and queues its initial snapshot under the same
    /// lock, so no connect/disconnect event can slip in before it.
    pub fn add_dashboard(&self, handle: DashboardHandle) -> DashboardId {
        let id = self.next_dashboard_id.fetch_add(1, Ordering::Relaxed);
        let mut inner = self.lock();
        let devices = if handle.sees_devices {
            inner.devices.iter().map(|(device_id, device)| device.snapshot(device_id)).collect()
        } else {
            Vec::new()
        };
        handle.send(DashboardEvent::Snapshot { devices });
        inner.dashboards.insert(id, handle);
        id
    }

    /// Drops a dashboard and detaches it from every device it was watching.
    pub fn remove_dashboard(&self, id: DashboardId) {
        self.lock().remove_dashboard(id);
    }

    /// Closes the dashboards opened with this session (on logout).
    pub fn close_session(&self, session_id: i64) {
        self.lock().close_where(|handle| handle.session_id == session_id);
    }

    /// Closes every dashboard of this user (account disabled).
    pub fn close_user(&self, user_id: i64) {
        self.lock().close_where(|handle| handle.user_id == user_id);
    }

    /// The first viewer makes the device start capturing; later viewers just
    /// attach to the stream. Returns false if the device isn't connected or
    /// this dashboard may not view it.
    pub fn start_view(&self, dashboard: DashboardId, device_id: &str) -> bool {
        let mut inner = self.lock();
        let Some(frames) = inner
            .dashboards
            .get(&dashboard)
            .filter(|handle| handle.sees_devices)
            .map(|handle| handle.frames.clone())
        else {
            return false;
        };
        let Some(device) = inner.devices.get_mut(device_id) else { return false };
        let was_idle = device.viewers.is_empty();
        device.viewers.insert(dashboard, Viewer { frames, awaiting_keyframe: true });
        if was_idle {
            let _ = device.commands.send(DeviceCommand::StartCapture);
        }
        true
    }

    pub fn stop_view(&self, dashboard: DashboardId, device_id: &str) {
        let mut inner = self.lock();
        if let Some(device) = inner.devices.get_mut(device_id) {
            detach(device, dashboard);
        }
    }

    /// Fans one video frame out to the device's viewers without blocking: a
    /// viewer whose queue is full loses frames until the next keyframe.
    pub fn forward_frame(&self, device_id: &str, frame: Bytes) {
        let keyframe = is_keyframe(&frame);
        let mut inner = self.lock();
        let Some(device) = inner.devices.get_mut(device_id) else { return };
        for viewer in device.viewers.values_mut() {
            if viewer.awaiting_keyframe && !keyframe {
                continue;
            }
            viewer.awaiting_keyframe = viewer.frames.try_send(frame.clone()).is_err();
        }
    }
}

/// The last viewer leaving stops capture on the device.
fn detach(device: &mut Device, dashboard: DashboardId) {
    if device.viewers.remove(&dashboard).is_some() && device.viewers.is_empty() {
        let _ = device.commands.send(DeviceCommand::StopCapture);
    }
}
