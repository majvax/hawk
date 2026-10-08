//! Live state: which machines are connected, which dashboards are open, what
//! each dashboard's user may access, and who is watching what. The database
//! is the source of truth for access; API handlers mirror every change into
//! the registry so open dashboards update (and lose access) immediately.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::mpsc;

use crate::db::{MachineRow, Role};
use crate::protocol::{DashboardEvent, DeviceCommand, InputEvent, MachineView, is_keyframe};

pub type DashboardId = u64;

/// What the relay pushes to a dashboard's socket task besides frames.
pub enum Outbound {
    Event(Box<DashboardEvent>),
    /// The session behind this dashboard ended (logout, account disabled):
    /// close the socket.
    Close,
}

/// What the relay pushes to a device's socket task.
pub enum DeviceOutbound {
    Command(DeviceCommand),
    /// Disconnect the device (machine removed, owner disabled, replaced by a
    /// newer connection with the same credential).
    Close(u16, &'static str),
}

/// A viewer of a single-view share stopped watching. `immediate` when they
/// pressed stop; otherwise their dashboard went away, and the share is only
/// used up if they don't come back to it (see machines::spawn_single_view_watch).
pub struct ViewEnded {
    pub user_id: i64,
    pub machine_id: String,
    pub immediate: bool,
}

/// How a dashboard's socket task is reached, and who is behind it. Events
/// are rare and must not be lost, so their queue is unbounded; frames are
/// bounded so a slow viewer can't make the relay buffer video without limit.
pub struct DashboardHandle {
    pub events: mpsc::UnboundedSender<Outbound>,
    pub frames: mpsc::Sender<Bytes>,
    pub user_id: i64,
    pub session_id: i64,
    pub email: String,
}

impl DashboardHandle {
    fn send(&self, event: DashboardEvent) {
        let _ = self.events.send(Outbound::Event(Box::new(event)));
    }
}

struct Dashboard {
    handle: DashboardHandle,
    /// Machines this dashboard's user may access, by machine id.
    access: HashMap<String, MachineRow>,
}

struct Viewer {
    frames: mpsc::Sender<Bytes>,
    email: String,
    // Set for a new viewer and whenever its queue overflowed: a dropped
    // frame breaks every delta after it, so skip ahead to the next keyframe.
    awaiting_keyframe: bool,
    /// This viewer has sent input, so it may have keys or buttons held down
    /// on the machine that must be released when it stops controlling.
    sent_input: bool,
}

struct Device {
    /// Distinguishes this connection from a newer one for the same machine.
    connection: u64,
    owner_id: i64,
    connected_at: OffsetDateTime,
    outbound: mpsc::UnboundedSender<DeviceOutbound>,
    viewers: HashMap<DashboardId, Viewer>,
}

impl Device {
    fn send(&self, command: DeviceCommand) {
        let _ = self.outbound.send(DeviceOutbound::Command(command));
    }
}

#[derive(Default)]
struct Inner {
    devices: HashMap<String, Device>,
    dashboards: HashMap<DashboardId, Dashboard>,
    /// Where single-view endings are reported; unset in a registry that
    /// nothing listens to.
    view_ended: Option<mpsc::UnboundedSender<ViewEnded>>,
}

impl Inner {
    fn view(&self, row: &MachineRow) -> MachineView {
        let device = self.devices.get(&row.public_id);
        MachineView {
            id: row.public_id.clone(),
            name: row.name.clone(),
            hostname: row.hostname.clone(),
            owner_email: row.owner_email.clone(),
            role: row.role,
            online: device.is_some(),
            connected_at: device.map(|device| device.connected_at.format(&Rfc3339).unwrap_or_default()),
            last_seen_at: row.last_seen_at,
            key_storage: row.key_storage.clone(),
            access_expires_at: row.share_expires_at,
            single_view: row.single_view,
            viewers: (row.role == Role::Owner).then(|| {
                let mut emails: Vec<String> = device
                    .map(|device| device.viewers.values().map(|viewer| viewer.email.clone()).collect())
                    .unwrap_or_default();
                emails.sort();
                emails.dedup();
                emails
            }),
        }
    }

    /// Re-sends the machine to every dashboard that can access it.
    fn publish(&self, machine_id: &str) {
        for dashboard in self.dashboards.values() {
            if let Some(row) = dashboard.access.get(machine_id) {
                dashboard.handle.send(DashboardEvent::MachineUpdated { machine: self.view(row) });
            }
        }
    }

    /// Stops `dashboard` watching `machine_id`. The last viewer leaving stops
    /// capture on the device. Returns whether it was watching.
    fn detach(&mut self, dashboard: DashboardId, machine_id: &str) -> bool {
        let Some(device) = self.devices.get_mut(machine_id) else { return false };
        let Some(viewer) = device.viewers.remove(&dashboard) else { return false };
        if viewer.sent_input {
            device.send(DeviceCommand::ReleaseInput);
        }
        if device.viewers.is_empty() {
            device.send(DeviceCommand::StopCapture);
        }
        self.publish(machine_id); // the owner's viewer list changed
        true
    }

    /// Takes `machine_id` away from one dashboard.
    fn revoke_dashboard(&mut self, dashboard_id: DashboardId, machine_id: &str) {
        let Some(dashboard) = self.dashboards.get_mut(&dashboard_id) else { return };
        if dashboard.access.remove(machine_id).is_none() {
            return;
        }
        let was_viewing = self.detach(dashboard_id, machine_id);
        if let Some(dashboard) = self.dashboards.get(&dashboard_id) {
            if was_viewing {
                dashboard.handle.send(DashboardEvent::CaptureEnded { device_id: machine_id.to_owned() });
            }
            dashboard.handle.send(DashboardEvent::MachineRemoved { id: machine_id.to_owned() });
        }
    }

    fn remove_dashboard(&mut self, id: DashboardId) -> Option<Dashboard> {
        let dashboard = self.dashboards.remove(&id)?;
        for (machine_id, row) in &dashboard.access {
            if self.detach(id, machine_id) && row.single_view {
                self.report_view_ended(dashboard.handle.user_id, machine_id, false);
            }
        }
        Some(dashboard)
    }

    fn report_view_ended(&self, user_id: i64, machine_id: &str, immediate: bool) {
        if let Some(view_ended) = &self.view_ended {
            let _ = view_ended.send(ViewEnded { user_id, machine_id: machine_id.to_owned(), immediate });
        }
    }

    fn close_dashboards_where(&mut self, predicate: impl Fn(&DashboardHandle) -> bool) {
        let ids: Vec<DashboardId> =
            self.dashboards.iter().filter(|(_, dashboard)| predicate(&dashboard.handle)).map(|(id, _)| *id).collect();
        for id in ids {
            if let Some(dashboard) = self.remove_dashboard(id) {
                let _ = dashboard.handle.events.send(Outbound::Close);
            }
        }
    }

    /// Drops a device connection and tells its viewers the stream ended.
    fn drop_device(&mut self, machine_id: &str) -> Option<Device> {
        let device = self.devices.remove(machine_id)?;
        for dashboard_id in device.viewers.keys() {
            if let Some(dashboard) = self.dashboards.get(dashboard_id) {
                dashboard.handle.send(DashboardEvent::CaptureEnded { device_id: machine_id.to_owned() });
            }
        }
        Some(device)
    }
}

#[derive(Default)]
pub struct Registry {
    inner: Mutex<Inner>,
    next_id: AtomicU64,
}

impl Registry {
    /// A registry that reports single-view endings to `view_ended`.
    pub fn new(view_ended: mpsc::UnboundedSender<ViewEnded>) -> Self {
        Self { inner: Mutex::new(Inner { view_ended: Some(view_ended), ..Inner::default() }), next_id: AtomicU64::new(0) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding the lock leaves plain maps behind, which are
        // still consistent enough to keep serving.
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    // ---- devices ----------------------------------------------------------

    /// Registers an authenticated machine connection and returns its
    /// connection id. A previous connection for the same machine is closed.
    pub fn add_device(
        &self,
        machine_id: &str,
        owner_id: i64,
        outbound: mpsc::UnboundedSender<DeviceOutbound>,
    ) -> u64 {
        let connection = self.next_id();
        let mut inner = self.lock();
        if let Some(previous) = inner.drop_device(machine_id) {
            let _ = previous.outbound.send(DeviceOutbound::Close(1008, "replaced by a newer connection"));
        }
        let device = Device {
            connection,
            owner_id,
            connected_at: OffsetDateTime::now_utc(),
            outbound,
            viewers: HashMap::new(),
        };
        inner.devices.insert(machine_id.to_owned(), device);
        inner.publish(machine_id);
        connection
    }

    /// Unregisters a machine connection (if it's still the current one) and
    /// records when it was last seen.
    pub fn remove_device(&self, machine_id: &str, connection: u64, last_seen_at: i64) {
        let mut inner = self.lock();
        if inner.devices.get(machine_id).is_none_or(|device| device.connection != connection) {
            return;
        }
        inner.drop_device(machine_id);
        for dashboard in inner.dashboards.values_mut() {
            if let Some(row) = dashboard.access.get_mut(machine_id) {
                row.last_seen_at = Some(last_seen_at);
            }
        }
        inner.publish(machine_id);
    }

    /// Fans one video frame out to the machine's viewers without blocking: a
    /// viewer whose queue is full loses frames until the next keyframe.
    pub fn forward_frame(&self, machine_id: &str, frame: Bytes) {
        let keyframe = is_keyframe(&frame);
        let mut inner = self.lock();
        let Some(device) = inner.devices.get_mut(machine_id) else { return };
        for viewer in device.viewers.values_mut() {
            if viewer.awaiting_keyframe && !keyframe {
                continue;
            }
            viewer.awaiting_keyframe = viewer.frames.try_send(frame.clone()).is_err();
        }
    }

    // ---- dashboards -------------------------------------------------------

    /// Registers a dashboard with the machines its user may access, and
    /// queues its initial snapshot under the same lock, so no update can
    /// slip in before it.
    pub fn add_dashboard(&self, handle: DashboardHandle, machines: Vec<MachineRow>) -> DashboardId {
        let id = self.next_id();
        let mut inner = self.lock();
        let snapshot = machines.iter().map(|row| inner.view(row)).collect();
        handle.send(DashboardEvent::Snapshot { machines: snapshot });
        let access = machines.into_iter().map(|row| (row.public_id.clone(), row)).collect();
        inner.dashboards.insert(id, Dashboard { handle, access });
        id
    }

    /// Drops a dashboard and detaches it from everything it was watching.
    pub fn remove_dashboard(&self, id: DashboardId) {
        self.lock().remove_dashboard(id);
    }

    /// Closes the dashboards opened with this session (logout).
    pub fn close_session(&self, session_id: i64) {
        self.lock().close_dashboards_where(|handle| handle.session_id == session_id);
    }

    /// Closes the user's dashboards opened with any session but `keep`
    /// (signed out everywhere else, or the password changed).
    pub fn close_other_sessions(&self, user_id: i64, keep: i64) {
        self.lock().close_dashboards_where(|handle| handle.user_id == user_id && handle.session_id != keep);
    }

    /// Account disabled: closes the user's dashboards and disconnects the
    /// machines they own.
    pub fn close_user(&self, user_id: i64) {
        let mut inner = self.lock();
        inner.close_dashboards_where(|handle| handle.user_id == user_id);
        let owned: Vec<String> = inner
            .devices
            .iter()
            .filter(|(_, device)| device.owner_id == user_id)
            .map(|(machine_id, _)| machine_id.clone())
            .collect();
        for machine_id in owned {
            if let Some(device) = inner.drop_device(&machine_id) {
                let _ = device.outbound.send(DeviceOutbound::Close(1008, "owner disabled"));
            }
            inner.publish(&machine_id);
        }
    }

    /// The first viewer makes the machine start capturing; later viewers just
    /// attach to the stream. Returns false if the machine is offline or this
    /// dashboard has no access to it.
    pub fn start_view(&self, dashboard_id: DashboardId, machine_id: &str) -> bool {
        let mut inner = self.lock();
        let Some(dashboard) = inner.dashboards.get(&dashboard_id) else { return false };
        if !dashboard.access.contains_key(machine_id) {
            return false;
        }
        let viewer = Viewer {
            frames: dashboard.handle.frames.clone(),
            email: dashboard.handle.email.clone(),
            awaiting_keyframe: true,
            sent_input: false,
        };
        let Some(device) = inner.devices.get_mut(machine_id) else { return false };
        let was_idle = device.viewers.is_empty();
        device.viewers.insert(dashboard_id, viewer);
        if was_idle {
            device.send(DeviceCommand::StartCapture);
        }
        inner.publish(machine_id);
        true
    }

    /// Forwards input to the machine if this dashboard may control it: its
    /// user has a control (or owner) role, and it's watching the machine
    /// right now. Returns whether it was forwarded.
    pub fn input(&self, dashboard_id: DashboardId, machine_id: &str, event: InputEvent) -> bool {
        let mut inner = self.lock();
        let may_control = inner
            .dashboards
            .get(&dashboard_id)
            .and_then(|dashboard| dashboard.access.get(machine_id))
            .is_some_and(|row| row.role >= Role::Control);
        if !may_control {
            return false;
        }
        let Some(device) = inner.devices.get_mut(machine_id) else { return false };
        let Some(viewer) = device.viewers.get_mut(&dashboard_id) else { return false };
        viewer.sent_input = true;
        device.send(DeviceCommand::Input { event });
        true
    }

    pub fn stop_view(&self, dashboard_id: DashboardId, machine_id: &str) {
        let mut inner = self.lock();
        let Some(dashboard) = inner.dashboards.get(&dashboard_id) else { return };
        let user_id = dashboard.handle.user_id;
        let single_view = dashboard.access.get(machine_id).is_some_and(|row| row.single_view);
        if inner.detach(dashboard_id, machine_id) && single_view {
            inner.report_view_ended(user_id, machine_id, true);
        }
    }

    /// Whether any open dashboard of `user_id` is watching the machine.
    pub fn is_watching(&self, user_id: i64, machine_id: &str) -> bool {
        let inner = self.lock();
        inner.devices.get(machine_id).is_some_and(|device| {
            device.viewers.keys().any(|id| inner.dashboards.get(id).is_some_and(|d| d.handle.user_id == user_id))
        })
    }

    // ---- access changes (mirrors of committed database changes) -----------

    /// `row.role` on `row.public_id` for every open dashboard of `user_id`:
    /// a new share, a changed role, or a newly enrolled machine.
    pub fn grant(&self, user_id: i64, row: &MachineRow) {
        let mut inner = self.lock();
        let ids: Vec<DashboardId> = inner
            .dashboards
            .iter()
            .filter(|(_, dashboard)| dashboard.handle.user_id == user_id)
            .map(|(id, _)| *id)
            .collect();
        for id in &ids {
            if let Some(dashboard) = inner.dashboards.get_mut(id) {
                dashboard.access.insert(row.public_id.clone(), row.clone());
            }
        }
        // Down to view only: whatever their input was holding is let go.
        if row.role < Role::Control
            && let Some(device) = inner.devices.get_mut(&row.public_id)
        {
            let mut released = false;
            for id in &ids {
                if let Some(viewer) = device.viewers.get_mut(id) {
                    released |= std::mem::take(&mut viewer.sent_input);
                }
            }
            if released {
                device.send(DeviceCommand::ReleaseInput);
            }
        }
        inner.publish(&row.public_id);
    }

    /// Takes the machine away from every open dashboard of `user_id`,
    /// stopping their view of it immediately.
    pub fn revoke(&self, user_id: i64, machine_id: &str) {
        let mut inner = self.lock();
        let ids: Vec<DashboardId> = inner
            .dashboards
            .iter()
            .filter(|(_, dashboard)| dashboard.handle.user_id == user_id)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            inner.revoke_dashboard(id, machine_id);
        }
    }

    pub fn rename(&self, machine_id: &str, name: &str) {
        let mut inner = self.lock();
        for dashboard in inner.dashboards.values_mut() {
            if let Some(row) = dashboard.access.get_mut(machine_id) {
                row.name = name.to_owned();
            }
        }
        inner.publish(machine_id);
    }

    /// The machine was deleted: disconnect it and take it away from everyone.
    pub fn remove_machine(&self, machine_id: &str) {
        let mut inner = self.lock();
        if let Some(device) = inner.drop_device(machine_id) {
            let _ = device.outbound.send(DeviceOutbound::Close(1008, "machine removed"));
        }
        let ids: Vec<DashboardId> = inner
            .dashboards
            .iter()
            .filter(|(_, dashboard)| dashboard.access.contains_key(machine_id))
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            inner.revoke_dashboard(id, machine_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{InputEvent, MouseButton};

    const MACHINE: &str = "machine-1";

    fn row(role: Role) -> MachineRow {
        MachineRow {
            public_id: MACHINE.to_owned(),
            owner_id: 1,
            owner_email: "owner@example.com".to_owned(),
            name: "desk".to_owned(),
            hostname: "desk".to_owned(),
            last_seen_at: None,
            key_storage: Some("tpm".to_owned()),
            role,
            share_expires_at: None,
            single_view: false,
        }
    }

    fn handle(user_id: i64) -> DashboardHandle {
        let (events, _) = mpsc::unbounded_channel();
        let (frames, _) = mpsc::channel(1);
        DashboardHandle { events, frames, user_id, session_id: user_id, email: format!("user{user_id}@example.com") }
    }

    /// A registry with the machine connected and one dashboard of `role`
    /// watching it, plus the receiving end of the device's commands (its
    /// start_capture already taken off).
    fn watching(role: Role) -> (Registry, DashboardId, mpsc::UnboundedReceiver<DeviceOutbound>) {
        let registry = Registry::default();
        let user_id = if role == Role::Owner { 1 } else { 2 };
        let dashboard = registry.add_dashboard(handle(user_id), vec![row(role)]);
        let (outbound, mut device_rx) = mpsc::unbounded_channel();
        registry.add_device(MACHINE, 1, outbound);
        assert!(registry.start_view(dashboard, MACHINE));
        assert!(matches!(device_rx.try_recv(), Ok(DeviceOutbound::Command(DeviceCommand::StartCapture))));
        (registry, dashboard, device_rx)
    }

    fn click() -> InputEvent {
        InputEvent::MouseButton { button: MouseButton::Left, down: true }
    }

    #[test]
    fn control_input_reaches_the_machine() {
        let (registry, dashboard, mut device_rx) = watching(Role::Control);
        assert!(registry.input(dashboard, MACHINE, click()));
        assert!(matches!(device_rx.try_recv(), Ok(DeviceOutbound::Command(DeviceCommand::Input { .. }))));
    }

    #[test]
    fn view_only_input_is_dropped() {
        let (registry, dashboard, mut device_rx) = watching(Role::View);
        assert!(!registry.input(dashboard, MACHINE, click()));
        assert!(device_rx.try_recv().is_err());
    }

    #[test]
    fn input_needs_an_open_view() {
        let (registry, dashboard, mut device_rx) = watching(Role::Control);
        registry.stop_view(dashboard, MACHINE);
        assert!(!registry.input(dashboard, MACHINE, click()));
        assert!(matches!(device_rx.try_recv(), Ok(DeviceOutbound::Command(DeviceCommand::StopCapture))));
    }

    /// Whatever a viewer's input is holding down is let go when they stop
    /// watching, before the machine is told to stop capturing.
    #[test]
    fn leaving_releases_input() {
        let (registry, dashboard, mut device_rx) = watching(Role::Control);
        assert!(registry.input(dashboard, MACHINE, click()));
        assert!(matches!(device_rx.try_recv(), Ok(DeviceOutbound::Command(DeviceCommand::Input { .. }))));

        registry.remove_dashboard(dashboard);
        assert!(matches!(device_rx.try_recv(), Ok(DeviceOutbound::Command(DeviceCommand::ReleaseInput))));
        assert!(matches!(device_rx.try_recv(), Ok(DeviceOutbound::Command(DeviceCommand::StopCapture))));
    }

    /// Nothing to release from a viewer who never sent any input.
    #[test]
    fn leaving_without_input_releases_nothing() {
        let (registry, dashboard, mut device_rx) = watching(Role::Control);
        registry.remove_dashboard(dashboard);
        assert!(matches!(device_rx.try_recv(), Ok(DeviceOutbound::Command(DeviceCommand::StopCapture))));
    }

    /// Dropped to view only mid-session: the keys their input was holding
    /// are released at once, and nothing more gets through.
    #[test]
    fn losing_control_releases_input() {
        let (registry, dashboard, mut device_rx) = watching(Role::Control);
        assert!(registry.input(dashboard, MACHINE, click()));
        assert!(matches!(device_rx.try_recv(), Ok(DeviceOutbound::Command(DeviceCommand::Input { .. }))));

        registry.grant(2, &row(Role::View));
        assert!(matches!(device_rx.try_recv(), Ok(DeviceOutbound::Command(DeviceCommand::ReleaseInput))));
        assert!(!registry.input(dashboard, MACHINE, click()));
        assert!(device_rx.try_recv().is_err());
    }
}
