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

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::auth::{self, STEP_UP_WINDOW};
use crate::db::{MachineRow, Role, Signed};
use crate::protocol::{
    AUDIO_DEVICES_PROTOCOL, DashboardEvent, DeviceCommand, MachineView, PING_PROTOCOL, POWER_PROTOCOL, SignedView, is_audio,
    is_keyframe,
};

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
    /// File and shell messages from machines: bounded like frames, and sent
    /// after both events and frames, so a download or a shell's output never
    /// holds up the picture. The machine keeps only a small window of each
    /// unacknowledged, so an honest one never fills it; what overflows is
    /// dropped, and the transfer stalls and is retried from where it got to.
    pub bulk: mpsc::Sender<DashboardEvent>,
    pub user_id: i64,
    pub session_id: i64,
    pub email: String,
    pub step_up: StepUp,
}

/// Where the session behind a dashboard stands on step-up: whether its
/// account has a second factor to prove, and when it last did.
#[derive(Debug, Clone, Copy, Default)]
pub struct StepUp {
    pub mfa: bool,
    pub at: Option<i64>,
}

impl StepUp {
    /// Whether control, files and shells may be opened right now.
    fn allows(self, now: i64) -> bool {
        !self.mfa || self.at.is_some_and(|at| now - at < STEP_UP_WINDOW)
    }
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
    // Whether this viewer's role watches the screen. A dev share is a
    // viewer for its shell and files only: it neither starts capture nor
    // gets frames (which it couldn't decrypt anyway: the machine never
    // gives it the stream key).
    video: bool,
    // Set for a new viewer and whenever its queue overflowed: a dropped
    // frame breaks every delta after it, so skip ahead to the next keyframe.
    awaiting_keyframe: bool,
    // Whether input, files and shells are passed on for this view: set when
    // the view starts or is elevated within the step-up window, and kept
    // until the view ends.
    elevated: bool,
}

struct Device {
    /// Distinguishes this connection from a newer one for the same machine.
    connection: u64,
    owner_id: i64,
    connected_at: OffsetDateTime,
    outbound: mpsc::UnboundedSender<DeviceOutbound>,
    viewers: HashMap<DashboardId, Viewer>,
    /// As the machine reports them: its release, and an update it holds.
    version: Option<String>,
    update_available: Option<String>,
    /// The protocol the machine said it speaks in its hello.
    protocol: u32,
}

/// What a machine says about itself in its hello.
#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    /// Its release, e.g. "1.0.0".
    pub version: Option<String>,
    /// The protocol it speaks; 0 for one older than the field.
    pub protocol: u32,
}

/// How long a machine that said it's restarting shows as such before it's
/// simply offline. A restart with updates to install can take a while.
pub const RESTART_GRACE: i64 = 10 * 60;

impl Device {
    fn send(&self, command: DeviceCommand) {
        let _ = self.outbound.send(DeviceOutbound::Command(command));
    }
}

/// What the machine sent for one of its viewers.
pub enum Answer {
    Accept {
        statement: String,
        signature: String,
        wrapped_key: String,
        clipboard: &'static str,
        files: bool,
        shell: bool,
        analytics: bool,
    },
    Reject { reason: String },
    StreamKey { wrapped_key: String },
    Clipboard { sealed: String },
    Pong { nonce: String },
}

#[derive(Default)]
struct Inner {
    devices: HashMap<String, Device>,
    /// Machines that said they're restarting: until when to show them so.
    /// Kept apart from `devices`, since they're mostly offline meanwhile.
    restarting: HashMap<String, i64>,
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
            analytics: row.analytics,
            viewers: (row.role == Role::Owner).then(|| {
                let mut emails: Vec<String> = device
                    .map(|device| device.viewers.values().map(|viewer| viewer.email.clone()).collect())
                    .unwrap_or_default();
                emails.sort();
                emails.dedup();
                emails
            }),
            public_key: row.public_key.as_ref().map(|key| BASE64.encode(key)),
            owner_public_key: row.owner_public_key.as_ref().map(|key| BASE64.encode(key)),
            endorsement: row.endorsement.as_ref().map(|signature| BASE64.encode(signature)),
            enroll_code_hash: row.enroll_code_hash.as_ref().map(|hash| BASE64.encode(hash)),
            enroll_binding: row.enroll_binding.as_ref().map(|binding| BASE64.encode(binding)),
            granted: row.role == Role::Owner || row.grant.is_some(),
            version: device.filter(|_| row.role == Role::Owner).and_then(|device| device.version.clone()),
            update_available: device
                .filter(|_| row.role == Role::Owner)
                .and_then(|device| device.update_available.clone()),
            restarting: self.restarting.get(&row.public_id).is_some_and(|until| *until > auth::now()),
            power: row.role.can_control() && device.is_some_and(|device| device.protocol >= POWER_PROTOCOL),
            audio_devices: device.is_some_and(|device| device.protocol >= AUDIO_DEVICES_PROTOCOL),
            ping: device.is_some_and(|device| device.protocol >= PING_PROTOCOL),
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

    /// Stops `dashboard` watching `machine_id`. The machine lets go of its
    /// input and rekeys the stream for whoever is left; the last viewer
    /// leaving stops capture. Returns whether it was watching.
    fn detach(&mut self, dashboard: DashboardId, machine_id: &str) -> bool {
        let Some(device) = self.devices.get_mut(machine_id) else { return false };
        let Some(left) = device.viewers.remove(&dashboard) else { return false };
        device.send(DeviceCommand::ViewerLeft { viewer: dashboard });
        if left.video && !device.viewers.values().any(|viewer| viewer.video) {
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
        info: DeviceInfo,
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
            version: info.version,
            update_available: None,
            protocol: info.protocol,
        };
        inner.devices.insert(machine_id.to_owned(), device);
        inner.restarting.remove(machine_id); // it's back
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
        let audio = is_audio(&frame);
        let mut inner = self.lock();
        let Some(device) = inner.devices.get_mut(machine_id) else { return };
        for viewer in device.viewers.values_mut().filter(|viewer| viewer.video) {
            if audio {
                // Each packet stands alone: a lost one is a click, not a
                // broken picture, so it never waits for a keyframe.
                let _ = viewer.frames.try_send(frame.clone());
                continue;
            }
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
    /// attach to the stream. Either way the machine is handed the viewer's
    /// signed join request and its grant, and only streams to it once it
    /// has checked them (see [`Registry::answer`]). Returns false if the
    /// machine is offline or this dashboard has no access to it.
    pub fn start_view(&self, dashboard_id: DashboardId, machine_id: &str, join: SignedView) -> bool {
        let mut inner = self.lock();
        let Some(dashboard) = inner.dashboards.get(&dashboard_id) else { return false };
        let Some(row) = dashboard.access.get(machine_id) else { return false };
        let grant = row.grant.as_ref().map(SignedView::from);
        let video = row.role.can_view();
        let elevated = dashboard.handle.step_up.allows(auth::now());
        let viewer = Viewer {
            frames: dashboard.handle.frames.clone(),
            email: dashboard.handle.email.clone(),
            video,
            awaiting_keyframe: true,
            elevated,
        };
        let Some(device) = inner.devices.get_mut(machine_id) else { return false };
        // Capture starts with the first viewer that watches the screen.
        let was_idle = video && !device.viewers.values().any(|viewer| viewer.video);
        // Asked again while already watching (a fresh key exchange): start
        // over from the next keyframe, and stay elevated if it was.
        let mut elevated = elevated;
        device
            .viewers
            .entry(dashboard_id)
            .and_modify(|viewer| {
                viewer.awaiting_keyframe = true;
                viewer.elevated |= elevated;
                elevated = viewer.elevated;
            })
            .or_insert(viewer);
        if was_idle {
            device.send(DeviceCommand::StartCapture { audio: true });
        }
        device.send(DeviceCommand::ViewerJoin {
            viewer: dashboard_id,
            statement: join.statement,
            signature: join.signature,
            grant,
        });
        if let Some(dashboard) = inner.dashboards.get(&dashboard_id) {
            dashboard.handle.send(DashboardEvent::Elevation { device_id: machine_id.to_owned(), elevated });
        }
        inner.publish(machine_id);
        true
    }

    /// Lets this dashboard's view of the machine pass on input, files and
    /// shells, if its session has proved a second factor within the window
    /// (or has none to prove). Answers with an elevation event either way;
    /// a refused one tells the dashboard to ask for a code.
    pub fn elevate(&self, dashboard_id: DashboardId, machine_id: &str) {
        let mut inner = self.lock();
        let Some(dashboard) = inner.dashboards.get(&dashboard_id) else { return };
        let allowed = dashboard.handle.step_up.allows(auth::now());
        let Some(viewer) = inner.devices.get_mut(machine_id).and_then(|device| device.viewers.get_mut(&dashboard_id))
        else {
            return;
        };
        viewer.elevated |= allowed;
        let elevated = viewer.elevated;
        if let Some(dashboard) = inner.dashboards.get(&dashboard_id) {
            dashboard.handle.send(DashboardEvent::Elevation { device_id: machine_id.to_owned(), elevated });
        }
    }

    /// The session proved a second factor at `at`.
    pub fn note_step_up(&self, session_id: i64, at: i64) {
        let mut inner = self.lock();
        for dashboard in inner.dashboards.values_mut().filter(|dashboard| dashboard.handle.session_id == session_id) {
            dashboard.handle.step_up.at = Some(at);
        }
    }

    /// The user gained their first second factor, or lost their last.
    pub fn set_mfa(&self, user_id: i64, mfa: bool) {
        let mut inner = self.lock();
        for dashboard in inner.dashboards.values_mut().filter(|dashboard| dashboard.handle.user_id == user_id) {
            dashboard.handle.step_up.mfa = mfa;
        }
    }

    /// Passes sealed input on to the machine if this dashboard may control
    /// it: its user has a control (or owner) role, and it's watching the
    /// machine right now. The machine checks the role again against the
    /// owner's grant before acting on it. Returns whether it was passed on.
    pub fn input(&self, dashboard_id: DashboardId, machine_id: &str, sealed: String) -> bool {
        self.pass_on(dashboard_id, machine_id, Role::can_control, DeviceCommand::Input { viewer: dashboard_id, sealed })
    }

    /// Passes a sealed clipboard request on to the machine if this dashboard
    /// is watching it, whatever its role: the machine's config decides
    /// whether a view share may read the clipboard, and the machine checks
    /// every request. Returns whether it was passed on.
    pub fn clipboard(&self, dashboard_id: DashboardId, machine_id: &str, sealed: String) -> bool {
        let inner = self.lock();
        let has_access =
            inner.dashboards.get(&dashboard_id).is_some_and(|dashboard| dashboard.access.contains_key(machine_id));
        let Some(device) = inner.devices.get(machine_id) else { return false };
        if !has_access || !device.viewers.contains_key(&dashboard_id) {
            return false;
        }
        device.send(DeviceCommand::Clipboard { viewer: dashboard_id, sealed });
        true
    }

    /// Passes a sealed file-channel message on to the machine if this
    /// dashboard may control it and is watching it. Returns whether it was.
    pub fn file(&self, dashboard_id: DashboardId, machine_id: &str, sealed: String) -> bool {
        self.pass_on(dashboard_id, machine_id, Role::can_files, DeviceCommand::File { viewer: dashboard_id, sealed })
    }

    /// Passes a sealed shell-channel message on to the machine if this
    /// dashboard may open shells there and is watching it, elevated.
    pub fn shell(&self, dashboard_id: DashboardId, machine_id: &str, sealed: String) -> bool {
        self.pass_on(dashboard_id, machine_id, Role::can_shell, DeviceCommand::Shell { viewer: dashboard_id, sealed })
    }

    /// Passes a sealed metrics request on to the machine if this dashboard
    /// owns it or has a share with analytics, and is watching it.
    pub fn metrics(&self, dashboard_id: DashboardId, machine_id: &str, sealed: String) -> bool {
        let inner = self.lock();
        let may = inner
            .dashboards
            .get(&dashboard_id)
            .and_then(|dashboard| dashboard.access.get(machine_id))
            .is_some_and(|row| row.analytics);
        let Some(device) = inner.devices.get(machine_id) else { return false };
        if !may || !device.viewers.contains_key(&dashboard_id) {
            return false;
        }
        device.send(DeviceCommand::Metrics { viewer: dashboard_id, sealed });
        true
    }

    fn pass_on(
        &self,
        dashboard_id: DashboardId,
        machine_id: &str,
        allowed: fn(Role) -> bool,
        command: DeviceCommand,
    ) -> bool {
        let inner = self.lock();
        let may = inner
            .dashboards
            .get(&dashboard_id)
            .and_then(|dashboard| dashboard.access.get(machine_id))
            .is_some_and(|row| allowed(row.role));
        let Some(device) = inner.devices.get(machine_id) else { return false };
        // Not elevated: the session owes a fresh second factor first.
        if !may || !device.viewers.get(&dashboard_id).is_some_and(|viewer| viewer.elevated) {
            return false;
        }
        device.send(command);
        true
    }

    /// Queues a machine's file or shell message for one of its viewers,
    /// without waiting: false when that viewer isn't watching or its queue
    /// is full.
    pub fn forward_bulk(&self, machine_id: &str, viewer: DashboardId, event: DashboardEvent) -> bool {
        let inner = self.lock();
        let watching = inner.devices.get(machine_id).is_some_and(|device| device.viewers.contains_key(&viewer));
        let Some(dashboard) = inner.dashboards.get(&viewer).filter(|_| watching) else { return false };
        dashboard.handle.bulk.try_send(event).is_ok()
    }

    /// Routes the machine's answer to one of its viewers. A refused viewer
    /// stops being sent frames, and is told why.
    pub fn answer(&self, machine_id: &str, viewer: DashboardId, answer: Answer) {
        let mut inner = self.lock();
        let watching = inner.devices.get(machine_id).is_some_and(|device| device.viewers.contains_key(&viewer));
        if !watching {
            return;
        }
        let device_id = machine_id.to_owned();
        let event = match answer {
            Answer::Accept { statement, signature, wrapped_key, clipboard, files, shell, analytics } => {
                DashboardEvent::ViewAccepted {
                    device_id,
                    statement,
                    signature,
                    wrapped_key,
                    clipboard,
                    files,
                    shell,
                    analytics,
                }
            }
            Answer::StreamKey { wrapped_key } => DashboardEvent::StreamKey { device_id, wrapped_key },
            Answer::Clipboard { sealed } => DashboardEvent::Clipboard { device_id, sealed },
            Answer::Pong { nonce } => DashboardEvent::Pong { device_id, nonce },
            Answer::Reject { reason } => {
                inner.detach(viewer, machine_id);
                DashboardEvent::ViewRejected { device_id, reason }
            }
        };
        if let Some(dashboard) = inner.dashboards.get(&viewer) {
            dashboard.handle.send(event);
        }
    }

    /// Hands the machine every revocation its owner signed, if it's online.
    pub fn send_revocations(&self, machine_id: &str, revocations: &[Signed]) {
        let inner = self.lock();
        if let Some(device) = inner.devices.get(machine_id) {
            device.send(DeviceCommand::Revocations { revocations: revocations.iter().map(SignedView::from).collect() });
        }
    }

    /// The machine's updater found a release it's holding for the owner, or
    /// no longer has one.
    pub fn set_update_available(&self, machine_id: &str, connection: u64, available: Option<String>) {
        let mut inner = self.lock();
        let Some(device) = inner.devices.get_mut(machine_id).filter(|device| device.connection == connection) else {
            return;
        };
        if device.update_available != available {
            device.update_available = available;
            inner.publish(machine_id);
        }
    }

    /// The machine said it's restarting: show it so until it's back, or
    /// for RESTART_GRACE. Only from its current connection.
    pub fn going_down(&self, machine_id: &str, connection: u64, restart: bool) {
        let mut inner = self.lock();
        if !restart || inner.devices.get(machine_id).is_none_or(|device| device.connection != connection) {
            return;
        }
        inner.restarting.insert(machine_id.to_owned(), auth::now() + RESTART_GRACE);
        inner.publish(machine_id);
    }

    /// A restarting machine's grace ran out: if it isn't back, show it as
    /// just offline.
    pub fn restart_overdue(&self, machine_id: &str) {
        let mut inner = self.lock();
        let now = auth::now();
        if inner.restarting.get(machine_id).is_some_and(|until| *until <= now) {
            inner.restarting.remove(machine_id);
            inner.publish(machine_id);
        }
    }

    /// Passes a sealed power action on to the machine if this dashboard may
    /// control it and is watching it, elevated.
    pub fn power(&self, dashboard_id: DashboardId, machine_id: &str, sealed: String) -> bool {
        self.pass_on(dashboard_id, machine_id, Role::can_control, DeviceCommand::Power { viewer: dashboard_id, sealed })
    }

    /// Passes a sealed request for the output devices on to the machine if
    /// this dashboard is watching it, whatever its role: the machine only
    /// answers roles that watch the screen.
    pub fn audio_devices(&self, dashboard_id: DashboardId, machine_id: &str, sealed: String) -> bool {
        let inner = self.lock();
        let has_access =
            inner.dashboards.get(&dashboard_id).is_some_and(|dashboard| dashboard.access.contains_key(machine_id));
        let Some(device) = inner.devices.get(machine_id) else { return false };
        if !has_access || !device.viewers.contains_key(&dashboard_id) {
            return false;
        }
        device.send(DeviceCommand::AudioDevices { viewer: dashboard_id, sealed });
        true
    }

    /// Passes a ping on to the machine if this dashboard is watching it,
    /// whatever its role, and the machine is new enough to answer it.
    /// Returns whether it was passed on.
    pub fn ping(&self, dashboard_id: DashboardId, machine_id: &str, nonce: String) -> bool {
        let inner = self.lock();
        let has_access =
            inner.dashboards.get(&dashboard_id).is_some_and(|dashboard| dashboard.access.contains_key(machine_id));
        let Some(device) = inner.devices.get(machine_id) else { return false };
        if !has_access || !device.viewers.contains_key(&dashboard_id) || device.protocol < PING_PROTOCOL {
            return false;
        }
        device.send(DeviceCommand::Ping { viewer: dashboard_id, nonce });
        true
    }

    /// Passes a sealed choice of output device on to the machine if this
    /// dashboard may control it and is watching it, elevated: it changes
    /// what everyone watching hears.
    pub fn audio_select(&self, dashboard_id: DashboardId, machine_id: &str, sealed: String) -> bool {
        self.pass_on(
            dashboard_id,
            machine_id,
            Role::can_control,
            DeviceCommand::AudioSelect { viewer: dashboard_id, sealed },
        )
    }

    /// Passes the owner's go-ahead for an update on. Anyone else is ignored.
    pub fn install_update(&self, dashboard_id: DashboardId, machine_id: &str) {
        let inner = self.lock();
        let Some(dashboard) = inner.dashboards.get(&dashboard_id) else { return };
        if !dashboard.access.get(machine_id).is_some_and(|row| row.role == Role::Owner) {
            return;
        }
        if let Some(device) = inner.devices.get(machine_id) {
            device.send(DeviceCommand::InstallUpdate);
        }
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
    /// a new share, changed terms, or a newly enrolled or endorsed machine.
    /// Their open views of it end and start over, so the machine checks the
    /// new grant (and lets go of their input if they lost control).
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
            if inner.detach(*id, &row.public_id)
                && let Some(dashboard) = inner.dashboards.get(id)
            {
                // The dashboard asks again once it hears the machine is
                // online (the update published below).
                dashboard.handle.send(DashboardEvent::CaptureEnded { device_id: row.public_id.clone() });
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
            analytics: role == Role::Owner,
            public_key: None,
            owner_public_key: None,
            endorsement: None,
            enroll_code_hash: None,
            enroll_binding: None,
            grant: (role != Role::Owner)
                .then(|| Signed { statement: "hawk-grant-v1".to_owned(), signature: vec![1, 2, 3] }),
        }
    }

    fn handle(user_id: i64) -> (DashboardHandle, mpsc::UnboundedReceiver<Outbound>) {
        let (events, events_rx) = mpsc::unbounded_channel();
        let (frames, _) = mpsc::channel(1);
        let (bulk, _) = mpsc::channel(1);
        let handle = DashboardHandle {
            events,
            frames,
            bulk,
            user_id,
            session_id: user_id,
            email: format!("user{user_id}@example.com"),
            step_up: StepUp::default(),
        };
        (handle, events_rx)
    }

    fn join() -> SignedView {
        SignedView { statement: "hawk-join-v1".to_owned(), signature: "c2ln".to_owned() }
    }

    fn next(device_rx: &mut mpsc::UnboundedReceiver<DeviceOutbound>) -> Option<DeviceCommand> {
        match device_rx.try_recv() {
            Ok(DeviceOutbound::Command(command)) => Some(command),
            _ => None,
        }
    }

    /// A registry with the machine connected and one dashboard of `role`
    /// watching it, plus the receiving ends of the device's commands (start
    /// and join already taken off) and of the dashboard's events.
    fn watching(
        role: Role,
    ) -> (Registry, DashboardId, mpsc::UnboundedReceiver<DeviceOutbound>, mpsc::UnboundedReceiver<Outbound>) {
        let registry = Registry::default();
        let user_id = if role == Role::Owner { 1 } else { 2 };
        let (handle, events_rx) = handle(user_id);
        let dashboard = registry.add_dashboard(handle, vec![row(role)]);
        let (outbound, mut device_rx) = mpsc::unbounded_channel();
        registry.add_device(MACHINE, 1, DeviceInfo { version: None, protocol: PING_PROTOCOL }, outbound);
        assert!(registry.start_view(dashboard, MACHINE, join()));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::StartCapture { .. })));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::ViewerJoin { .. })));
        (registry, dashboard, device_rx, events_rx)
    }

    #[test]
    fn joining_hands_the_machine_the_grant() {
        let registry = Registry::default();
        let (handle, _events) = handle(2);
        let dashboard = registry.add_dashboard(handle, vec![row(Role::View)]);
        let (outbound, mut device_rx) = mpsc::unbounded_channel();
        registry.add_device(MACHINE, 1, DeviceInfo::default(), outbound);
        assert!(registry.start_view(dashboard, MACHINE, join()));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::StartCapture { .. })));
        let Some(DeviceCommand::ViewerJoin { viewer, grant, .. }) = next(&mut device_rx) else { panic!("no join") };
        assert_eq!(viewer, dashboard);
        assert_eq!(grant.map(|grant| grant.statement), Some("hawk-grant-v1".to_owned()));
    }

    #[test]
    fn control_input_reaches_the_machine() {
        let (registry, dashboard, mut device_rx, _events) = watching(Role::Control);
        assert!(registry.input(dashboard, MACHINE, "sealed".to_owned()));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::Input { viewer, .. }) if viewer == dashboard));
    }

    fn next_elevation(events: &mut mpsc::UnboundedReceiver<Outbound>) -> Option<bool> {
        while let Ok(outbound) = events.try_recv() {
            if let Outbound::Event(event) = outbound
                && let DashboardEvent::Elevation { elevated, .. } = *event
            {
                return Some(elevated);
            }
        }
        None
    }

    /// A session that owes a second factor watches, but its input, files
    /// and shells go nowhere until it steps up and asks again.
    #[test]
    fn control_waits_for_step_up() {
        let registry = Registry::default();
        let (mut handle, mut events) = handle(1);
        handle.step_up = StepUp { mfa: true, at: None };
        let dashboard = registry.add_dashboard(handle, vec![row(Role::Owner)]);
        let (outbound, mut device_rx) = mpsc::unbounded_channel();
        registry.add_device(MACHINE, 1, DeviceInfo::default(), outbound);
        assert!(registry.start_view(dashboard, MACHINE, join()));
        assert_eq!(next_elevation(&mut events), Some(false));
        while next(&mut device_rx).is_some() {}

        assert!(!registry.input(dashboard, MACHINE, "sealed".to_owned()));
        assert!(!registry.shell(dashboard, MACHINE, "sealed".to_owned()));
        assert!(!registry.power(dashboard, MACHINE, "sealed".to_owned()));
        registry.elevate(dashboard, MACHINE);
        assert_eq!(next_elevation(&mut events), Some(false));

        registry.note_step_up(1, auth::now());
        registry.elevate(dashboard, MACHINE);
        assert_eq!(next_elevation(&mut events), Some(true));
        assert!(registry.input(dashboard, MACHINE, "sealed".to_owned()));
        assert!(registry.shell(dashboard, MACHINE, "sealed".to_owned()));
        assert!(registry.power(dashboard, MACHINE, "sealed".to_owned()));
    }

    /// Restarting or signing out is control's to ask for, never a view
    /// share's or a dev share's.
    #[test]
    fn power_needs_control() {
        let (registry, dashboard, mut device_rx, _events) = watching(Role::Control);
        assert!(registry.power(dashboard, MACHINE, "sealed".to_owned()));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::Power { viewer, .. }) if viewer == dashboard));
        let (registry, dashboard, mut device_rx, _events) = watching(Role::View);
        assert!(!registry.power(dashboard, MACHINE, "sealed".to_owned()));
        assert!(next(&mut device_rx).is_none());

        // A dev share watches no stream, so it isn't `watching`'s shape.
        let registry = Registry::default();
        let (handle, _events) = handle(2);
        let dashboard = registry.add_dashboard(handle, vec![row(Role::Dev)]);
        let (outbound, mut device_rx) = mpsc::unbounded_channel();
        registry.add_device(MACHINE, 1, DeviceInfo::default(), outbound);
        assert!(registry.start_view(dashboard, MACHINE, join()));
        while next(&mut device_rx).is_some() {}
        assert!(!registry.power(dashboard, MACHINE, "sealed".to_owned()));
        assert!(next(&mut device_rx).is_none());
    }

    /// Anyone watching may see the output devices; only control may choose.
    #[test]
    fn choosing_the_output_device_needs_control() {
        let (registry, dashboard, mut device_rx, _events) = watching(Role::View);
        assert!(registry.audio_devices(dashboard, MACHINE, "sealed".to_owned()));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::AudioDevices { viewer, .. }) if viewer == dashboard));
        assert!(!registry.audio_select(dashboard, MACHINE, "sealed".to_owned()));
        assert!(next(&mut device_rx).is_none());

        let (registry, dashboard, mut device_rx, _events) = watching(Role::Control);
        assert!(registry.audio_select(dashboard, MACHINE, "sealed".to_owned()));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::AudioSelect { viewer, .. }) if viewer == dashboard));
    }

    /// Anyone watching may ping the machine, and only its own viewer hears
    /// the pong.
    #[test]
    fn pings_need_an_open_view() {
        let (registry, dashboard, mut device_rx, mut events) = watching(Role::View);
        assert!(registry.ping(dashboard, MACHINE, "1".to_owned()));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::Ping { viewer, .. }) if viewer == dashboard));
        while events.try_recv().is_ok() {}
        registry.answer(MACHINE, dashboard, Answer::Pong { nonce: "1".to_owned() });
        let event = events.try_recv().ok().and_then(|outbound| match outbound {
            Outbound::Event(event) => Some(*event),
            Outbound::Close => None,
        });
        assert!(matches!(event, Some(DashboardEvent::Pong { nonce, .. }) if nonce == "1"));
        registry.stop_view(dashboard, MACHINE);
        assert!(!registry.ping(dashboard, MACHINE, "2".to_owned()));
    }

    /// A dashboard that isn't watching the machine, or can't see it at
    /// all, can't ping it, and a pong for it goes nowhere.
    #[test]
    fn pings_need_access_and_a_view() {
        let (registry, watcher, mut device_rx, _events) = watching(Role::View);
        // Can see the machine, but isn't watching it.
        let (idle_handle, mut idle_events) = handle(3);
        let idle = registry.add_dashboard(idle_handle, vec![row(Role::View)]);
        assert!(!registry.ping(idle, MACHINE, "1".to_owned()));
        // Can't see it at all.
        let (stranger_handle, _stranger_events) = handle(4);
        let stranger = registry.add_dashboard(stranger_handle, vec![]);
        assert!(!registry.ping(stranger, MACHINE, "1".to_owned()));
        // No such machine.
        assert!(!registry.ping(watcher, "machine-2", "1".to_owned()));
        assert!(next(&mut device_rx).is_none());
        // A pong addressed to a dashboard that isn't watching is dropped.
        while idle_events.try_recv().is_ok() {}
        registry.answer(MACHINE, idle, Answer::Pong { nonce: "1".to_owned() });
        assert!(idle_events.try_recv().is_err());
    }

    /// A machine too old to answer a ping is never sent one, and says so.
    #[test]
    fn pings_follow_the_protocol() {
        let registry = Registry::default();
        let (handle, mut events) = handle(2);
        let dashboard = registry.add_dashboard(handle, vec![row(Role::View)]);
        let (outbound, mut device_rx) = mpsc::unbounded_channel();
        registry.add_device(MACHINE, 1, DeviceInfo { version: None, protocol: POWER_PROTOCOL }, outbound);
        assert!(last_view(&mut events).is_some_and(|view| !view.ping));
        assert!(registry.start_view(dashboard, MACHINE, join()));
        while next(&mut device_rx).is_some() {}
        assert!(!registry.ping(dashboard, MACHINE, "1".to_owned()));
        assert!(next(&mut device_rx).is_none());
    }

    /// Only machines new enough to list their devices offer the picker.
    #[test]
    fn audio_devices_follow_the_protocol() {
        let registry = Registry::default();
        let (handle, mut events) = handle(1);
        registry.add_dashboard(handle, vec![row(Role::View)]);
        let (outbound, _device_rx) = mpsc::unbounded_channel();
        let info = DeviceInfo { version: None, protocol: POWER_PROTOCOL };
        let connection = registry.add_device(MACHINE, 1, info, outbound);
        assert!(last_view(&mut events).is_some_and(|view| !view.audio_devices));
        registry.remove_device(MACHINE, connection, auth::now());
        let (outbound, _device_rx) = mpsc::unbounded_channel();
        let info = DeviceInfo { version: None, protocol: AUDIO_DEVICES_PROTOCOL };
        registry.add_device(MACHINE, 1, info, outbound);
        assert!(last_view(&mut events).is_some_and(|view| view.audio_devices));
    }

    /// The last machine view `events` carries.
    fn last_view(events: &mut mpsc::UnboundedReceiver<Outbound>) -> Option<MachineView> {
        let mut last = None;
        while let Ok(Outbound::Event(event)) = events.try_recv() {
            match *event {
                DashboardEvent::MachineUpdated { machine } => last = Some(machine),
                DashboardEvent::Snapshot { mut machines } => last = machines.pop(),
                _ => {}
            }
        }
        last
    }

    /// A machine that said it's restarting shows so while it's gone, and
    /// stops the moment it's back.
    #[test]
    fn restarting_lasts_until_the_machine_is_back() {
        let registry = Registry::default();
        let (handle, mut events) = handle(1);
        registry.add_dashboard(handle, vec![row(Role::Owner)]);
        let (outbound, _device_rx) = mpsc::unbounded_channel();
        let info = DeviceInfo { version: None, protocol: POWER_PROTOCOL };
        let connection = registry.add_device(MACHINE, 1, info.clone(), outbound);
        assert!(last_view(&mut events).is_some_and(|view| view.power && !view.restarting));

        registry.going_down(MACHINE, connection + 1, true); // not its connection
        assert!(last_view(&mut events).is_none());
        registry.going_down(MACHINE, connection, true);
        assert!(last_view(&mut events).is_some_and(|view| view.restarting));
        registry.remove_device(MACHINE, connection, auth::now());
        assert!(last_view(&mut events).is_some_and(|view| view.restarting && !view.online && !view.power));
        registry.restart_overdue(MACHINE); // not overdue yet
        assert!(last_view(&mut events).is_none());

        let (outbound, _device_rx) = mpsc::unbounded_channel();
        registry.add_device(MACHINE, 1, info, outbound);
        assert!(last_view(&mut events).is_some_and(|view| view.online && !view.restarting));
    }

    /// A shut down isn't a restart: the machine is just offline after it.
    #[test]
    fn shutting_down_is_not_restarting() {
        let registry = Registry::default();
        let (handle, mut events) = handle(1);
        registry.add_dashboard(handle, vec![row(Role::Owner)]);
        let (outbound, _device_rx) = mpsc::unbounded_channel();
        let connection = registry.add_device(MACHINE, 1, DeviceInfo::default(), outbound);
        assert!(last_view(&mut events).is_some_and(|view| !view.power));
        registry.going_down(MACHINE, connection, false);
        registry.remove_device(MACHINE, connection, auth::now());
        assert!(last_view(&mut events).is_some_and(|view| !view.restarting));
    }

    /// Sound gets through while the picture waits for its next keyframe.
    #[test]
    fn audio_never_waits_for_a_keyframe() {
        let registry = Registry::default();
        let (events, _events_rx) = mpsc::unbounded_channel();
        let (frames, mut frames_rx) = mpsc::channel(8);
        let (bulk, _) = mpsc::channel(1);
        let handle =
            DashboardHandle { events, frames, bulk, user_id: 1, session_id: 1, email: "o@example.com".to_owned(), step_up: StepUp::default() };
        let dashboard = registry.add_dashboard(handle, vec![row(Role::Owner)]);
        let (outbound, mut device_rx) = mpsc::unbounded_channel();
        registry.add_device(MACHINE, 1, DeviceInfo::default(), outbound);
        assert!(registry.start_view(dashboard, MACHINE, join()));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::StartCapture { audio: true })));

        registry.forward_frame(MACHINE, Bytes::from_static(&[2, 0, 1])); // a delta: dropped
        registry.forward_frame(MACHINE, Bytes::from_static(&[2, 2, 2])); // audio: through
        registry.forward_frame(MACHINE, Bytes::from_static(&[2, 1, 3])); // a keyframe: through
        assert_eq!(frames_rx.try_recv().ok().as_deref(), Some([2, 2, 2].as_slice()));
        assert_eq!(frames_rx.try_recv().ok().as_deref(), Some([2, 1, 3].as_slice()));
        assert!(frames_rx.try_recv().is_err());
    }

    #[test]
    fn view_only_input_is_dropped() {
        let (registry, dashboard, mut device_rx, _events) = watching(Role::View);
        assert!(!registry.input(dashboard, MACHINE, "sealed".to_owned()));
        assert!(next(&mut device_rx).is_none());
    }

    #[test]
    fn input_needs_an_open_view() {
        let (registry, dashboard, mut device_rx, _events) = watching(Role::Control);
        registry.stop_view(dashboard, MACHINE);
        assert!(!registry.input(dashboard, MACHINE, "sealed".to_owned()));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::ViewerLeft { viewer }) if viewer == dashboard));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::StopCapture)));
    }

    /// The machine hears who left before it's told to stop, so it can let
    /// go of their input and rekey the stream.
    #[test]
    fn leaving_tells_the_machine() {
        let (registry, dashboard, mut device_rx, _events) = watching(Role::Control);
        registry.remove_dashboard(dashboard);
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::ViewerLeft { viewer }) if viewer == dashboard));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::StopCapture)));
    }

    /// New terms end the view so it starts over with the new grant.
    #[test]
    fn new_terms_restart_the_view() {
        let (registry, dashboard, mut device_rx, mut events) = watching(Role::Control);
        registry.grant(2, &row(Role::View));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::ViewerLeft { viewer }) if viewer == dashboard));
        let mut ended = false;
        while let Ok(Outbound::Event(event)) = events.try_recv() {
            ended |= matches!(*event, DashboardEvent::CaptureEnded { .. });
        }
        assert!(ended);
        assert!(!registry.input(dashboard, MACHINE, "sealed".to_owned()));
    }

    /// A refused viewer is told why and gets no more frames.
    #[test]
    fn rejected_viewers_are_detached() {
        let (registry, dashboard, mut device_rx, mut events) = watching(Role::View);
        registry.answer(MACHINE, dashboard, Answer::Reject { reason: "no grant".to_owned() });
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::ViewerLeft { .. })));
        let mut rejected = false;
        while let Ok(Outbound::Event(event)) = events.try_recv() {
            rejected |= matches!(*event, DashboardEvent::ViewRejected { .. });
        }
        assert!(rejected);
        assert!(!registry.is_watching(2, MACHINE));
    }

    /// A view share's request still reaches the machine, which decides from
    /// its config; it needs an open view all the same.
    #[test]
    fn clipboard_requests_need_an_open_view() {
        let (registry, dashboard, mut device_rx, _events) = watching(Role::View);
        assert!(registry.clipboard(dashboard, MACHINE, "sealed".to_owned()));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::Clipboard { viewer, .. }) if viewer == dashboard));
        registry.stop_view(dashboard, MACHINE);
        while next(&mut device_rx).is_some() {}
        assert!(!registry.clipboard(dashboard, MACHINE, "sealed".to_owned()));
        assert!(next(&mut device_rx).is_none());
    }

    /// Clipboard text goes to the viewer it was sealed for, and nobody else.
    #[test]
    fn clipboard_text_reaches_only_its_viewer() {
        let (registry, dashboard, _device_rx, mut events) = watching(Role::Control);
        let (handle, mut other_events) = handle(3);
        let other = registry.add_dashboard(handle, vec![row(Role::Control)]);
        assert!(registry.start_view(other, MACHINE, join()));
        while events.try_recv().is_ok() {}
        while other_events.try_recv().is_ok() {}

        registry.answer(MACHINE, dashboard, Answer::Clipboard { sealed: "text".to_owned() });
        let Ok(Outbound::Event(event)) = events.try_recv() else { panic!("no clipboard event") };
        assert!(matches!(*event, DashboardEvent::Clipboard { ref sealed, .. } if sealed == "text"));
        assert!(other_events.try_recv().is_err());
    }

    /// Files need control, and an open view.
    #[test]
    fn file_requests_need_control() {
        let (registry, dashboard, mut device_rx, _events) = watching(Role::View);
        assert!(!registry.file(dashboard, MACHINE, "sealed".to_owned()));
        assert!(next(&mut device_rx).is_none());

        let (registry, dashboard, mut device_rx, _events) = watching(Role::Control);
        assert!(registry.file(dashboard, MACHINE, "sealed".to_owned()));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::File { viewer, .. }) if viewer == dashboard));
        registry.stop_view(dashboard, MACHINE);
        while next(&mut device_rx).is_some() {}
        assert!(!registry.file(dashboard, MACHINE, "sealed".to_owned()));
    }

    /// File data goes on the bounded queue of the viewer it's for, and is
    /// dropped rather than queued without limit.
    #[test]
    fn file_data_is_bounded() {
        let registry = Registry::default();
        let (events, _events_rx) = mpsc::unbounded_channel();
        let (frames, _frames_rx) = mpsc::channel(1);
        let (bulk, mut files_rx) = mpsc::channel(2);
        let handle =
            DashboardHandle {
                events,
                frames,
                bulk,
                user_id: 2,
                session_id: 2,
                email: "user2@example.com".to_owned(),
                step_up: StepUp::default(),
            };
        let dashboard = registry.add_dashboard(handle, vec![row(Role::Control)]);
        let (outbound, _device_rx) = mpsc::unbounded_channel();
        registry.add_device(MACHINE, 1, DeviceInfo::default(), outbound);
        let file = |sealed: &str| DashboardEvent::File { device_id: MACHINE.to_owned(), sealed: sealed.to_owned() };
        assert!(!registry.forward_bulk(MACHINE, dashboard, file("early")));
        assert!(registry.start_view(dashboard, MACHINE, join()));

        assert!(registry.forward_bulk(MACHINE, dashboard, file("a")));
        assert!(registry.forward_bulk(MACHINE, dashboard, file("b")));
        assert!(!registry.forward_bulk(MACHINE, dashboard, file("c")));
        assert!(matches!(files_rx.try_recv(), Ok(DashboardEvent::File { ref sealed, .. }) if sealed == "a"));
    }

    /// A dev share is a viewer for its shell and files: it doesn't start
    /// capture, gets no frames, and can't send input.
    #[test]
    fn dev_shares_get_a_shell_and_no_video() {
        let registry = Registry::default();
        let (handle, _events) = handle(2);
        let dashboard = registry.add_dashboard(handle, vec![row(Role::Dev)]);
        let (outbound, mut device_rx) = mpsc::unbounded_channel();
        registry.add_device(MACHINE, 1, DeviceInfo::default(), outbound);
        assert!(registry.start_view(dashboard, MACHINE, join()));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::ViewerJoin { .. })));
        assert!(next(&mut device_rx).is_none(), "no capture for a dev share");

        assert!(!registry.input(dashboard, MACHINE, "sealed".to_owned()));
        assert!(registry.shell(dashboard, MACHINE, "sealed".to_owned()));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::Shell { .. })));
        assert!(registry.file(dashboard, MACHINE, "sealed".to_owned()));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::File { .. })));

        registry.stop_view(dashboard, MACHINE);
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::ViewerLeft { .. })));
        assert!(next(&mut device_rx).is_none(), "nothing to stop");
    }

    /// Control has video and input, and no shell.
    #[test]
    fn control_shares_get_no_shell() {
        let (registry, dashboard, mut device_rx, _events) = watching(Role::Control);
        assert!(!registry.shell(dashboard, MACHINE, "sealed".to_owned()));
        assert!(next(&mut device_rx).is_none());
        let (registry, dashboard, mut device_rx, _events) = watching(Role::Owner);
        assert!(registry.shell(dashboard, MACHINE, "sealed".to_owned()));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::Shell { .. })));
    }

    /// Capture stops when the last viewer that watches leaves, even with a
    /// dev share still there for its shell.
    #[test]
    fn capture_stops_with_the_last_video_viewer() {
        let (registry, watcher, mut device_rx, _events) = watching(Role::Control);
        let (handle, _dev_events) = handle(3);
        let mut dev_row = row(Role::Dev);
        dev_row.owner_id = 1;
        let dev = registry.add_dashboard(handle, vec![dev_row]);
        assert!(registry.start_view(dev, MACHINE, join()));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::ViewerJoin { .. })));
        registry.stop_view(watcher, MACHINE);
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::ViewerLeft { .. })));
        assert!(matches!(next(&mut device_rx), Some(DeviceCommand::StopCapture)));
    }

    /// Answers only go to a dashboard that is watching that machine.
    #[test]
    fn answers_for_strangers_are_dropped() {
        let (registry, _dashboard, _device_rx, _events) = watching(Role::View);
        let (handle, mut stranger_events) = handle(3);
        let stranger = registry.add_dashboard(handle, vec![]);
        while stranger_events.try_recv().is_ok() {}
        registry.answer(MACHINE, stranger, Answer::StreamKey { wrapped_key: "k".to_owned() });
        assert!(stranger_events.try_recv().is_err());
    }
}
