//! The audit log: who signed in, watched a machine, used its shell or its
//! files, pressed a power button or changed its config, and from where.
//!
//! It's metadata only. The relay can't read what a view, a shell or a file
//! carries, so what it records is that a channel was used during a view and
//! how many sealed bytes went each way; and it never records a secret
//! (passwords, codes, tokens, sealed payloads): an event is built from typed
//! fields, so nothing else can slip in.
//!
//! Recording never waits. Events go into a bounded queue that one task
//! writes to the database in batches; when the queue is full the event is
//! dropped and counted, rather than holding up a login or the registry.
//! When the relay stops, the writer is given a moment to write what's still
//! queued (see [`AuditWriter::flush`]).
//!
//! Who reads what: everyone sees what they did and what was done to their
//! account; a machine's owner also sees everything done on it, by anyone;
//! the admin sees everything.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Json;
use axum::extract::{ConnectInfo, FromRequestParts, Query, State};
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::AppState;
use crate::api;
use crate::auth::{self, AdminUser, CurrentUser};
use crate::db::{self, AuditFilter, Db, FactorKind, MachineRow, Role, SessionOrigin};
use crate::error::ApiError;
use crate::metrics::METRICS;

/// Events waiting for the writer before new ones are dropped: minutes of
/// a busy relay's worth, and a few hundred KB at most.
pub const QUEUE_LEN: usize = 4096;
/// Events written per transaction.
const BATCH_LEN: usize = 256;

/// How long events are kept unless the relay is told otherwise.
pub const DEFAULT_RETENTION_DAYS: u32 = 90;
/// Events deleted per statement when pruning.
const PRUNE_CHUNK: i64 = 5000;

/// What happened. Stored and sent as its snake_case name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    // Accounts.
    SignIn,
    SignInFailed,
    MfaFailed,
    StepUp,
    SignedUp,
    PasswordChanged,
    MfaAdded,
    MfaRemoved,
    RecoveryCodesRegenerated,
    MfaReset,
    UserDisabled,
    UserEnabled,
    InviteCreated,
    InviteRevoked,
    MfaPolicyChanged,
    // Machines and shares.
    MachineEnrolled,
    MachineRenamed,
    MachineRemoved,
    ShareGranted,
    ShareRevoked,
    // Views, and what was done in them.
    ViewStarted,
    ViewEnded,
    ViewRejected,
    ViewElevated,
    ShellUsed,
    FilesUsed,
    ClipboardImagePasted,
    Power,
    CtrlAltDel,
    EndProcess,
    ConfigChanged,
    UpdateInstall,
}

impl Kind {
    pub const ALL: [Self; 32] = [
        Self::SignIn,
        Self::SignInFailed,
        Self::MfaFailed,
        Self::StepUp,
        Self::SignedUp,
        Self::PasswordChanged,
        Self::MfaAdded,
        Self::MfaRemoved,
        Self::RecoveryCodesRegenerated,
        Self::MfaReset,
        Self::UserDisabled,
        Self::UserEnabled,
        Self::InviteCreated,
        Self::InviteRevoked,
        Self::MfaPolicyChanged,
        Self::MachineEnrolled,
        Self::MachineRenamed,
        Self::MachineRemoved,
        Self::ShareGranted,
        Self::ShareRevoked,
        Self::ViewStarted,
        Self::ViewEnded,
        Self::ViewRejected,
        Self::ViewElevated,
        Self::ShellUsed,
        Self::FilesUsed,
        Self::ClipboardImagePasted,
        Self::Power,
        Self::CtrlAltDel,
        Self::EndProcess,
        Self::ConfigChanged,
        Self::UpdateInstall,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "sign_in",
            Self::SignInFailed => "sign_in_failed",
            Self::MfaFailed => "mfa_failed",
            Self::StepUp => "step_up",
            Self::SignedUp => "signed_up",
            Self::PasswordChanged => "password_changed",
            Self::MfaAdded => "mfa_added",
            Self::MfaRemoved => "mfa_removed",
            Self::RecoveryCodesRegenerated => "recovery_codes_regenerated",
            Self::MfaReset => "mfa_reset",
            Self::UserDisabled => "user_disabled",
            Self::UserEnabled => "user_enabled",
            Self::InviteCreated => "invite_created",
            Self::InviteRevoked => "invite_revoked",
            Self::MfaPolicyChanged => "mfa_policy_changed",
            Self::MachineEnrolled => "machine_enrolled",
            Self::MachineRenamed => "machine_renamed",
            Self::MachineRemoved => "machine_removed",
            Self::ShareGranted => "share_granted",
            Self::ShareRevoked => "share_revoked",
            Self::ViewStarted => "view_started",
            Self::ViewEnded => "view_ended",
            Self::ViewRejected => "view_rejected",
            Self::ViewElevated => "view_elevated",
            Self::ShellUsed => "shell_used",
            Self::FilesUsed => "files_used",
            Self::ClipboardImagePasted => "clipboard_image_pasted",
            Self::Power => "power",
            Self::CtrlAltDel => "ctrl_alt_del",
            Self::EndProcess => "end_process",
            Self::ConfigChanged => "config_changed",
            Self::UpdateInstall => "update_install",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == name)
    }
}

/// Where a request came from: the TCP peer (behind a reverse proxy, the
/// proxy) and the browser's User-Agent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Client {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

impl From<&SessionOrigin> for Client {
    fn from(origin: &SessionOrigin) -> Self {
        Self { ip: Some(origin.ip.clone()), user_agent: origin.user_agent.clone() }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Client {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|info| info.0);
        Ok(match peer {
            Some(peer) => Self::from(&api::session_origin(peer, &parts.headers)),
            None => Self::default(),
        })
    }
}

/// The particulars of an event, stored as a JSON object. Only what's here
/// can be recorded, and none of it is a secret.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Details {
    /// Why: a refused view (the machine's words), a failed sign-in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// How long a view lasted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds: Option<i64>,
    /// Sealed bytes of shell and file traffic during a view, to the machine
    /// (up) and from it (down). Sealed, so a little over what was carried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_up: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_down: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files_up: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files_down: Option<u64>,
    /// Whether a view passed on input, files and shells when it started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elevated: Option<bool>,
    /// The second factor was a recovery code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_code: Option<bool>,
    /// The kind of second factor added, removed, or proved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub factor: Option<FactorKind>,
    /// A machine's new name, an authenticator's label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// A share's terms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starts_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub single_view: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analytics: Option<bool>,
    /// The admin's two-factor policy, as changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_mfa: Option<bool>,
}

impl Details {
    /// None when there's nothing to say.
    pub fn to_json(&self) -> Option<String> {
        (*self != Self::default()).then(|| serde_json::to_string(self).unwrap_or_default())
    }

    pub fn reason(reason: impl Into<String>) -> Self {
        Self { reason: Some(reason.into()), ..Self::default() }
    }

    pub fn name(name: impl Into<String>) -> Self {
        Self { name: Some(name.into()), ..Self::default() }
    }

    /// A factor added or removed: its kind and label.
    pub fn factor(kind: FactorKind, label: impl Into<String>) -> Self {
        Self { factor: Some(kind), name: Some(label.into()), ..Self::default() }
    }
}

/// One thing that happened.
#[derive(Debug, Clone)]
pub struct Event {
    pub at: i64,
    pub kind: Kind,
    /// Who did it; None for an account that doesn't exist (a sign-in with an
    /// unknown email).
    pub user_id: Option<i64>,
    /// The account it was done to, when that's someone else: the user a
    /// machine was shared with, the account the admin disabled.
    pub subject_id: Option<i64>,
    pub machine_id: Option<String>,
    pub machine_name: Option<String>,
    /// The machine's owner, who sees every event about it.
    pub owner_id: Option<i64>,
    pub role: Option<Role>,
    pub client: Client,
    pub details: Details,
}

impl Event {
    pub fn new(kind: Kind) -> Self {
        Self {
            at: auth::now(),
            kind,
            user_id: None,
            subject_id: None,
            machine_id: None,
            machine_name: None,
            owner_id: None,
            role: None,
            client: Client::default(),
            details: Details::default(),
        }
    }

    pub fn by(mut self, user_id: i64) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn about(mut self, subject_id: i64) -> Self {
        self.subject_id = Some(subject_id);
        self
    }

    pub fn on(mut self, machine_id: &str, name: Option<String>, owner_id: i64) -> Self {
        self.machine_id = Some(machine_id.to_owned());
        self.machine_name = name;
        self.owner_id = Some(owner_id);
        self
    }

    pub fn role(mut self, role: Role) -> Self {
        self.role = Some(role);
        self
    }

    pub fn client(mut self, client: &Client) -> Self {
        self.client = client.clone();
        self
    }

    pub fn details(mut self, details: Details) -> Self {
        self.details = details;
        self
    }
}

/// Where events are recorded: a bounded queue to the writer task.
pub struct AuditLog {
    queue: mpsc::Sender<Event>,
    /// Shared with the writer, which adds the events of a batch it failed
    /// to write.
    dropped: Arc<AtomicU64>,
}

impl AuditLog {
    /// The log, and the queue's other end for [`spawn_writer`].
    pub fn new(capacity: usize) -> (Self, mpsc::Receiver<Event>) {
        let (queue, events) = mpsc::channel(capacity);
        (Self { queue, dropped: Arc::new(AtomicU64::new(0)) }, events)
    }

    /// Queues the event without waiting. A full queue drops it: counted,
    /// and said in the log, less often the more there are.
    pub fn record(&self, event: Event) {
        METRICS.audit_event(event.kind);
        match self.queue.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(event)) => {
                let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if dropped.is_power_of_two() {
                    warn!(dropped, kind = event.kind.as_str(), "audit: the log can't keep up, dropping events");
                }
            }
            // Only while shutting down.
            Err(TrySendError::Closed(_)) => {}
        }
    }

    /// Events lost since the relay started: dropped from a full queue, or
    /// in a batch that couldn't be written.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Events waiting for the writer.
    pub fn queued(&self) -> usize {
        self.queue.max_capacity() - self.queue.capacity()
    }

    pub fn capacity(&self) -> usize {
        self.queue.max_capacity()
    }
}

/// The writer task, for [`AuditWriter::flush`] when the relay stops.
pub struct AuditWriter {
    task: JoinHandle<()>,
    stop: oneshot::Sender<()>,
}

impl AuditWriter {
    /// Closes the queue and waits up to `limit` for the writer to write
    /// what was already in it. Events recorded after this are dropped
    /// quietly. False when the time ran out first: what was left is lost.
    pub async fn flush(self, limit: Duration) -> bool {
        let _ = self.stop.send(());
        tokio::time::timeout(limit, self.task).await.is_ok()
    }
}

/// Writes queued events to the database, as many as are waiting (up to a
/// batch) per transaction. A batch that fails is lost, and counted as
/// dropped.
pub fn spawn_writer(log: &AuditLog, db: Db, mut events: mpsc::Receiver<Event>) -> AuditWriter {
    let dropped = Arc::clone(&log.dropped);
    let (stop, mut stopping) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut batch = Vec::with_capacity(BATCH_LEN);
        let mut listening = true;
        loop {
            let received = tokio::select! {
                received = events.recv_many(&mut batch, BATCH_LEN) => received,
                // Told to stop: nothing more gets in, and the loop goes on
                // until what's queued is written. A writer whose handle was
                // dropped instead just carries on.
                stop = &mut stopping, if listening => {
                    listening = false;
                    if stop.is_ok() {
                        events.close();
                    }
                    continue;
                }
            };
            if received == 0 {
                break; // closed, and everything in it written
            }
            let written = std::mem::take(&mut batch);
            let count = written.len();
            if let Err(error) = db.call(move |conn| db::insert_audit_events(conn, &written)).await {
                let total = dropped.fetch_add(count as u64, Ordering::Relaxed) + count as u64;
                error!(%error, count, dropped = total, "audit: writing events failed, they're lost");
            }
        }
    });
    AuditWriter { task, stop }
}

/// `HAWK_AUDIT_RETENTION_DAYS`: how many days events are kept, 0 for
/// forever. Unset: [`DEFAULT_RETENTION_DAYS`].
pub fn retention_days(setting: Option<&str>) -> Result<u32, String> {
    match setting.map(str::trim).filter(|setting| !setting.is_empty()) {
        None => Ok(DEFAULT_RETENTION_DAYS),
        Some(days) => days
            .parse()
            .map_err(|_| format!("HAWK_AUDIT_RETENTION_DAYS: \"{days}\" isn't a number of days (0 keeps events forever)")),
    }
}

/// Deletes events older than the retention; nothing with 0 days.
pub async fn prune(db: &Db, retention_days: u32, now: i64) -> rusqlite::Result<usize> {
    if retention_days == 0 {
        return Ok(0);
    }
    let before = now - i64::from(retention_days) * 24 * 60 * 60;
    // In chunks, letting go of the connection between them: a first prune
    // after the retention was shortened may have millions to go.
    let mut pruned = 0;
    loop {
        let chunk = db.call(move |conn| db::prune_audit_events(conn, before, PRUNE_CHUNK)).await?;
        pruned += chunk;
        if chunk < PRUNE_CHUNK as usize {
            break;
        }
        tokio::task::yield_now().await;
    }
    if pruned > 0 {
        info!(pruned, retention_days, "audit: pruned old events");
    }
    Ok(pruned)
}

// ---- views ----------------------------------------------------------------

/// Who is behind a view, for every event it records.
#[derive(Debug, Clone)]
pub struct ViewContext {
    user_id: i64,
    machine_id: String,
    machine_name: String,
    owner_id: i64,
    role: Role,
    client: Client,
}

impl ViewContext {
    pub fn new(user_id: i64, client: &Client, row: &MachineRow) -> Self {
        Self {
            user_id,
            machine_id: row.public_id.clone(),
            machine_name: row.name.clone(),
            owner_id: row.owner_id,
            role: row.role,
            client: client.clone(),
        }
    }

    pub fn event(&self, kind: Kind) -> Event {
        Event::new(kind)
            .by(self.user_id)
            .on(&self.machine_id, Some(self.machine_name.clone()), self.owner_id)
            .role(self.role)
            .client(&self.client)
    }
}

/// What the relay passed on for a view that the log wants to hear about.
#[derive(Debug, Clone, Copy)]
pub enum Use {
    /// A shell-channel message, of this many sealed bytes.
    Shell(usize),
    /// A file-channel message, of this many sealed bytes.
    Files(usize),
    ClipboardImage,
    Power,
    CtrlAltDel,
    /// A process to end: which one is sealed, so not which.
    EndProcess,
    ConfigChange,
}

/// One view's record: one row when it starts, one when it ends, one the
/// first time it uses a shell, files or pastes a picture, and one per power
/// action, Ctrl+Alt+Del, process ended and config change. Never one per
/// message.
#[derive(Debug)]
pub struct ViewLog {
    context: ViewContext,
    /// When the machine accepted the viewer; None until it has.
    accepted_at: Option<i64>,
    shell: bool,
    files: bool,
    clipboard_image: bool,
    traffic: Traffic,
}

#[derive(Debug, Default)]
struct Traffic {
    shell_up: u64,
    shell_down: u64,
    files_up: u64,
    files_down: u64,
}

fn nonzero(bytes: u64) -> Option<u64> {
    (bytes > 0).then_some(bytes)
}

impl ViewLog {
    pub fn new(context: ViewContext) -> Self {
        Self { context, accepted_at: None, shell: false, files: false, clipboard_image: false, traffic: Traffic::default() }
    }

    /// The role the view was opened with.
    pub fn role(&self) -> Role {
        self.context.role
    }

    /// The machine accepted the viewer: the view starts, once.
    pub fn accepted(&mut self, elevated: bool, now: i64) -> Option<Event> {
        if self.accepted_at.is_some() {
            return None; // a fresh key exchange on a view already going
        }
        self.accepted_at = Some(now);
        Some(self.context.event(Kind::ViewStarted).details(Details { elevated: Some(elevated), ..Details::default() }))
    }

    pub fn rejected(&self, reason: &str) -> Event {
        self.context.event(Kind::ViewRejected).details(Details::reason(reason))
    }

    pub fn elevated(&self) -> Event {
        self.context.event(Kind::ViewElevated)
    }

    /// Something was passed on to the machine.
    pub fn used(&mut self, used: Use) -> Option<Event> {
        let first = |seen: &mut bool| !std::mem::replace(seen, true);
        let kind = match used {
            Use::Shell(bytes) => {
                self.traffic.shell_up += bytes as u64;
                first(&mut self.shell).then_some(Kind::ShellUsed)?
            }
            Use::Files(bytes) => {
                self.traffic.files_up += bytes as u64;
                first(&mut self.files).then_some(Kind::FilesUsed)?
            }
            Use::ClipboardImage => first(&mut self.clipboard_image).then_some(Kind::ClipboardImagePasted)?,
            Use::Power => Kind::Power,
            Use::CtrlAltDel => Kind::CtrlAltDel,
            Use::EndProcess => Kind::EndProcess,
            Use::ConfigChange => Kind::ConfigChanged,
        };
        Some(self.context.event(kind))
    }

    /// The machine sent the viewer this many sealed bytes of shell output.
    pub fn shell_received(&mut self, bytes: usize) {
        self.traffic.shell_down += bytes as u64;
    }

    /// The machine sent the viewer this many sealed bytes of file data.
    pub fn files_received(&mut self, bytes: usize) {
        self.traffic.files_down += bytes as u64;
    }

    /// The view is over: how long it lasted and what went through it. None
    /// for one the machine never accepted.
    pub fn ended(&self, now: i64) -> Option<Event> {
        let started = self.accepted_at?;
        let traffic = &self.traffic;
        Some(self.context.event(Kind::ViewEnded).details(Details {
            seconds: Some((now - started).max(0)),
            shell_up: nonzero(traffic.shell_up),
            shell_down: nonzero(traffic.shell_down),
            files_up: nonzero(traffic.files_up),
            files_down: nonzero(traffic.files_down),
            ..Details::default()
        }))
    }
}

// ---- reading it -----------------------------------------------------------

/// A page when none is asked for, and the most one can be.
const DEFAULT_PAGE: i64 = 50;
const MAX_PAGE: i64 = 200;
/// Longer than any machine id.
const MAX_MACHINE_ID_LEN: usize = 64;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditQuery {
    /// One machine's events (its id).
    #[serde(default)]
    machine: Option<String>,
    /// What this account did or had done to it.
    #[serde(default)]
    user: Option<i64>,
    /// Kinds, comma separated.
    #[serde(default)]
    kind: Option<String>,
    /// Unix seconds, inclusive.
    #[serde(default)]
    since: Option<i64>,
    #[serde(default)]
    until: Option<i64>,
    /// The `next` of the page before: only older events.
    #[serde(default)]
    before: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
}

impl AuditQuery {
    fn filter(self, visible_to: Option<i64>) -> Result<AuditFilter, ApiError> {
        let mut kinds = Vec::new();
        for name in self.kind.iter().flat_map(|kinds| kinds.split(',')).map(str::trim).filter(|name| !name.is_empty()) {
            let kind = Kind::parse(name).ok_or_else(|| ApiError::bad_request(format!("unknown event kind \"{name}\"")))?;
            kinds.push(kind.as_str());
        }
        if self.machine.as_ref().is_some_and(|machine| machine.len() > MAX_MACHINE_ID_LEN) {
            return Err(ApiError::bad_request("invalid machine id"));
        }
        Ok(AuditFilter {
            visible_to,
            machine_id: self.machine.filter(|machine| !machine.is_empty()),
            user_id: self.user,
            kinds,
            since: self.since,
            until: self.until,
            before: self.before,
            limit: self.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE),
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventView {
    id: i64,
    at: i64,
    kind: String,
    user_id: Option<i64>,
    user_email: Option<String>,
    subject_id: Option<i64>,
    subject_email: Option<String>,
    machine_id: Option<String>,
    machine_name: Option<String>,
    role: Option<String>,
    ip: Option<String>,
    user_agent: Option<String>,
    details: Details,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventPage {
    /// Newest first.
    events: Vec<EventView>,
    /// Pass as `before` for the next (older) page; None on the last.
    next: Option<i64>,
}

async fn page(state: &AppState, mut filter: AuditFilter) -> Result<Json<EventPage>, ApiError> {
    let limit = filter.limit;
    let viewer = filter.visible_to;
    // One more than asked, to know whether there's another page.
    filter.limit = limit + 1;
    let mut rows = state.db.call(move |conn| db::audit_events(conn, &filter)).await?;
    let more = rows.len() as i64 > limit;
    rows.truncate(usize::try_from(limit).unwrap_or(0));
    let next = if more { rows.last().map(|row| row.id) } else { None };
    let events = rows
        .into_iter()
        .map(|mut row| {
            // Where someone else was is theirs to see, and the owner's of the
            // machine it was on; not the account it was done to (a shared
            // user doesn't learn the owner's address from a share, nor a user
            // the admin's from being disabled).
            if viewer.is_some_and(|me| row.user_id != Some(me) && row.owner_id != Some(me)) {
                row.ip = None;
                row.user_agent = None;
            }
            row
        })
        .map(|row| EventView {
            id: row.id,
            at: row.at,
            kind: row.kind,
            user_id: row.user_id,
            user_email: row.user_email,
            subject_id: row.subject_id,
            subject_email: row.subject_email,
            machine_id: row.machine_id,
            machine_name: row.machine_name,
            role: row.role,
            ip: row.ip,
            user_agent: row.user_agent,
            details: row.details.and_then(|details| serde_json::from_str(&details).ok()).unwrap_or_default(),
        })
        .collect();
    Ok(Json(EventPage { events, next }))
}

/// The caller's view of the log: what they did, what was done to their
/// account, and everything on the machines they own. A machine shared with
/// them shows only their own doings there.
pub async fn list(
    State(state): State<AppState>,
    current: CurrentUser,
    Query(query): Query<AuditQuery>,
) -> Result<Json<EventPage>, ApiError> {
    page(&state, query.filter(Some(current.user.id))?).await
}

/// Everything, for the admin.
pub async fn admin_list(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(query): Query<AuditQuery>,
) -> Result<Json<EventPage>, ApiError> {
    page(&state, query.filter(None)?).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::Request;
    use tokio::sync::Notify;

    use super::*;
    use crate::auth::{AccountLimiter, AllowedOrigins, LoginLimiter};
    use crate::db::AccountFlags;
    use crate::mfa::LoginTickets;
    use crate::registry::Registry;
    use crate::totp::SecretKey;

    fn test_state() -> (AppState, mpsc::Receiver<Event>) {
        let (audit, events) = AuditLog::new(QUEUE_LEN);
        let audit = Arc::new(audit);
        let (view_ended, _) = mpsc::unbounded_channel();
        let state = AppState {
            registry: Arc::new(Registry::new(view_ended, audit.clone())),
            db: Db::open_in_memory(),
            limiter: Arc::new(LoginLimiter::default()),
            secure_cookies: false,
            relay_pin: None,
            shares_changed: Arc::new(Notify::new()),
            mfa_limiter: Arc::new(AccountLimiter::default()),
            mfa_tickets: Arc::new(LoginTickets::default()),
            secret_key: Arc::new(SecretKey::from_bytes(&[7; 32]).unwrap()),
            totp_issuer: "Hawk (test)".into(),
            mailer: None,
            allowed_origins: Arc::new(AllowedOrigins::default()),
            audit,
            passkeys: Arc::new(crate::passkeys::Passkeys::new(None)),
        };
        (state, events)
    }

    /// Owner 1 with machine "m1", shared with 2; 3 has nothing to do with
    /// it; 4 is the admin.
    async fn seed(db: &Db) {
        db.call(|conn| {
            for (id, admin) in [(1, false), (2, false), (3, false), (4, true)] {
                conn.execute(
                    "INSERT INTO users (id, email, password_hash, is_admin, created_at) VALUES (?1, ?2, 'x', ?3, 0)",
                    rusqlite::params![id, format!("user{id}@example.com"), admin],
                )?;
            }
            conn.execute(
                "INSERT INTO machines (public_id, owner_id, name, hostname, key_fingerprint, created_at)
                 VALUES ('m1', 1, 'desk', 'desk', x'01', 0)",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }

    fn row(role: Role) -> MachineRow {
        MachineRow {
            public_id: "m1".to_owned(),
            owner_id: 1,
            owner_email: "user1@example.com".to_owned(),
            name: "desk".to_owned(),
            hostname: "desk".to_owned(),
            last_seen_at: None,
            key_storage: None,
            role,
            share_expires_at: None,
            single_view: false,
            analytics: false,
            public_key: None,
            owner_public_key: None,
            endorsement: None,
            enroll_code_hash: None,
            enroll_binding: None,
            grant: None,
        }
    }

    async fn write(db: &Db, events: Vec<Event>) {
        db.call(move |conn| db::insert_audit_events(conn, &events)).await.unwrap();
    }

    fn current(user_id: i64, is_admin: bool) -> CurrentUser {
        CurrentUser {
            user: db::User { id: user_id, email: format!("user{user_id}@example.com"), is_admin },
            session_id: user_id,
            step_up_at: None,
            account: AccountFlags { mfa: false, email_verified: true, mfa_required: false, passkeys: false },
        }
    }

    async fn kinds_for(state: &AppState, user_id: i64, query: AuditQuery) -> Vec<(String, Option<i64>)> {
        let Json(page) = list(State(state.clone()), current(user_id, false), Query(query)).await.unwrap();
        page.events.into_iter().map(|event| (event.kind, event.user_id)).collect()
    }

    /// The owner sees everything on their machine; a shared user only their
    /// own doings there and what was done to them; someone else nothing of
    /// it; the admin everything, and only the admin gets the admin list.
    #[tokio::test]
    async fn who_sees_what() {
        let (state, _events) = test_state();
        seed(&state.db).await;
        let shared = ViewContext::new(2, &Client::default(), &row(Role::Control));
        let owned = ViewContext::new(1, &Client::default(), &row(Role::Owner));
        write(
            &state.db,
            vec![
                Event::new(Kind::SignIn).by(1),
                Event::new(Kind::ShareGranted).by(1).about(2).on("m1", Some("desk".into()), 1),
                owned.event(Kind::ViewStarted),
                owned.event(Kind::ShellUsed),
                shared.event(Kind::ViewStarted),
                shared.event(Kind::Power),
                Event::new(Kind::SignIn).by(3),
                Event::new(Kind::SignInFailed),
            ],
        )
        .await;

        let owner = kinds_for(&state, 1, AuditQuery::default()).await;
        assert_eq!(owner.len(), 6, "{owner:?}");
        assert!(owner.iter().all(|(kind, user)| *user != Some(3) && kind != "sign_in_failed"));

        let sharee = kinds_for(&state, 2, AuditQuery::default()).await;
        assert_eq!(
            sharee,
            [("power".to_owned(), Some(2)), ("view_started".to_owned(), Some(2)), ("share_granted".to_owned(), Some(1))]
        );
        // The machine's own page, for a shared user, is still only theirs.
        let on_machine = kinds_for(&state, 2, AuditQuery { machine: Some("m1".into()), ..AuditQuery::default() }).await;
        assert_eq!(on_machine.len(), 3);

        let stranger = kinds_for(&state, 3, AuditQuery { machine: Some("m1".into()), ..AuditQuery::default() }).await;
        assert!(stranger.is_empty());
        assert_eq!(kinds_for(&state, 3, AuditQuery::default()).await, [("sign_in".to_owned(), Some(3))]);

        let Json(all) = admin_list(State(state.clone()), AdminUser(current(4, true)), Query(AuditQuery::default()))
            .await
            .unwrap();
        assert_eq!(all.events.len(), 8);
        assert_eq!(all.events[0].user_email, None);
        assert_eq!(all.events[1].user_email.as_deref(), Some("user3@example.com"));

        // The admin extractor itself: a signed-in non-admin is refused.
        for (user_id, allowed) in [(3, false), (4, true)] {
            let token = format!("token-{user_id}");
            let hash = auth::token_hash(&token);
            state
                .db
                .call(move |conn| {
                    let origin = SessionOrigin { user_agent: None, ip: "127.0.0.1".into() };
                    db::create_session(conn, &hash, user_id, &origin, 0, i64::MAX, None)
                })
                .await
                .unwrap();
            let (mut parts, ()) =
                Request::builder().header("cookie", format!("hawk_session={token}")).body(()).unwrap().into_parts();
            let admin = AdminUser::from_request_parts(&mut parts, &state).await;
            assert_eq!(admin.is_ok(), allowed, "user {user_id}");
            assert!(allowed || matches!(admin, Err(ApiError::Forbidden)));
        }
    }

    /// Pages walk the log newest first without repeating or skipping, and
    /// the filters narrow it.
    #[tokio::test]
    async fn pages_follow_the_cursor() {
        let (state, _events) = test_state();
        seed(&state.db).await;
        let events = (0..25)
            .map(|at| {
                let mut event = Event::new(if at % 5 == 0 { Kind::Power } else { Kind::SignIn }).by(1);
                event.at = 1000 + at;
                event
            })
            .collect();
        write(&state.db, events).await;

        let mut seen = Vec::new();
        let mut before = None;
        loop {
            let query = AuditQuery { limit: Some(10), before, ..AuditQuery::default() };
            let Json(page) = list(State(state.clone()), current(1, false), Query(query)).await.unwrap();
            assert!(page.events.len() <= 10);
            seen.extend(page.events.iter().map(|event| event.at));
            match page.next {
                Some(next) => before = Some(next),
                None => break,
            }
        }
        assert_eq!(seen, (1000..1025).rev().collect::<Vec<_>>());

        let query = AuditQuery { kind: Some("power".into()), since: Some(1005), until: Some(1015), ..AuditQuery::default() };
        let Json(page) = list(State(state.clone()), current(1, false), Query(query)).await.unwrap();
        assert_eq!(page.events.iter().map(|event| event.at).collect::<Vec<_>>(), [1015, 1010, 1005]);
        assert_eq!(page.next, None);

        // Exactly a page's worth: no next.
        let query = AuditQuery { limit: Some(25), ..AuditQuery::default() };
        let Json(page) = list(State(state.clone()), current(1, false), Query(query)).await.unwrap();
        assert_eq!((page.events.len(), page.next), (25, None));

        let query = AuditQuery { kind: Some("power,nonsense".into()), ..AuditQuery::default() };
        assert!(matches!(
            list(State(state.clone()), current(1, false), Query(query)).await,
            Err(ApiError::BadRequest(_))
        ));
    }

    /// Events past the retention go; newer ones stay; 0 days keeps all.
    #[tokio::test]
    async fn pruning_keeps_the_retention() {
        let (state, _events) = test_state();
        let day = 24 * 60 * 60;
        let now = 1_000 * day;
        let events = [now - 91 * day, now - 90 * day - 1, now - 89 * day, now]
            .into_iter()
            .map(|at| {
                let mut event = Event::new(Kind::SignIn).by(1);
                event.at = at;
                event
            })
            .collect();
        write(&state.db, events).await;
        assert_eq!(prune(&state.db, 0, now).await.unwrap(), 0);
        assert_eq!(prune(&state.db, 90, now).await.unwrap(), 2);
        assert_eq!(prune(&state.db, 90, now).await.unwrap(), 0);
        let filter = AuditFilter { limit: 10, ..AuditFilter::default() };
        let left = state.db.call(move |conn| db::audit_events(conn, &filter)).await.unwrap();
        assert_eq!(left.iter().map(|row| row.at).collect::<Vec<_>>(), [now, now - 89 * day]);

        assert_eq!(retention_days(None), Ok(DEFAULT_RETENTION_DAYS));
        assert_eq!(retention_days(Some(" 30 ")), Ok(30));
        assert_eq!(retention_days(Some("0")), Ok(0));
        assert!(retention_days(Some("-1")).is_err());
        assert!(retention_days(Some("a month")).is_err());
    }

    /// A batch the database refuses is lost, and counted with the dropped.
    #[tokio::test]
    async fn a_failed_batch_counts_as_dropped() {
        let db = Db::open_in_memory();
        db.call(|conn| conn.execute_batch("DROP TABLE audit_events")).await.unwrap();
        let (log, events) = AuditLog::new(8);
        spawn_writer(&log, db, events);
        for _ in 0..3 {
            log.record(Event::new(Kind::SignIn).by(1));
        }
        for _ in 0..100 {
            if log.dropped() == 3 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(log.dropped(), 3);
    }

    /// A full queue drops and counts, never waits; what got in is written.
    #[tokio::test]
    async fn a_full_queue_drops_instead_of_waiting() {
        let db = Db::open_in_memory();
        let (log, events) = AuditLog::new(3);
        for _ in 0..10 {
            log.record(Event::new(Kind::SignIn).by(1));
        }
        assert_eq!(log.dropped(), 7);
        spawn_writer(&log, db.clone(), events);
        // Room again once the writer has taken them.
        for _ in 0..50 {
            if log.queue.capacity() == 3 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        log.record(Event::new(Kind::SignIn).by(1));
        assert_eq!(log.dropped(), 7);
        let mut written = 0;
        for _ in 0..50 {
            let filter = AuditFilter { limit: 100, ..AuditFilter::default() };
            written = db.call(move |conn| db::audit_events(conn, &filter)).await.unwrap().len();
            if written == 4 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(written, 4);
    }

    /// Every row as stored, as one string, to look for what mustn't be there.
    async fn everything_stored(db: &Db) -> String {
        db.call(|conn| {
            let mut statement = conn.prepare("SELECT * FROM audit_events")?;
            let columns = statement.column_count();
            let rows = statement.query_map([], |row| {
                let mut text = String::new();
                for column in 0..columns {
                    match row.get_ref(column)? {
                        rusqlite::types::ValueRef::Text(bytes) => text.push_str(&String::from_utf8_lossy(bytes)),
                        other => text.push_str(&format!("{other:?}")),
                    }
                    text.push('|');
                }
                Ok(text)
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map(|rows| rows.join("\n"))
        })
        .await
        .unwrap()
    }

    async fn drain(state: &AppState, events: &mut mpsc::Receiver<Event>) {
        let mut batch = Vec::new();
        while let Ok(event) = events.try_recv() {
            batch.push(event);
        }
        write(&state.db, batch).await;
    }

    /// What passes through the relay sealed, and the codes and tickets of a
    /// sign-in, never reach the log; the table has nowhere to put them.
    #[tokio::test]
    async fn no_secrets_are_recorded() {
        use crate::protocol::{PROTOCOL_VERSION, SignedView};
        use crate::registry::{DashboardHandle, DeviceInfo, StepUp};

        let (state, mut events) = test_state();
        seed(&state.db).await;
        const SECRET: &str = "S3CR3T-SEALED-PAYLOAD";

        // A view with every sealed channel used.
        let registry = &state.registry;
        let (outbound, _device_rx) = mpsc::unbounded_channel();
        registry.add_device("m1", 1, DeviceInfo { version: None, protocol: PROTOCOL_VERSION }, outbound);
        let (dashboard_events, _dashboard_rx) = mpsc::unbounded_channel();
        let (frames, _frames_rx) = mpsc::channel(1);
        let (bulk, _bulk_rx) = mpsc::channel(8);
        let handle = DashboardHandle {
            events: dashboard_events,
            frames,
            bulk,
            user_id: 1,
            session_id: 1,
            email: "user1@example.com".into(),
            step_up: StepUp::default(),
            client: Client { ip: Some("192.0.2.7".into()), user_agent: Some("Firefox".into()) },
        };
        let dashboard = registry.add_dashboard(handle, vec![row(Role::Owner)]);
        assert!(registry.start_view(dashboard, "m1", SignedView { statement: SECRET.into(), signature: SECRET.into() }));
        let accept = crate::registry::Answer::Accept {
            statement: SECRET.into(),
            signature: SECRET.into(),
            wrapped_key: SECRET.into(),
            clipboard: "sync",
            files: true,
            shell: true,
            analytics: true,
            clipboard_images: true,
        };
        registry.answer("m1", dashboard, accept);
        assert!(registry.shell(dashboard, "m1", SECRET.into()));
        assert!(registry.shell(dashboard, "m1", SECRET.into()));
        assert!(registry.file(dashboard, "m1", SECRET.into()));
        assert!(registry.power(dashboard, "m1", SECRET.into()));
        assert!(registry.sas(dashboard, "m1", SECRET.into()));
        assert!(registry.end_process(dashboard, "m1", SECRET.into()));
        assert!(registry.config_set(dashboard, "m1", SECRET.into()));
        assert!(registry.clipboard_image_put(dashboard, "m1", SECRET.into()));
        assert!(registry.input(dashboard, "m1", SECRET.into()));
        assert!(registry.clipboard(dashboard, "m1", SECRET.into()));
        let shell_out = crate::protocol::DashboardEvent::Shell { device_id: "m1".into(), sealed: SECRET.into() };
        assert!(registry.forward_bulk("m1", dashboard, shell_out));
        registry.stop_view(dashboard, "m1");

        // A wrong code at the second step of a sign-in, and at step-up.
        let ticket = state.mfa_tickets.issue(2, SessionOrigin { user_agent: None, ip: "198.51.100.1".into() });
        let wrong = serde_json::from_value(serde_json::json!({ "ticket": ticket, "code": "123456" })).unwrap();
        let headers = axum::http::HeaderMap::new();
        let peer: SocketAddr = "198.51.100.1:5000".parse().unwrap();
        let jar = axum_extra::extract::cookie::CookieJar::new();
        assert!(api::login_mfa(State(state.clone()), ConnectInfo(peer), headers, jar, Json(wrong)).await.is_err());

        drain(&state, &mut events).await;
        let stored = everything_stored(&state.db).await;
        for kind in ["view_started", "shell_used", "files_used", "power", "ctrl_alt_del", "end_process", "config_changed"] {
            assert!(stored.contains(kind), "{kind} missing from {stored}");
        }
        assert!(stored.contains("clipboard_image_pasted") && stored.contains("view_ended") && stored.contains("mfa_failed"));
        assert_eq!(stored.matches("shell_used").count(), 1, "one row per shell, not per message");
        assert!(stored.contains("192.0.2.7") && stored.contains("198.51.100.1"));
        for secret in [SECRET, "123456", ticket.as_str()] {
            assert!(!stored.contains(secret), "{secret} was recorded: {stored}");
        }

        // Nowhere to put a secret even by mistake.
        let columns: Vec<String> = state
            .db
            .call(|conn| {
                conn.prepare("SELECT name FROM pragma_table_info('audit_events')")?
                    .query_map([], |row| row.get(0))?
                    .collect()
            })
            .await
            .unwrap();
        for column in &columns {
            for word in ["password", "token", "secret", "code", "sealed", "key", "hash", "signature"] {
                assert!(!column.contains(word), "audit_events.{column}");
            }
        }
    }

    fn from(ip: &str) -> Client {
        Client { ip: Some(ip.into()), user_agent: Some(format!("UA {ip}")) }
    }

    async fn page_for(state: &AppState, user_id: i64, query: AuditQuery) -> Vec<EventView> {
        let Json(page) = list(State(state.clone()), current(user_id, false), Query(query)).await.unwrap();
        page.events
    }

    async fn admin_page(state: &AppState, query: AuditQuery) -> Vec<EventView> {
        let Json(page) = admin_list(State(state.clone()), AdminUser(current(4, true)), Query(query)).await.unwrap();
        page.events
    }

    fn summary(events: &[EventView]) -> Vec<(&str, Option<i64>, Option<i64>)> {
        events.iter().map(|event| (event.kind.as_str(), event.user_id, event.subject_id)).collect()
    }

    fn query(machine: Option<&str>, user: Option<i64>) -> AuditQuery {
        AuditQuery { machine: machine.map(str::to_owned), user, ..AuditQuery::default() }
    }

    /// Owner 1's "m1" is shared with 2 and 5; 1 also owns "m2", shared with
    /// no one. A shared user sees their own doings and what was done to
    /// them, never the other shared user's, the owner's elsewhere, or anyone
    /// else's address; no filter widens that; a revoked share keeps only
    /// the old rows about them.
    #[tokio::test]
    async fn filters_never_widen_what_a_user_sees() {
        let (state, _events) = test_state();
        seed(&state.db).await;
        state
            .db
            .call(|conn| {
                conn.execute(
                    "INSERT INTO users (id, email, password_hash, is_admin, created_at)
                     VALUES (5, 'user5@example.com', 'x', 0, 0)",
                    [],
                )
            })
            .await
            .unwrap();
        let two = ViewContext::new(2, &from("10.0.0.2"), &row(Role::Control));
        let five = ViewContext::new(5, &from("10.0.0.5"), &row(Role::Control));
        let mut m2 = row(Role::Owner);
        m2.public_id = "m2".into();
        let owner_elsewhere = ViewContext::new(1, &from("10.0.0.1"), &m2);
        let owner = from("10.0.0.1");
        let grant = |user| Event::new(Kind::ShareGranted).by(1).about(user).on("m1", Some("desk".into()), 1).client(&owner);
        write(
            &state.db,
            vec![
                grant(2),                                                            // 1
                grant(5),                                                            // 2
                two.event(Kind::ViewStarted),                                        // 3
                two.event(Kind::ShellUsed),                                          // 4
                two.event(Kind::ViewEnded),                                          // 5
                five.event(Kind::ViewStarted),                                       // 6
                five.event(Kind::Power),                                             // 7
                owner_elsewhere.event(Kind::ViewStarted),                            // 8
                Event::new(Kind::SignIn).by(1).client(&owner),                       // 9
                Event::new(Kind::UserDisabled).by(4).about(2).client(&from("10.0.0.4")), // 10
                Event::new(Kind::ShareRevoked).by(1).about(2).on("m1", Some("desk".into()), 1).client(&owner), // 11
                five.event(Kind::ViewEnded),                                         // 12, after 2 lost it
                Event::new(Kind::SignInFailed).by(2).client(&from("203.0.113.9")),   // 13
            ],
        )
        .await;

        // Shared user 2: their own and what was done to them, nothing of 5's,
        // nothing on m2, not the owner's sign-in.
        let mine = page_for(&state, 2, AuditQuery::default()).await;
        assert_eq!(
            summary(&mine),
            [
                ("sign_in_failed", Some(2), None),
                ("share_revoked", Some(1), Some(2)),
                ("user_disabled", Some(4), Some(2)),
                ("view_ended", Some(2), None),
                ("shell_used", Some(2), None),
                ("view_started", Some(2), None),
                ("share_granted", Some(1), Some(2)),
            ]
        );
        // Their own addresses (a failed sign-in's too); not the owner's or the
        // admin's on what those did to them.
        for event in &mine {
            let theirs = event.user_id == Some(2);
            assert_eq!(event.ip.is_some(), theirs, "{}", event.kind);
            assert_eq!(event.user_agent.is_some(), theirs, "{}", event.kind);
            assert!(event.ip.as_deref().is_none_or(|ip| ip == "10.0.0.2" || ip == "203.0.113.9"));
        }
        // Filters only narrow.
        for (machine, user) in [
            (Some("m1"), Some(5)),
            (None, Some(5)),
            (Some("m2"), None),
            (Some("m2"), Some(1)),
            (Some("m1' OR '1'='1"), None),
            (Some("m1\" OR 1=1 --"), Some(2)),
        ] {
            assert!(page_for(&state, 2, query(machine, user)).await.is_empty(), "{machine:?} {user:?}");
        }
        // The owner's doings that concern them, and only those.
        let by_owner = page_for(&state, 2, query(None, Some(1))).await;
        assert_eq!(summary(&by_owner), [("share_revoked", Some(1), Some(2)), ("share_granted", Some(1), Some(2))]);
        assert_eq!(page_for(&state, 2, query(Some("m1"), None)).await.len(), 5);
        let power = AuditQuery { kind: Some("power".into()), ..AuditQuery::default() };
        assert!(page_for(&state, 2, power).await.is_empty());
        let injected = AuditQuery { kind: Some("power') OR 1=1 --".into()), ..AuditQuery::default() };
        assert!(matches!(list(State(state.clone()), current(2, false), Query(injected)).await, Err(ApiError::BadRequest(_))));

        // Shared user 5 sees none of 2's, and the view that ended after 2's
        // share was revoked is still theirs.
        let five_sees = page_for(&state, 5, AuditQuery::default()).await;
        assert_eq!(
            summary(&five_sees),
            [("view_ended", Some(5), None), ("power", Some(5), None), ("view_started", Some(5), None), ("share_granted", Some(1), Some(5))]
        );

        // The owner: everything on their machines, with every address, their
        // own sign-in; not what the admin did to 2, nor 2's failed sign-in.
        let owner_sees = page_for(&state, 1, AuditQuery::default()).await;
        assert_eq!(owner_sees.iter().map(|event| event.id).collect::<Vec<_>>(), [12, 11, 9, 8, 7, 6, 5, 4, 3, 2, 1]);
        assert!(owner_sees.iter().all(|event| event.ip.is_some()));
        assert_eq!(owner_sees.iter().find(|event| event.id == 7).unwrap().ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(page_for(&state, 1, query(Some("m1"), Some(5))).await.len(), 4);
        assert_eq!(page_for(&state, 1, query(Some("m2"), Some(2))).await.len(), 0);

        // Someone unrelated: nothing, whatever they ask for.
        for (machine, user) in [(None, None), (Some("m1"), None), (None, Some(2)), (Some("m1"), Some(1))] {
            assert!(page_for(&state, 3, query(machine, user)).await.is_empty(), "{machine:?} {user:?}");
        }

        // The admin's own page is only theirs; the admin list everything,
        // with the addresses.
        assert_eq!(summary(&page_for(&state, 4, AuditQuery::default()).await), [("user_disabled", Some(4), Some(2))]);
        let about_two = admin_page(&state, query(None, Some(2))).await;
        assert_eq!(about_two.iter().map(|event| event.id).collect::<Vec<_>>(), [13, 11, 10, 5, 4, 3, 1]);
        assert!(about_two.iter().all(|event| event.ip.is_some()));
        assert_eq!(admin_page(&state, query(Some("m1"), Some(5))).await.len(), 4);
        assert_eq!(admin_page(&state, AuditQuery::default()).await.len(), 13);
    }

    fn accept() -> crate::registry::Answer {
        crate::registry::Answer::Accept {
            statement: String::new(),
            signature: String::new(),
            wrapped_key: String::new(),
            clipboard: "sync",
            files: true,
            shell: true,
            analytics: false,
            clipboard_images: true,
        }
    }

    fn drained(events: &mut mpsc::Receiver<Event>) -> Vec<&'static str> {
        let mut kinds = Vec::new();
        while let Ok(event) = events.try_recv() {
            kinds.push(event.kind.as_str());
        }
        kinds
    }

    /// Every way a view can end writes exactly one view_ended, and a view
    /// the machine never accepted none.
    #[tokio::test]
    async fn every_view_ends_exactly_once() {
        use crate::protocol::{PROTOCOL_VERSION, SignedView};
        use crate::registry::{DashboardHandle, DeviceInfo, StepUp};

        #[derive(Debug, Clone, Copy)]
        enum End {
            StopView,
            DashboardThenDevice,
            DeviceThenDashboard,
            DeviceReplaced,
            Revoked,
            MachineRemoved,
            UserClosed,
            Rejected,
            StopTwiceThenEverything,
        }
        for end in [
            End::StopView,
            End::DashboardThenDevice,
            End::DeviceThenDashboard,
            End::DeviceReplaced,
            End::Revoked,
            End::MachineRemoved,
            End::UserClosed,
            End::Rejected,
            End::StopTwiceThenEverything,
        ] {
            let (state, mut events) = test_state();
            let registry = &state.registry;
            let (outbound, _device_rx) = mpsc::unbounded_channel();
            let connection = registry.add_device("m1", 1, DeviceInfo { version: None, protocol: PROTOCOL_VERSION }, outbound);
            let (dashboard_events, _dashboard_rx) = mpsc::unbounded_channel();
            let (frames, _frames_rx) = mpsc::channel(1);
            let (bulk, _bulk_rx) = mpsc::channel(8);
            let handle = DashboardHandle {
                events: dashboard_events,
                frames,
                bulk,
                user_id: 2,
                session_id: 2,
                email: "user2@example.com".into(),
                step_up: StepUp::default(),
                client: Client::default(),
            };
            let dashboard = registry.add_dashboard(handle, vec![row(Role::Control)]);
            let join = || SignedView { statement: String::new(), signature: String::new() };
            assert!(registry.start_view(dashboard, "m1", join()));
            registry.answer("m1", dashboard, accept());
            // A fresh key exchange on the same view starts nothing new.
            assert!(registry.start_view(dashboard, "m1", join()));
            registry.answer("m1", dashboard, accept());

            match end {
                End::StopView => registry.stop_view(dashboard, "m1"),
                End::DashboardThenDevice => {
                    registry.remove_dashboard(dashboard);
                    registry.remove_device("m1", connection, 0);
                }
                End::DeviceThenDashboard => {
                    registry.remove_device("m1", connection, 0);
                    registry.remove_dashboard(dashboard);
                }
                End::DeviceReplaced => {
                    let (outbound, _rx) = mpsc::unbounded_channel();
                    registry.add_device("m1", 1, DeviceInfo { version: None, protocol: PROTOCOL_VERSION }, outbound);
                    registry.remove_device("m1", connection, 0); // the old one's late goodbye
                    registry.remove_dashboard(dashboard);
                }
                End::Revoked => {
                    registry.revoke(2, "m1");
                    registry.remove_dashboard(dashboard);
                }
                End::MachineRemoved => {
                    registry.remove_machine("m1");
                    registry.remove_dashboard(dashboard);
                }
                End::UserClosed => {
                    registry.close_user(2);
                    registry.remove_dashboard(dashboard);
                    registry.remove_device("m1", connection, 0);
                }
                End::Rejected => {
                    registry.answer("m1", dashboard, crate::registry::Answer::Reject { reason: "no".into() });
                    registry.remove_dashboard(dashboard);
                }
                End::StopTwiceThenEverything => {
                    registry.stop_view(dashboard, "m1");
                    registry.stop_view(dashboard, "m1");
                    registry.remove_dashboard(dashboard);
                    registry.remove_device("m1", connection, 0);
                }
            }
            let kinds = drained(&mut events);
            assert_eq!(kinds.iter().filter(|kind| **kind == "view_started").count(), 1, "{end:?}: {kinds:?}");
            assert_eq!(kinds.iter().filter(|kind| **kind == "view_ended").count(), 1, "{end:?}: {kinds:?}");
            assert_eq!(kinds.last(), Some(&"view_ended"), "{end:?}: {kinds:?}");
        }

        // Refused outright: a rejection, no start, no end.
        let (state, mut events) = test_state();
        let registry = &state.registry;
        let (outbound, _device_rx) = mpsc::unbounded_channel();
        registry.add_device("m1", 1, DeviceInfo { version: None, protocol: PROTOCOL_VERSION }, outbound);
        let (dashboard_events, _dashboard_rx) = mpsc::unbounded_channel();
        let (frames, _frames_rx) = mpsc::channel(1);
        let (bulk, _bulk_rx) = mpsc::channel(8);
        let handle = DashboardHandle {
            events: dashboard_events,
            frames,
            bulk,
            user_id: 2,
            session_id: 2,
            email: "user2@example.com".into(),
            step_up: StepUp::default(),
            client: Client::default(),
        };
        let dashboard = registry.add_dashboard(handle, vec![row(Role::Control)]);
        assert!(registry.start_view(dashboard, "m1", SignedView { statement: String::new(), signature: String::new() }));
        registry.answer("m1", dashboard, crate::registry::Answer::Reject { reason: "busy".into() });
        registry.remove_dashboard(dashboard);
        assert_eq!(drained(&mut events), ["view_rejected"]);
    }

    /// One row the first time a view uses a shell, files or pastes a
    /// picture; one per power action; the end carries the length and the
    /// traffic both ways. A new view starts counting afresh.
    #[test]
    fn a_view_log_counts_once_and_times_right() {
        let context = ViewContext::new(2, &Client::default(), &row(Role::Control));
        let mut log = ViewLog::new(context.clone());
        assert!(log.ended(500).is_none(), "never accepted");
        assert!(log.used(Use::Shell(1)).is_some_and(|event| event.kind == Kind::ShellUsed));
        let started = log.accepted(false, 100).unwrap();
        assert_eq!((started.kind, started.details.elevated), (Kind::ViewStarted, Some(false)));
        assert!(log.accepted(true, 130).is_none(), "a rekey isn't a new view");
        assert!(log.used(Use::Shell(10)).is_none(), "the shell was already used");
        assert!(log.used(Use::Files(7)).is_some_and(|event| event.kind == Kind::FilesUsed));
        assert!(log.used(Use::Files(3)).is_none());
        assert!(log.used(Use::ClipboardImage).is_some());
        assert!(log.used(Use::ClipboardImage).is_none());
        assert!(log.used(Use::Power).is_some() && log.used(Use::Power).is_some());
        log.shell_received(4);
        log.files_received(0);
        let ended = log.ended(142).unwrap();
        assert_eq!(ended.kind, Kind::ViewEnded);
        assert_eq!(
            ended.details,
            Details { seconds: Some(42), shell_up: Some(11), shell_down: Some(4), files_up: Some(10), ..Details::default() }
        );
        // Clock skew never makes a negative length.
        assert_eq!(log.ended(50).unwrap().details.seconds, Some(0));

        let mut again = ViewLog::new(context);
        again.accepted(true, 200);
        assert!(again.used(Use::Shell(1)).is_some(), "a new view, a new first shell");
    }

    /// A failed batch is logged and the writer goes on with the next.
    #[tokio::test]
    async fn the_writer_survives_a_failed_write() {
        let db = Db::open_in_memory();
        let (log, events) = AuditLog::new(8);
        spawn_writer(&log, db.clone(), events);
        let hide = |sql: &'static str| {
            let db = db.clone();
            async move { db.call(move |conn| conn.execute_batch(sql)).await.unwrap() }
        };
        hide("ALTER TABLE audit_events RENAME TO audit_events_away").await;
        log.record(Event::new(Kind::SignIn).by(1));
        for _ in 0..100 {
            if log.queue.capacity() == 8 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        // Taken off the queue; give the failing insert time to finish.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        hide("ALTER TABLE audit_events_away RENAME TO audit_events").await;
        log.record(Event::new(Kind::SignIn).by(2));
        let mut written = Vec::new();
        for _ in 0..100 {
            let filter = AuditFilter { limit: 10, ..AuditFilter::default() };
            written = db.call(move |conn| db::audit_events(conn, &filter)).await.unwrap();
            if !written.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(written.iter().map(|row| row.user_id).collect::<Vec<_>>(), [Some(2)]);
    }

    async fn stored_count(db: &Db) -> usize {
        let count: i64 =
            db.call(|conn| conn.query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))).await.unwrap();
        usize::try_from(count).unwrap()
    }

    /// Stopping writes everything already queued, batches of it, before the
    /// writer ends; what's recorded after is dropped quietly, not counted.
    #[tokio::test]
    async fn stopping_writes_what_is_queued() {
        let db = Db::open_in_memory();
        let (log, events) = AuditLog::new(QUEUE_LEN);
        let queued = BATCH_LEN * 2 + 17;
        for user in 0..queued {
            log.record(Event::new(Kind::SignIn).by(user as i64));
        }
        assert_eq!(log.queued(), queued);
        let writer = spawn_writer(&log, db.clone(), events);
        assert!(writer.flush(std::time::Duration::from_secs(10)).await);
        assert_eq!(stored_count(&db).await, queued);
        assert_eq!(log.queued(), 0);
        log.record(Event::new(Kind::SignIn).by(1));
        assert_eq!((log.dropped(), stored_count(&db).await), (0, queued));

        // A writer that's never stopped (its handle dropped) keeps going.
        let (log, events) = AuditLog::new(8);
        drop(spawn_writer(&log, db.clone(), events));
        log.record(Event::new(Kind::SignIn).by(1));
        for _ in 0..100 {
            if stored_count(&db).await == queued + 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(stored_count(&db).await, queued + 1);
    }

    /// A database that doesn't answer can't hold the relay up: the flush
    /// gives up at its limit.
    #[tokio::test]
    async fn a_stuck_database_bounds_the_flush() {
        let db = Db::open_in_memory();
        let busy = db.clone();
        let (held, holding) = oneshot::channel();
        let stuck = tokio::spawn(async move {
            busy.call(move |_| {
                let _ = held.send(());
                std::thread::sleep(std::time::Duration::from_millis(500));
                Ok(())
            })
            .await
        });
        holding.await.unwrap();
        let (log, events) = AuditLog::new(8);
        log.record(Event::new(Kind::SignIn).by(1));
        let writer = spawn_writer(&log, db.clone(), events);
        let started = std::time::Instant::now();
        assert!(!writer.flush(std::time::Duration::from_millis(50)).await);
        assert!(started.elapsed() < std::time::Duration::from_millis(400));
        stuck.await.unwrap().unwrap();
    }

    /// The Client extractor over a real server, the way main serves the
    /// router: the peer's address and the browser's User-Agent.
    #[tokio::test]
    async fn the_client_comes_from_the_connection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn whoami(client: Client) -> String {
            format!("{:?}|{:?}", client.ip, client.user_agent)
        }
        let app = axum::Router::new()
            .route("/whoami", axum::routing::get(whoami))
            .into_make_service_with_connect_info::<SocketAddr>();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /whoami HTTP/1.1\r\nHost: x\r\nUser-Agent: TestBrowser/1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("Some(\"127.0.0.1\")|Some(\"TestBrowser/1\")"), "{response}");
    }
}
