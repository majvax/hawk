//! WebSocket endpoints for devices and dashboards.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::AppState;
use crate::auth::{self, CurrentUser};
use crate::db::{self, EnrollmentOwner, MachineAuth};
use crate::e2e;
use crate::error::ApiError;
use crate::protocol::{
    DashboardCommand, DashboardEvent, DeviceCommand, DeviceMessage, MAX_SEALED_CLIPBOARD_LEN, MAX_SEALED_FILE_LEN,
    MAX_PING_NONCE_LEN, MAX_SEALED_AUDIO_LEN, MAX_SEALED_AUDIO_REQUEST_LEN, MAX_SEALED_INPUT_LEN, MAX_SEALED_METRICS_LEN, MAX_SEALED_POWER_LEN, MAX_SEALED_METRICS_REQUEST_LEN, MAX_SEALED_SHELL_LEN, PROTOCOL_VERSION, answer_fits, clipboard_access,
    machine_auth_message,
};
use crate::registry::{Answer, DashboardHandle, DeviceInfo, DeviceOutbound, Outbound, RESTART_GRACE, Registry, StepUp};

const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// File and shell messages queued per dashboard before more are dropped. A
/// machine keeps 8 chunks per download unacknowledged, a viewer can run 2
/// downloads per machine, and a shell's window is 16 chunks; this leaves
/// room for a few machines at once.
const VIEWER_BULK_QUEUE: usize = 128;
/// About half a second of 60 fps video per viewer before frames are dropped.
const VIEWER_FRAME_QUEUE: usize = 32;

/// Endpoint machines (hawk-service) connect to. A connection must open with
/// a hello and then sign a fresh challenge with its machine key (see
/// [`DeviceMessage`]); anything else is closed with 1008 before the machine
/// is registered. After that, binary messages are video frames to fan out,
/// and the relay sends capture commands down.
pub async fn device_socket(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| handle_device(socket, state))
}

/// Signing happens in the machine's TPM, which can take a moment.
const PROOF_TIMEOUT: Duration = Duration::from_secs(10);

/// An HMAC-SHA256.
const BINDING_LEN: usize = 32;

type DeviceSink = futures_util::stream::SplitSink<WebSocket, Message>;
type DeviceStream = futures_util::stream::SplitStream<WebSocket>;

/// Who the device claims to be, and the key it must prove it holds.
enum Claim {
    Existing { public_id: String, owner_id: i64, public_key: Vec<u8> },
    Enroll { code_hash: Vec<u8>, public_key: Vec<u8>, key_storage: String, binding: Vec<u8> },
}

impl Claim {
    fn public_key(&self) -> &[u8] {
        match self {
            Self::Existing { public_key, .. } | Self::Enroll { public_key, .. } => public_key,
        }
    }
}

/// Why a device connection is refused.
enum Refusal {
    Malformed,
    Unknown,
    Server(rusqlite::Error),
}

impl From<rusqlite::Error> for Refusal {
    fn from(error: rusqlite::Error) -> Self {
        Self::Server(error)
    }
}

/// What a hello carries beyond the hostname.
struct HelloClaim {
    machine: Option<String>,
    enroll_code_hash: Option<String>,
    public_key: Option<String>,
    key_storage: Option<String>,
    binding: Option<String>,
}

async fn resolve_claim(state: &AppState, hello: HelloClaim) -> Result<Claim, Refusal> {
    let HelloClaim { machine, enroll_code_hash, public_key, key_storage, binding } = hello;
    if let Some(public_id) = machine {
        let lookup = public_id.clone();
        let key = state.db.call(move |conn| db::machine_key(conn, &lookup)).await?.ok_or(Refusal::Unknown)?;
        return Ok(Claim::Existing { public_id, owner_id: key.owner_id, public_key: key.public_key });
    }

    let (Some(code_hash), Some(public_key), Some(key_storage), Some(binding)) =
        (enroll_code_hash, public_key, key_storage, binding)
    else {
        return Err(Refusal::Malformed);
    };
    let public_key = BASE64.decode(public_key).map_err(|_| Refusal::Malformed)?;
    if !e2e::is_public_key(&public_key) {
        return Err(Refusal::Malformed);
    }
    let binding = BASE64.decode(binding).map_err(|_| Refusal::Malformed)?;
    if binding.len() != BINDING_LEN {
        return Err(Refusal::Malformed);
    }
    if key_storage != "tpm" && key_storage != "software" {
        return Err(Refusal::Malformed);
    }
    let code_hash = BASE64.decode(code_hash).map_err(|_| Refusal::Malformed)?;
    if code_hash.len() != 32 {
        return Err(Refusal::Malformed);
    }
    // Checked now so a bad code fails fast; consumed only after the proof.
    let (lookup, now) = (code_hash.clone(), auth::now());
    state.db.call(move |conn| db::enrollment_code_owner(conn, &lookup, now)).await?.ok_or(Refusal::Unknown)?;
    Ok(Claim::Enroll { code_hash, public_key, key_storage, binding })
}

/// The next text message within `limit`, parsed. None on timeout, close,
/// or anything that isn't a valid device message.
async fn next_device_message(stream: &mut DeviceStream, limit: Duration) -> Option<DeviceMessage> {
    match tokio::time::timeout(limit, stream.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => serde_json::from_str(&text).ok(),
        _ => None,
    }
}

async fn send_command(sink: &mut DeviceSink, command: &DeviceCommand) -> bool {
    match serde_json::to_string(command) {
        Ok(json) => sink.send(Message::Text(json.into())).await.is_ok(),
        Err(_) => false,
    }
}

/// Runs hello -> challenge -> proof. Returns the authenticated machine, who
/// it was enrolled for if this connection enrolled it, and what it said
/// about itself.
async fn authenticate_device(
    state: &AppState,
    sink: &mut DeviceSink,
    stream: &mut DeviceStream,
) -> Result<(MachineAuth, Option<EnrollmentOwner>, DeviceInfo), Refusal> {
    let Some(DeviceMessage::Hello {
        machine_id: hostname,
        machine,
        enroll_code_hash,
        public_key,
        key_storage,
        binding,
        version,
        protocol,
    }) = next_device_message(stream, HELLO_TIMEOUT).await
    else {
        return Err(Refusal::Malformed);
    };
    if protocol.is_some_and(|protocol| protocol > PROTOCOL_VERSION) {
        warn!(protocol, "relay: a machine speaks a newer protocol than this relay: update the relay");
    }
    let hostname: String = hostname.chars().take(255).collect();
    let version = version.map(|version| version.chars().take(32).collect::<String>());
    let info = DeviceInfo { version, protocol: protocol.unwrap_or(0) };
    let claim =
        resolve_claim(state, HelloClaim { machine, enroll_code_hash, public_key, key_storage, binding }).await?;

    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).expect("OS random number generator unavailable");
    if !send_command(sink, &DeviceCommand::Challenge { nonce: BASE64.encode(nonce) }).await {
        return Err(Refusal::Malformed);
    }
    let Some(DeviceMessage::Proof { signature }) = next_device_message(stream, PROOF_TIMEOUT).await else {
        return Err(Refusal::Malformed);
    };
    let signature = BASE64.decode(signature).map_err(|_| Refusal::Malformed)?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, claim.public_key())
        .verify(&machine_auth_message(&nonce), &signature)
        .map_err(|_| Refusal::Unknown)?;

    let now = auth::now();
    match claim {
        Claim::Existing { public_id, owner_id, .. } => {
            let id = public_id.clone();
            state.db.call(move |conn| db::record_connect(conn, &id, &hostname, now)).await?;
            Ok((MachineAuth { public_id, owner_id }, None, info))
        }
        Claim::Enroll { code_hash, public_key, key_storage, binding } => {
            let public_id = uuid::Uuid::new_v4().to_string();
            let enrolled = state
                .db
                .call(move |conn| {
                    let machine = db::NewMachine {
                        code_hash: &code_hash,
                        public_id: &public_id,
                        hostname: &hostname,
                        public_key: &public_key,
                        key_storage: &key_storage,
                        binding: &binding,
                    };
                    db::enroll_machine(conn, &machine, now)
                })
                .await?
                // The code was used by another connection while this one signed.
                .ok_or(Refusal::Unknown)?;
            let (machine, owner) = enrolled;
            Ok((machine, Some(owner), info))
        }
    }
}

async fn handle_device(socket: WebSocket, state: AppState) {
    let (mut sink, mut stream) = socket.split();

    let (machine, enrolled, info) = match authenticate_device(&state, &mut sink, &mut stream).await {
        Ok(result) => result,
        Err(Refusal::Malformed) => {
            warn!("relay: device sent a malformed or incomplete handshake, closing");
            let _ = sink.send(close(1003, "invalid handshake")).await;
            return;
        }
        Err(Refusal::Unknown) => {
            warn!("relay: rejected a device: unknown machine, bad enrollment code, or failed key proof");
            let _ = sink.send(close(1008, "unknown machine")).await;
            return;
        }
        Err(Refusal::Server(error)) => {
            error!(%error, "relay: database error authenticating a device");
            let _ = sink.send(close(1011, "server error")).await;
            return;
        }
    };
    let machine_id = machine.public_id.clone();

    if let Some(owner) = enrolled {
        info!(%machine_id, owner_id = machine.owner_id, "relay: machine enrolled");
        let enrolled = DeviceCommand::Enrolled {
            machine_id: machine_id.clone(),
            owner_key: BASE64.encode(&owner.owner_public_key),
            owner_binding: BASE64.encode(&owner.owner_binding),
        };
        if !send_command(&mut sink, &enrolled).await {
            return;
        }
        // The new machine shows up on its owner's open dashboards.
        let owner_id = machine.owner_id;
        let lookup = machine_id.clone();
        match state.db.call(move |conn| db::machine_for_user(conn, &lookup, owner_id, auth::now())).await {
            Ok(Some(row)) => state.registry.grant(owner_id, &row),
            Ok(None) => {}
            Err(error) => error!(%error, "relay: loading a newly enrolled machine failed"),
        }
    }

    let (outbound, mut outbound_rx) = mpsc::unbounded_channel();
    let connection = state.registry.add_device(&machine_id, machine.owner_id, info, outbound);
    info!(%machine_id, "relay: machine connected");

    // Before any viewer can join, so a revoked one is refused.
    let lookup = machine_id.clone();
    match state.db.call(move |conn| db::revocations(conn, &lookup)).await {
        Ok(revocations) => state.registry.send_revocations(&machine_id, &revocations),
        Err(error) => error!(%error, "relay: loading revocations failed"),
    }

    let writer = tokio::spawn(async move {
        while let Some(message) = outbound_rx.recv().await {
            match message {
                DeviceOutbound::Command(command) => {
                    let Ok(json) = serde_json::to_string(&command) else { continue };
                    if sink.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
                DeviceOutbound::Close(code, reason) => {
                    let _ = sink.send(close(code, reason)).await;
                    break;
                }
            }
        }
    });

    let mut clipboard_budgets = HashMap::new();
    while let Some(Ok(message)) = stream.next().await {
        match message {
            Message::Binary(frame) => state.registry.forward_frame(&machine_id, frame),
            Message::Text(text) => {
                match serde_json::from_str::<DeviceMessage>(&text) {
                    Ok(DeviceMessage::UpdateStatus { available }) => {
                        let available = available.map(|version| version.chars().take(32).collect());
                        state.registry.set_update_available(&machine_id, connection, available);
                        continue;
                    }
                    Ok(DeviceMessage::GoingDown { restart }) => {
                        info!(%machine_id, restart, "relay: machine is going down");
                        state.registry.going_down(&machine_id, connection, restart);
                        if restart {
                            // Back to plain offline if it doesn't come back.
                            let registry = Arc::clone(&state.registry);
                            let overdue = machine_id.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_secs(RESTART_GRACE.unsigned_abs() + 1)).await;
                                registry.restart_overdue(&overdue);
                            });
                        }
                        continue;
                    }
                    _ => {}
                }
                route_device_answer(&state.registry, &machine_id, &text, &mut clipboard_budgets);
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    let now = auth::now();
    let touched = machine_id.clone();
    if let Err(error) = state.db.call(move |conn| db::touch_machine(conn, &touched, now)).await {
        error!(%error, "relay: recording last-seen time failed");
    }
    state.registry.remove_device(&machine_id, connection, now);
    writer.abort();
    info!(%machine_id, "relay: machine disconnected");
}

/// Passes the machine's answer to one of its viewers on, unread. Clipboard
/// text is held to a budget per viewer, so a machine in sync mode copying
/// in a loop can't flood a dashboard.
fn route_device_answer(
    registry: &Registry,
    machine_id: &str,
    text: &str,
    clipboard_budgets: &mut HashMap<u64, Budget>,
) {
    let (viewer, answer) = match serde_json::from_str::<DeviceMessage>(text) {
        Ok(DeviceMessage::ViewerAccept {
            viewer,
            statement,
            signature,
            wrapped_key,
            clipboard,
            files,
            shell,
            analytics,
        }) if answer_fits(&[&statement, &signature, &wrapped_key]) => {
            let clipboard = clipboard_access(clipboard.as_deref());
            let files = files.unwrap_or(false);
            let shell = shell.unwrap_or(false);
            let analytics = analytics.unwrap_or(false);
            (viewer, Answer::Accept { statement, signature, wrapped_key, clipboard, files, shell, analytics })
        }
        Ok(DeviceMessage::ViewerReject { viewer, reason }) => {
            (viewer, Answer::Reject { reason: reason.chars().take(200).collect() })
        }
        Ok(DeviceMessage::StreamKey { viewer, wrapped_key }) if answer_fits(&[&wrapped_key]) => {
            (viewer, Answer::StreamKey { wrapped_key })
        }
        // With the events, ahead of frames, so the round trip isn't the
        // video's queue.
        Ok(DeviceMessage::Pong { viewer, nonce }) if nonce.len() <= MAX_PING_NONCE_LEN => {
            (viewer, Answer::Pong { nonce })
        }
        Ok(DeviceMessage::Clipboard { viewer, sealed }) if sealed.len() <= MAX_SEALED_CLIPBOARD_LEN => {
            if !clipboard_budgets.entry(viewer).or_insert_with(Budget::clipboard).take() {
                debug!(%machine_id, viewer, "relay: dropping clipboard text over the budget");
                return;
            }
            (viewer, Answer::Clipboard { sealed })
        }
        Ok(DeviceMessage::File { viewer, sealed }) if sealed.len() <= MAX_SEALED_FILE_LEN => {
            let event = DashboardEvent::File { device_id: machine_id.to_owned(), sealed };
            if !registry.forward_bulk(machine_id, viewer, event) {
                debug!(%machine_id, viewer, "relay: dropping file data for a viewer that isn't keeping up");
            }
            return;
        }
        Ok(DeviceMessage::Shell { viewer, sealed }) if sealed.len() <= MAX_SEALED_SHELL_LEN => {
            let event = DashboardEvent::Shell { device_id: machine_id.to_owned(), sealed };
            if !registry.forward_bulk(machine_id, viewer, event) {
                debug!(%machine_id, viewer, "relay: dropping shell output for a viewer that isn't keeping up");
            }
            return;
        }
        Ok(DeviceMessage::Metrics { viewer, sealed }) if sealed.len() <= MAX_SEALED_METRICS_LEN => {
            let event = DashboardEvent::Metrics { device_id: machine_id.to_owned(), sealed };
            if !registry.forward_bulk(machine_id, viewer, event) {
                debug!(%machine_id, viewer, "relay: dropping metrics for a viewer that isn't keeping up");
            }
            return;
        }
        Ok(DeviceMessage::Audio { viewer, sealed }) if sealed.len() <= MAX_SEALED_AUDIO_LEN => {
            let event = DashboardEvent::Audio { device_id: machine_id.to_owned(), sealed };
            if !registry.forward_bulk(machine_id, viewer, event) {
                debug!(%machine_id, viewer, "relay: dropping the device list for a viewer that isn't keeping up");
            }
            return;
        }
        _ => {
            debug!(%machine_id, "relay: ignoring an unexpected message from a machine");
            return;
        }
    };
    registry.answer(machine_id, viewer, answer);
}

/// The dashboard's view into the relay: a snapshot of the user's machines on
/// connect, live updates, and start_view/stop_view to receive a machine's
/// video frames as binary messages.
///
/// Requires a session. A browser always sends Origin on a WebSocket
/// handshake; refusing a foreign one keeps another site from opening this
/// socket with the user's cookie. A dashboard on an allowed origin sends
/// its bearer token as a subprotocol instead (see auth::session_token).
pub async fn dashboard_socket(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    current: CurrentUser,
    headers: HeaderMap,
) -> Response {
    if !same_origin(&headers) && state.allowed_origins.of_request(&headers).is_none() {
        warn!(user = %current.user.email, "dashboard: rejected cross-origin socket");
        return ApiError::Forbidden.into_response();
    }
    let user_id = current.user.id;
    let machines = match state.db.call(move |conn| db::accessible_machines(conn, user_id, auth::now())).await {
        Ok(machines) => machines,
        Err(error) => return ApiError::from(error).into_response(),
    };
    let registry = state.registry;
    ws.protocols([auth::SOCKET_PROTOCOL]).on_upgrade(move |socket| handle_dashboard(socket, registry, current, machines))
}

/// True when there's no Origin (not a browser) or it names the host the
/// request was sent to.
fn same_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else { return true };
    let host = headers.get(header::HOST).and_then(|host| host.to_str().ok());
    let origin_host = origin.to_str().ok().and_then(|origin| origin.split_once("://")).map(|(_, rest)| rest);
    matches!((origin_host, host), (Some(origin_host), Some(host)) if origin_host.eq_ignore_ascii_case(host))
}

async fn handle_dashboard(
    socket: WebSocket,
    registry: Arc<Registry>,
    current: CurrentUser,
    machines: Vec<db::MachineRow>,
) {
    let (mut sink, mut stream) = socket.split();

    let (events, mut event_rx) = mpsc::unbounded_channel::<Outbound>();
    let (frames, mut frame_rx) = mpsc::channel::<Bytes>(VIEWER_FRAME_QUEUE);
    let (bulk, mut bulk_rx) = mpsc::channel::<DashboardEvent>(VIEWER_BULK_QUEUE);
    let handle = DashboardHandle {
        events: events.clone(),
        frames,
        bulk,
        user_id: current.user.id,
        session_id: current.session_id,
        email: current.user.email,
        step_up: StepUp { mfa: current.account.mfa, at: current.step_up_at },
    };
    let dashboard_id = registry.add_dashboard(handle, machines);

    let writer = tokio::spawn(async move {
        loop {
            let message = tokio::select! {
                // Events first, so capture_ended never trails stale frames.
                biased;
                Some(outbound) = event_rx.recv() => match outbound {
                    Outbound::Event(event) => match serde_json::to_string(&event) {
                        Ok(json) => Message::Text(json.into()),
                        Err(_) => continue,
                    },
                    Outbound::Close => {
                        let _ = sink.send(close(1008, "session ended")).await;
                        break;
                    }
                },
                Some(frame) = frame_rx.recv() => Message::Binary(frame),
                // Last: file data and shell output fill whatever the
                // picture leaves.
                Some(bulk) = bulk_rx.recv() => match serde_json::to_string(&bulk) {
                    Ok(json) => Message::Text(json.into()),
                    Err(_) => continue,
                },
                else => break,
            };
            if sink.send(message).await.is_err() {
                break;
            }
        }
    });

    let mut input_budget = Budget::input();
    let mut clipboard_budget = Budget::clipboard();
    let mut file_budget = Budget::file_bytes();
    let mut shell_budget = Budget::shell_bytes();
    let mut metrics_budget = Budget::metrics();
    let mut audio_budget = Budget::audio();
    let mut ping_budget = Budget::ping();
    // A dashboard can send invalid commands as fast as it moves a mouse, so
    // only the first one per connection is worth a warning.
    let mut warned_invalid = false;
    while let Some(Ok(message)) = stream.next().await {
        let text = match message {
            Message::Text(text) => text,
            Message::Close(_) => break,
            _ => continue, // dashboards only send JSON control messages
        };
        match serde_json::from_str::<DashboardCommand>(&text) {
            Ok(DashboardCommand::StartView { device_id, join }) => {
                if join.decode().is_none() || !registry.start_view(dashboard_id, &device_id, join) {
                    let _ = events.send(Outbound::Event(Box::new(DashboardEvent::CaptureEnded { device_id })));
                }
            }
            Ok(DashboardCommand::StopView { device_id }) => registry.stop_view(dashboard_id, &device_id),
            Ok(DashboardCommand::Elevate { device_id }) => registry.elevate(dashboard_id, &device_id),
            Ok(DashboardCommand::InstallUpdate { device_id }) => registry.install_update(dashboard_id, &device_id),
            Ok(DashboardCommand::Input { device_id, sealed }) => {
                // Dropped quietly: a view-only or flooding dashboard gets
                // nothing through, and no reply it could time against. The
                // relay can't tell a release from a press any more, so the
                // budget is generous enough that a person never runs it dry.
                if sealed.len() <= MAX_SEALED_INPUT_LEN && input_budget.take() {
                    registry.input(dashboard_id, &device_id, sealed);
                }
            }
            Ok(DashboardCommand::Clipboard { device_id, sealed }) => {
                // Dropped quietly too. A person pastes or asks for the
                // clipboard by hand, a few times a minute at most.
                if sealed.len() <= MAX_SEALED_CLIPBOARD_LEN && clipboard_budget.take() {
                    registry.clipboard(dashboard_id, &device_id, sealed);
                }
            }
            Ok(DashboardCommand::File { device_id, sealed }) => {
                // Budgeted by size: a chunk of an upload is ~87 KB, a list
                // or an ack a few hundred bytes.
                if sealed.len() <= MAX_SEALED_FILE_LEN && file_budget.take_n(sealed.len() as f64) {
                    registry.file(dashboard_id, &device_id, sealed);
                }
            }
            Ok(DashboardCommand::Shell { device_id, sealed }) => {
                // Keystrokes, the odd paste, resizes and acks.
                if sealed.len() <= MAX_SEALED_SHELL_LEN && shell_budget.take_n(sealed.len() as f64) {
                    registry.shell(dashboard_id, &device_id, sealed);
                }
            }
            Ok(DashboardCommand::Power { device_id, sealed }) => {
                // By hand, after a confirmation: the input budget is plenty.
                if sealed.len() <= MAX_SEALED_POWER_LEN && input_budget.take() {
                    registry.power(dashboard_id, &device_id, sealed);
                }
            }
            Ok(DashboardCommand::Metrics { device_id, sealed }) => {
                // Subscribing, a range of history, the process list: a few
                // a second at most, each asking the machine for work.
                if sealed.len() <= MAX_SEALED_METRICS_REQUEST_LEN && metrics_budget.take() {
                    registry.metrics(dashboard_id, &device_id, sealed);
                }
            }
            Ok(DashboardCommand::AudioDevices { device_id, sealed }) => {
                // Opening the sound menu, by hand. Each one has the machine
                // enumerate its devices.
                if sealed.len() <= MAX_SEALED_AUDIO_REQUEST_LEN && audio_budget.take() {
                    registry.audio_devices(dashboard_id, &device_id, sealed);
                }
            }
            Ok(DashboardCommand::AudioSelect { device_id, sealed }) => {
                // Each one restarts the machine's capture.
                if sealed.len() <= MAX_SEALED_AUDIO_REQUEST_LEN && audio_budget.take() {
                    registry.audio_select(dashboard_id, &device_id, sealed);
                }
            }
            Ok(DashboardCommand::Ping { device_id, nonce }) => {
                // Once a second while the stats are up.
                if nonce.len() <= MAX_PING_NONCE_LEN && ping_budget.take() {
                    registry.ping(dashboard_id, &device_id, nonce);
                }
            }
            Err(error) if !std::mem::replace(&mut warned_invalid, true) => {
                warn!(%error, "dashboard: received invalid command (further ones are logged at debug)")
            }
            Err(error) => debug!(%error, "dashboard: received invalid command"),
        }
    }

    registry.remove_dashboard(dashboard_id);
    writer.abort();
}

/// Token bucket on one kind of message from one connection; anything above
/// it is dropped.
struct Budget {
    tokens: f64,
    refilled: Instant,
    per_second: f64,
    burst: f64,
}

impl Budget {
    /// A dashboard's input events. A person moving a mouse sends at most one
    /// move per display frame plus the odd key, far below this.
    fn input() -> Self {
        Self::new(500.0, 1000.0)
    }

    /// Clipboard messages, each up to 256 KB: a dashboard's requests, or the
    /// text a machine sends one viewer.
    fn clipboard() -> Self {
        Self::new(2.0, 5.0)
    }

    /// Metrics requests from one dashboard: switching ranges and refreshing
    /// the process list, never anywhere near this.
    fn metrics() -> Self {
        Self::new(5.0, 20.0)
    }

    /// Asking for the output devices and choosing one, by hand: a few a
    /// minute, and each has the machine do work (a choice restarts capture).
    fn audio() -> Self {
        Self::new(1.0, 5.0)
    }

    /// Pings from one dashboard: the stats overlay sends one a second.
    fn ping() -> Self {
        Self::new(2.0, 5.0)
    }

    /// Bytes of sealed file messages from one dashboard: far more than a
    /// home uplink, and still a ceiling on what one browser can push
    /// through to a machine.
    fn file_bytes() -> Self {
        Self::new(64.0 * 1024.0 * 1024.0, 16.0 * 1024.0 * 1024.0)
    }

    /// Bytes of sealed shell messages from one dashboard: far beyond typing,
    /// and room for a large paste.
    fn shell_bytes() -> Self {
        Self::new(1024.0 * 1024.0, 1024.0 * 1024.0)
    }

    fn new(per_second: f64, burst: f64) -> Self {
        Self { tokens: burst, refilled: Instant::now(), per_second, burst }
    }

    fn take(&mut self) -> bool {
        self.take_n(1.0)
    }

    /// Takes `cost` tokens if there are that many.
    fn take_n(&mut self, cost: f64) -> bool {
        let now = Instant::now();
        let refill = now.duration_since(self.refilled).as_secs_f64() * self.per_second;
        self.tokens = (self.tokens + refill).min(self.burst);
        self.refilled = now;
        if self.tokens < cost {
            return false;
        }
        self.tokens -= cost;
        true
    }
}

fn close(code: u16, reason: &'static str) -> Message {
    Message::Close(Some(CloseFrame { code, reason: reason.into() }))
}
