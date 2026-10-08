//! WebSocket endpoints for devices and dashboards.

use std::sync::Arc;
use std::time::Duration;

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
use tracing::{error, info, warn};

use crate::AppState;
use crate::auth::{self, CurrentUser};
use crate::db::{self, MachineAuth};
use crate::error::ApiError;
use crate::protocol::{DashboardCommand, DashboardEvent, DeviceCommand, DeviceMessage, machine_auth_message};
use crate::registry::{DashboardHandle, DeviceOutbound, Outbound, Registry};

const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

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

/// An uncompressed P-256 point: 0x04 || X || Y.
const P256_PUBLIC_KEY_LEN: usize = 65;

type DeviceSink = futures_util::stream::SplitSink<WebSocket, Message>;
type DeviceStream = futures_util::stream::SplitStream<WebSocket>;

/// Who the device claims to be, and the key it must prove it holds.
enum Claim {
    Existing { public_id: String, owner_id: i64, public_key: Vec<u8> },
    Enroll { code_hash: Vec<u8>, public_key: Vec<u8>, key_storage: String },
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

async fn resolve_claim(
    state: &AppState,
    machine: Option<String>,
    enroll_code: Option<String>,
    public_key: Option<String>,
    key_storage: Option<String>,
) -> Result<Claim, Refusal> {
    if let Some(public_id) = machine {
        let lookup = public_id.clone();
        let key = state.db.call(move |conn| db::machine_key(conn, &lookup)).await?.ok_or(Refusal::Unknown)?;
        return Ok(Claim::Existing { public_id, owner_id: key.owner_id, public_key: key.public_key });
    }

    let (Some(code), Some(public_key), Some(key_storage)) = (enroll_code, public_key, key_storage) else {
        return Err(Refusal::Malformed);
    };
    let public_key = BASE64.decode(public_key).map_err(|_| Refusal::Malformed)?;
    if public_key.len() != P256_PUBLIC_KEY_LEN || public_key[0] != 0x04 {
        return Err(Refusal::Malformed);
    }
    if key_storage != "tpm" && key_storage != "software" {
        return Err(Refusal::Malformed);
    }
    // Checked now so a bad code fails fast; consumed only after the proof.
    let code_hash = auth::enrollment_code_hash(&code);
    let (lookup, now) = (code_hash.clone(), auth::now());
    state.db.call(move |conn| db::enrollment_code_owner(conn, &lookup, now)).await?.ok_or(Refusal::Unknown)?;
    Ok(Claim::Enroll { code_hash, public_key, key_storage })
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

/// Runs hello -> challenge -> proof. Returns the authenticated machine, and
/// whether this connection enrolled it.
async fn authenticate_device(
    state: &AppState,
    sink: &mut DeviceSink,
    stream: &mut DeviceStream,
) -> Result<(MachineAuth, bool), Refusal> {
    let Some(DeviceMessage::Hello { machine_id: hostname, machine, enroll_code, public_key, key_storage }) =
        next_device_message(stream, HELLO_TIMEOUT).await
    else {
        return Err(Refusal::Malformed);
    };
    let hostname: String = hostname.chars().take(255).collect();
    let claim = resolve_claim(state, machine, enroll_code, public_key, key_storage).await?;

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
            Ok((MachineAuth { public_id, owner_id }, false))
        }
        Claim::Enroll { code_hash, public_key, key_storage } => {
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
                    };
                    db::enroll_machine(conn, &machine, now)
                })
                .await?
                // The code was used by another connection while this one signed.
                .ok_or(Refusal::Unknown)?;
            Ok((enrolled, true))
        }
    }
}

async fn handle_device(socket: WebSocket, state: AppState) {
    let (mut sink, mut stream) = socket.split();

    let (machine, enrolled) = match authenticate_device(&state, &mut sink, &mut stream).await {
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

    if enrolled {
        info!(%machine_id, owner_id = machine.owner_id, "relay: machine enrolled");
        if !send_command(&mut sink, &DeviceCommand::Enrolled { machine_id: machine_id.clone() }).await {
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
    let connection = state.registry.add_device(&machine_id, machine.owner_id, outbound);
    info!(%machine_id, "relay: machine connected");

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

    while let Some(Ok(message)) = stream.next().await {
        match message {
            Message::Binary(frame) => state.registry.forward_frame(&machine_id, frame),
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

/// The dashboard's view into the relay: a snapshot of the user's machines on
/// connect, live updates, and start_view/stop_view to receive a machine's
/// video frames as binary messages.
///
/// Requires a session. A browser always sends Origin on a WebSocket
/// handshake; refusing a foreign one keeps another site from opening this
/// socket with the user's cookie.
pub async fn dashboard_socket(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    current: CurrentUser,
    headers: HeaderMap,
) -> Response {
    if !same_origin(&headers) {
        warn!(user = %current.user.email, "dashboard: rejected cross-origin socket");
        return ApiError::Forbidden.into_response();
    }
    let user_id = current.user.id;
    let machines = match state.db.call(move |conn| db::accessible_machines(conn, user_id, auth::now())).await {
        Ok(machines) => machines,
        Err(error) => return ApiError::from(error).into_response(),
    };
    let registry = state.registry;
    ws.on_upgrade(move |socket| handle_dashboard(socket, registry, current, machines))
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
    let handle = DashboardHandle {
        events: events.clone(),
        frames,
        user_id: current.user.id,
        session_id: current.session_id,
        email: current.user.email,
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
                else => break,
            };
            if sink.send(message).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(message)) = stream.next().await {
        let text = match message {
            Message::Text(text) => text,
            Message::Close(_) => break,
            _ => continue, // dashboards only send JSON control messages
        };
        match serde_json::from_str::<DashboardCommand>(&text) {
            Ok(DashboardCommand::StartView { device_id }) => {
                if !registry.start_view(dashboard_id, &device_id) {
                    let _ = events.send(Outbound::Event(Box::new(DashboardEvent::CaptureEnded { device_id })));
                }
            }
            Ok(DashboardCommand::StopView { device_id }) => registry.stop_view(dashboard_id, &device_id),
            Err(error) => warn!(%error, "dashboard: received invalid command"),
        }
    }

    registry.remove_dashboard(dashboard_id);
    writer.abort();
}

fn close(code: u16, reason: &'static str) -> Message {
    Message::Close(Some(CloseFrame { code, reason: reason.into() }))
}
