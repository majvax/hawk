//! WebSocket endpoints for devices and dashboards.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::AppState;
use crate::auth::{self, CurrentUser};
use crate::db::{self, MachineAuth};
use crate::error::ApiError;
use crate::protocol::{DashboardCommand, DashboardEvent, DeviceCommand, DeviceMessage};
use crate::registry::{DashboardHandle, DeviceOutbound, Outbound, Registry};

const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// About half a second of 60 fps video per viewer before frames are dropped.
const VIEWER_FRAME_QUEUE: usize = 32;

/// Endpoint machines (hawk-service) connect to. The first message must be a
/// hello carrying the machine's credential or a one-time enrollment code;
/// anything else is closed with 1008 before the machine is registered.
/// After it, binary messages are video frames to fan out, and the relay
/// sends capture commands down.
pub async fn device_socket(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| handle_device(socket, state))
}

enum HelloOutcome {
    Authenticated(MachineAuth),
    /// Enrolled just now; the credential must be sent back to the machine.
    Enrolled(MachineAuth, String),
    Rejected,
}

async fn authenticate_hello(state: &AppState, hello: DeviceMessage) -> Result<HelloOutcome, rusqlite::Error> {
    let DeviceMessage::Hello { machine_id: hostname, credential, enroll_code } = hello;
    let hostname: String = hostname.chars().take(255).collect();
    let now = auth::now();

    if let Some(credential) = credential {
        let hash = auth::token_hash(&credential);
        let found = state.db.call(move |conn| db::authenticate_machine(conn, &hash, &hostname, now)).await?;
        return Ok(found.map_or(HelloOutcome::Rejected, HelloOutcome::Authenticated));
    }

    if let Some(code) = enroll_code {
        let code_hash = auth::enrollment_code_hash(&code);
        let credential = auth::random_token();
        let credential_hash = auth::token_hash(&credential);
        let public_id = uuid::Uuid::new_v4().to_string();
        let enrolled = state
            .db
            .call(move |conn| db::enroll_machine(conn, &code_hash, &public_id, &hostname, &credential_hash, now))
            .await?;
        return Ok(enrolled.map_or(HelloOutcome::Rejected, |machine| HelloOutcome::Enrolled(machine, credential)));
    }

    Ok(HelloOutcome::Rejected)
}

async fn handle_device(socket: WebSocket, state: AppState) {
    let (mut sink, mut stream) = socket.split();

    let hello = match tokio::time::timeout(HELLO_TIMEOUT, stream.next()).await {
        Err(_) => {
            warn!("relay: device did not send hello in time, closing");
            let _ = sink.send(close(1002, "expected hello")).await;
            return;
        }
        Ok(None | Some(Err(_))) => return,
        Ok(Some(Ok(Message::Text(text)))) => match serde_json::from_str::<DeviceMessage>(&text) {
            Ok(hello) => hello,
            Err(_) => {
                warn!("relay: received invalid hello message");
                let _ = sink.send(close(1003, "invalid hello")).await;
                return;
            }
        },
        Ok(Some(Ok(_))) => {
            warn!("relay: expected a text hello message, closing");
            let _ = sink.send(close(1003, "invalid hello")).await;
            return;
        }
    };

    let (machine, credential) = match authenticate_hello(&state, hello).await {
        Ok(HelloOutcome::Authenticated(machine)) => (machine, None),
        Ok(HelloOutcome::Enrolled(machine, credential)) => (machine, Some(credential)),
        Ok(HelloOutcome::Rejected) => {
            warn!("relay: rejected a device with an unknown credential or enrollment code");
            let _ = sink.send(close(1008, "unknown machine")).await;
            return;
        }
        Err(error) => {
            error!(%error, "relay: database error authenticating a device");
            let _ = sink.send(close(1011, "server error")).await;
            return;
        }
    };
    let machine_id = machine.public_id.clone();

    if let Some(credential) = credential {
        info!(%machine_id, owner_id = machine.owner_id, "relay: machine enrolled");
        let enrolled = DeviceCommand::Enrolled { machine_id: machine_id.clone(), credential };
        let Ok(json) = serde_json::to_string(&enrolled) else { return };
        if sink.send(Message::Text(json.into())).await.is_err() {
            return;
        }
        // The new machine shows up on its owner's open dashboards.
        let owner_id = machine.owner_id;
        let lookup = machine_id.clone();
        match state.db.call(move |conn| db::machine_for_user(conn, &lookup, owner_id)).await {
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
    let machines = match state.db.call(move |conn| db::accessible_machines(conn, user_id)).await {
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
                    let _ = events.send(Outbound::Event(DashboardEvent::CaptureEnded { device_id }));
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
