//! HTTP and WebSocket endpoints.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::AppState;
use crate::auth::{AdminUser, CurrentUser};
use crate::error::ApiError;
use crate::protocol::{DashboardCommand, DashboardEvent, DeviceMessage, DeviceSnapshot};
use crate::registry::{DashboardHandle, Outbound, Registry};

const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// About half a second of 60 fps video per viewer before frames are dropped.
const VIEWER_FRAME_QUEUE: usize = 32;

/// Admin only until machines have owners.
pub async fn devices(State(state): State<AppState>, _admin: AdminUser) -> Json<Vec<DeviceSnapshot>> {
    Json(state.registry.snapshot())
}

/// Endpoint devices (hawk-service) connect to. The first message must be a
/// hello; after it, binary messages are video frames to fan out and the
/// relay sends capture commands down.
pub async fn device_socket(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    let registry = state.registry;
    ws.on_upgrade(move |socket| handle_device(socket, registry))
}

async fn handle_device(socket: WebSocket, registry: Arc<Registry>) {
    let (mut sink, mut stream) = socket.split();

    let machine_id = match tokio::time::timeout(HELLO_TIMEOUT, stream.next()).await {
        Err(_) => {
            warn!("relay: device did not send hello in time, closing");
            let _ = sink.send(close(1002, "expected hello")).await;
            return;
        }
        Ok(None | Some(Err(_))) => return,
        Ok(Some(Ok(Message::Text(text)))) => match serde_json::from_str::<DeviceMessage>(&text) {
            Ok(DeviceMessage::Hello { machine_id }) if !machine_id.is_empty() => machine_id,
            _ => {
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

    let (commands, mut command_rx) = mpsc::unbounded_channel();
    let device_id = registry.add_device(machine_id.clone(), commands);
    info!(%machine_id, %device_id, "relay: device connected");

    let writer = tokio::spawn(async move {
        while let Some(command) = command_rx.recv().await {
            let Ok(json) = serde_json::to_string(&command) else { continue };
            if sink.send(Message::Text(json.into())).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(message)) = stream.next().await {
        match message {
            Message::Binary(frame) => registry.forward_frame(&device_id, frame),
            Message::Close(_) => break,
            _ => {}
        }
    }

    registry.remove_device(&device_id);
    writer.abort();
    info!(%machine_id, %device_id, "relay: device disconnected");
}

/// The dashboard's view into the relay: a snapshot on connect, live
/// connect/disconnect events, and start_view/stop_view to receive a device's
/// video frames as binary messages.
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
    let registry = state.registry;
    ws.on_upgrade(move |socket| handle_dashboard(socket, registry, current))
}

/// True when there's no Origin (not a browser) or it names the host the
/// request was sent to.
fn same_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else { return true };
    let host = headers.get(header::HOST).and_then(|host| host.to_str().ok());
    let origin_host = origin.to_str().ok().and_then(|origin| origin.split_once("://")).map(|(_, rest)| rest);
    matches!((origin_host, host), (Some(origin_host), Some(host)) if origin_host.eq_ignore_ascii_case(host))
}

async fn handle_dashboard(socket: WebSocket, registry: Arc<Registry>, current: CurrentUser) {
    let (mut sink, mut stream) = socket.split();

    let (events, mut event_rx) = mpsc::unbounded_channel::<Outbound>();
    let (frames, mut frame_rx) = mpsc::channel::<Bytes>(VIEWER_FRAME_QUEUE);
    let dashboard_id = registry.add_dashboard(DashboardHandle {
        events: events.clone(),
        frames,
        user_id: current.user.id,
        session_id: current.session_id,
        sees_devices: current.user.is_admin,
    });

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
