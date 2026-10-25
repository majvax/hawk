//! Prometheus metrics, for whoever runs the relay: how many machines and
//! dashboards are connected, how much goes through, how sign-ins go, and
//! whether the audit log and the backups keep up.
//!
//! Off unless asked for (see [`MetricsConfig`]). Nothing here names a
//! user, a machine or an address: every label comes from a fixed set (a
//! role, a route template, a status class), so a scrape can't learn who
//! is on the relay, and the number of series stays bounded.
//!
//! The exposition is written by hand: a few counters don't need a crate.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::audit::{AuditLog, Kind};
use crate::db::Role;
use crate::protocol;

/// Every counter the relay keeps. One per process, so the places that
/// count don't need a handle passed down to them.
pub static METRICS: Metrics = Metrics::new();

/// Which side of the relay bytes went to or came from.
#[derive(Debug, Clone, Copy)]
pub enum Peer {
    Machine,
    Dashboard,
}

pub struct Metrics {
    /// Bytes received from and sent to machines and dashboards, over their
    /// sockets: [machine in, machine out, dashboard in, dashboard out].
    bytes: [AtomicU64; 4],
    /// Video frames a viewer's full queue made the relay drop.
    frames_dropped: AtomicU64,
    sign_ins: AtomicU64,
    sign_ins_failed: AtomicU64,
    mfa_failed: AtomicU64,
    /// Requests refused with 429 by a login or second-factor throttle.
    rate_limited: AtomicU64,
    /// By route template, then status class (1xx to 5xx).
    requests: Mutex<BTreeMap<String, [u64; 5]>>,
    backups_enabled: AtomicBool,
    backups: AtomicU64,
    backup_failures: AtomicU64,
    /// Unix seconds; 0 until the first one.
    backup_last_success: AtomicI64,
}

impl Metrics {
    pub(crate) const fn new() -> Self {
        Self {
            bytes: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
            frames_dropped: AtomicU64::new(0),
            sign_ins: AtomicU64::new(0),
            sign_ins_failed: AtomicU64::new(0),
            mfa_failed: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            requests: Mutex::new(BTreeMap::new()),
            backups_enabled: AtomicBool::new(false),
            backups: AtomicU64::new(0),
            backup_failures: AtomicU64::new(0),
            backup_last_success: AtomicI64::new(0),
        }
    }

    pub fn received(&self, peer: Peer, bytes: usize) {
        let index = match peer {
            Peer::Machine => 0,
            Peer::Dashboard => 2,
        };
        self.bytes[index].fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn sent(&self, peer: Peer, bytes: usize) {
        let index = match peer {
            Peer::Machine => 1,
            Peer::Dashboard => 3,
        };
        self.bytes[index].fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn frame_dropped(&self) {
        self.frames_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Every audit event passes through here: the sign-in counters are the
    /// log's own events, so they can't disagree with it.
    pub fn audit_event(&self, kind: Kind) {
        let counter = match kind {
            Kind::SignIn => &self.sign_ins,
            Kind::SignInFailed => &self.sign_ins_failed,
            Kind::MfaFailed => &self.mfa_failed,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    fn request(&self, route: &str, status: StatusCode) {
        let class = usize::from(status.as_u16() / 100).clamp(1, 5) - 1;
        let mut requests = self.requests.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match requests.get_mut(route) {
            Some(counts) => counts[class] += 1,
            None => {
                let mut counts = [0; 5];
                counts[class] = 1;
                requests.insert(route.to_owned(), counts);
            }
        }
    }

    pub fn backups_enabled(&self) {
        self.backups_enabled.store(true, Ordering::Relaxed);
    }

    pub fn backup_succeeded(&self, at: i64) {
        self.backups.fetch_add(1, Ordering::Relaxed);
        self.backup_last_success.store(at, Ordering::Relaxed);
    }

    /// A backup taken before this relay started: its time, not counted.
    pub fn backup_seen(&self, at: i64) {
        self.backup_last_success.fetch_max(at, Ordering::Relaxed);
    }

    pub fn backup_failed(&self) {
        self.backup_failures.fetch_add(1, Ordering::Relaxed);
    }
}

/// Counts every request by the route it matched, never its actual path:
/// `/api/invites/{token}`, not the token. What no route matched (the
/// dashboard's files, unknown paths) counts as `other`.
pub async fn track(request: Request, next: Next) -> Response {
    let route = request.extensions().get::<MatchedPath>().map(|path| path.as_str().to_owned());
    let response = next.run(request).await;
    METRICS.request(route.as_deref().unwrap_or("other"), response.status());
    response
}

/// `HAWK_METRICS_TOKEN` and `HAWK_METRICS_ADDR`.
///
/// - Neither: no metrics; `/metrics` is just another unknown path.
/// - A token alone: `/metrics` on the relay's own port, to requests that
///   send `Authorization: Bearer <token>`.
/// - An address: `/metrics` on a listener of its own there (plain HTTP,
///   e.g. `127.0.0.1:9100`), and not on the relay's port. With a token as
///   well, that listener asks for it too.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetricsConfig {
    /// SHA-256 of the token: compared without leaking where it differs.
    token: Option<[u8; 32]>,
    pub addr: Option<SocketAddr>,
}

/// Shorter than this, a token is guessable over the network.
const MIN_TOKEN_LEN: usize = 16;

impl MetricsConfig {
    pub fn parse(token: Option<&str>, addr: Option<&str>) -> Result<Self, String> {
        let token = match token.map(str::trim).filter(|token| !token.is_empty()) {
            Some(token) if token.len() < MIN_TOKEN_LEN => {
                return Err(format!("HAWK_METRICS_TOKEN: use at least {MIN_TOKEN_LEN} random characters"));
            }
            Some(token) => Some(Sha256::digest(token.as_bytes()).into()),
            None => None,
        };
        let addr = match addr.map(str::trim).filter(|addr| !addr.is_empty()) {
            Some(addr) => Some(addr.parse().map_err(|error| format!("HAWK_METRICS_ADDR: \"{addr}\": {error}"))?),
            None => None,
        };
        Ok(Self { token, addr })
    }

    pub fn enabled(&self) -> bool {
        self.token.is_some() || self.addr.is_some()
    }

    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// Whether the request may read the metrics.
    fn allows(&self, headers: &HeaderMap) -> bool {
        let Some(expected) = &self.token else { return true };
        let Some(given) = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' '))
            // The scheme is case-insensitive (RFC 7235); the token isn't.
            .and_then(|(scheme, token)| scheme.eq_ignore_ascii_case("bearer").then_some(token))
        else {
            return false;
        };
        // Both sides hashed to the same length, then compared in full.
        let given: [u8; 32] = Sha256::digest(given.trim().as_bytes()).into();
        given.iter().zip(expected).fold(0u8, |differ, (a, b)| differ | (a ^ b)) == 0
    }
}

/// `GET /metrics`, on whichever listener [`MetricsConfig`] puts it.
pub async fn serve(State(state): State<AppState>, config: Arc<MetricsConfig>, headers: HeaderMap) -> Response {
    if !config.allows(&headers) {
        let mut response = StatusCode::UNAUTHORIZED.into_response();
        response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        return response;
    }
    let db_size = state
        .db
        .call(|conn| {
            let pages: i64 = conn.pragma_query_value(None, "page_count", |row| row.get(0))?;
            let size: i64 = conn.pragma_query_value(None, "page_size", |row| row.get(0))?;
            Ok(pages * size)
        })
        .await
        .ok();
    let live = state.registry.counts();
    let body = render(&METRICS, &live, &state.audit, db_size);
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")], body).into_response()
}

/// What's connected right now, from the registry.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Live {
    pub machines: usize,
    pub dashboards: usize,
    /// Views by the viewer's role: [view, control, dev, owner].
    pub views: [usize; 4],
}

impl Live {
    pub fn add_view(&mut self, role: Role) {
        self.views[role_index(role)] += 1;
    }
}

const ROLES: [Role; 4] = [Role::View, Role::Control, Role::Dev, Role::Owner];

fn role_index(role: Role) -> usize {
    match role {
        Role::View => 0,
        Role::Control => 1,
        Role::Dev => 2,
        Role::Owner => 3,
    }
}

fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// The text exposition format, version 0.0.4.
pub fn render(metrics: &Metrics, live: &Live, audit: &AuditLog, db_size: Option<i64>) -> String {
    let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    let mut out = String::with_capacity(4096);

    family(&mut out, "hawk_relay_build_info", "gauge", "The relay's release and protocol version.");
    let _ = writeln!(
        out,
        "hawk_relay_build_info{{version=\"{}\",protocol=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION"),
        protocol::PROTOCOL_VERSION
    );

    family(&mut out, "hawk_relay_machines_connected", "gauge", "Machines connected now.");
    let _ = writeln!(out, "hawk_relay_machines_connected {}", live.machines);
    family(&mut out, "hawk_relay_dashboards_connected", "gauge", "Dashboard sockets open now.");
    let _ = writeln!(out, "hawk_relay_dashboards_connected {}", live.dashboards);
    family(&mut out, "hawk_relay_views", "gauge", "Views open now, by the viewer's role.");
    for role in ROLES {
        let _ = writeln!(out, "hawk_relay_views{{role=\"{}\"}} {}", role.as_str(), live.views[role_index(role)]);
    }

    family(&mut out, "hawk_relay_bytes_total", "counter", "Bytes over machine and dashboard sockets.");
    for (index, (peer, direction)) in
        [("machine", "in"), ("machine", "out"), ("dashboard", "in"), ("dashboard", "out")].into_iter().enumerate()
    {
        let _ = writeln!(
            out,
            "hawk_relay_bytes_total{{peer=\"{peer}\",direction=\"{direction}\"}} {}",
            load(&metrics.bytes[index])
        );
    }
    family(&mut out, "hawk_relay_frames_dropped_total", "counter", "Video frames dropped for viewers that fell behind.");
    let _ = writeln!(out, "hawk_relay_frames_dropped_total {}", load(&metrics.frames_dropped));

    family(&mut out, "hawk_relay_http_requests_total", "counter", "HTTP requests, by route template and status class.");
    {
        let requests = metrics.requests.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        for (route, counts) in requests.iter() {
            for (class, count) in counts.iter().enumerate().filter(|(_, count)| **count > 0) {
                let route = route.replace('\\', "\\\\").replace('"', "\\\"");
                let _ = writeln!(
                    out,
                    "hawk_relay_http_requests_total{{route=\"{route}\",class=\"{}xx\"}} {count}",
                    class + 1
                );
            }
        }
    }

    family(&mut out, "hawk_relay_logins_total", "counter", "Sign-ins, by result (the password step).");
    let _ = writeln!(out, "hawk_relay_logins_total{{result=\"success\"}} {}", load(&metrics.sign_ins));
    let _ = writeln!(out, "hawk_relay_logins_total{{result=\"failure\"}} {}", load(&metrics.sign_ins_failed));
    family(&mut out, "hawk_relay_mfa_failures_total", "counter", "Wrong second factors, signing in or stepping up.");
    let _ = writeln!(out, "hawk_relay_mfa_failures_total {}", load(&metrics.mfa_failed));
    family(&mut out, "hawk_relay_rate_limited_total", "counter", "Requests refused by a login or second-factor throttle.");
    let _ = writeln!(out, "hawk_relay_rate_limited_total {}", load(&metrics.rate_limited));

    family(&mut out, "hawk_relay_audit_queue_depth", "gauge", "Audit events waiting to be written.");
    let _ = writeln!(out, "hawk_relay_audit_queue_depth {}", audit.queued());
    family(&mut out, "hawk_relay_audit_queue_capacity", "gauge", "Audit events the queue holds before dropping.");
    let _ = writeln!(out, "hawk_relay_audit_queue_capacity {}", audit.capacity());
    family(&mut out, "hawk_relay_audit_events_dropped_total", "counter", "Audit events lost: a full queue or a failed write.");
    let _ = writeln!(out, "hawk_relay_audit_events_dropped_total {}", audit.dropped());

    if let Some(size) = db_size {
        family(&mut out, "hawk_relay_db_size_bytes", "gauge", "The database's size (pages in use and free).");
        let _ = writeln!(out, "hawk_relay_db_size_bytes {size}");
    }

    if metrics.backups_enabled.load(Ordering::Relaxed) {
        family(&mut out, "hawk_relay_backups_total", "counter", "Scheduled backups written.");
        let _ = writeln!(out, "hawk_relay_backups_total {}", load(&metrics.backups));
        family(&mut out, "hawk_relay_backup_failures_total", "counter", "Scheduled backups that failed.");
        let _ = writeln!(out, "hawk_relay_backup_failures_total {}", load(&metrics.backup_failures));
        family(
            &mut out,
            "hawk_relay_backup_last_success_timestamp_seconds",
            "gauge",
            "When the newest backup was written, in Unix seconds, including one found at startup; 0 if none.",
        );
        let _ = writeln!(
            out,
            "hawk_relay_backup_last_success_timestamp_seconds {}",
            metrics.backup_last_success.load(Ordering::Relaxed)
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token is needed exactly when one is set, compared in full; a short
    /// one or a bad address stops the relay instead.
    #[test]
    fn the_token_guards_the_metrics() {
        let open = MetricsConfig::parse(None, Some("127.0.0.1:9100")).unwrap();
        assert!(open.enabled() && open.allows(&HeaderMap::new()));
        assert!(!MetricsConfig::parse(None, None).unwrap().enabled());
        assert!(!MetricsConfig::parse(Some("  "), Some("")).unwrap().enabled());

        let token = "0123456789abcdef0123";
        let guarded = MetricsConfig::parse(Some(token), None).unwrap();
        assert!(guarded.enabled() && guarded.addr.is_none());
        let with = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, value.parse().unwrap());
            headers
        };
        assert!(guarded.allows(&with(&format!("Bearer {token}"))));
        assert!(!guarded.allows(&HeaderMap::new()));
        assert!(!guarded.allows(&with(&format!("Bearer {token}x"))));
        assert!(!guarded.allows(&with(&format!("Bearer {}", &token[..19]))));
        assert!(!guarded.allows(&with(&format!("Basic {token}"))));
        assert!(!guarded.allows(&with(token)));
        // Nothing after the scheme, or nothing at all, is no token.
        for empty in ["Bearer", "Bearer ", "Bearer    ", ""] {
            assert!(!guarded.allows(&with(empty)), "{empty:?}");
        }
        // The scheme in any case; the token exactly.
        for scheme in ["bearer", "BEARER", "BeArEr"] {
            assert!(guarded.allows(&with(&format!("{scheme} {token}"))), "{scheme}");
        }
        assert!(!guarded.allows(&with(&format!("Bearer {}", token.to_uppercase()))));
        assert!(!guarded.allows(&with(&format!("Bearerx {token}"))));
        // Two headers: only the first is read, and it has to be right.
        let mut two = with("Bearer wrong-token-wrong-token");
        two.append(header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        assert!(!guarded.allows(&two));

        assert!(MetricsConfig::parse(Some("short"), None).is_err());
        assert!(MetricsConfig::parse(None, Some("localhost")).is_err());
    }

    /// Over a real server, layered the way main layers it: a request counts
    /// under the template it matched, never its path, and one no route
    /// matched under `other`.
    #[tokio::test]
    async fn requests_count_by_route_template() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let app = axum::Router::new()
            .route("/metrics-test/{secret}", axum::routing::get(|| async { StatusCode::NO_CONTENT }))
            .fallback(|| async { StatusCode::NOT_FOUND })
            .layer(axum::middleware::from_fn(track));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        for path in ["/metrics-test/hunter2", "/metrics-test/swordfish", "/no-such-page"] {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let request = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            stream.write_all(request.as_bytes()).await.unwrap();
            stream.read_to_end(&mut Vec::new()).await.unwrap();
        }
        let requests = METRICS.requests.lock().unwrap().clone();
        assert_eq!(requests.get("/metrics-test/{secret}"), Some(&[0, 2, 0, 0, 0]));
        assert!(requests.get("other").is_some_and(|counts| counts[3] >= 1));
        assert!(requests.keys().all(|route| !route.contains("hunter2") && !route.contains("no-such-page")));
    }

    /// Every family is there with its type, labels come from fixed sets,
    /// and the backup families only when backups are on.
    #[test]
    fn renders_the_exposition_format() {
        let metrics = Metrics::new();
        metrics.received(Peer::Machine, 100);
        metrics.sent(Peer::Dashboard, 40);
        metrics.audit_event(Kind::SignIn);
        metrics.audit_event(Kind::SignInFailed);
        metrics.audit_event(Kind::SignInFailed);
        metrics.audit_event(Kind::MfaFailed);
        metrics.audit_event(Kind::Power);
        metrics.rate_limited();
        metrics.request("/api/invites/{token}", StatusCode::NOT_FOUND);
        metrics.request("/api/invites/{token}", StatusCode::OK);
        metrics.request("/healthz", StatusCode::NO_CONTENT);
        let mut live = Live { machines: 2, dashboards: 3, ..Live::default() };
        live.add_view(Role::Control);
        live.add_view(Role::Control);
        live.add_view(Role::Owner);
        let (audit, _events) = AuditLog::new(8);

        let text = render(&metrics, &live, &audit, Some(4096));
        for line in [
            "hawk_relay_machines_connected 2",
            "hawk_relay_dashboards_connected 3",
            "hawk_relay_views{role=\"control\"} 2",
            "hawk_relay_views{role=\"owner\"} 1",
            "hawk_relay_views{role=\"view\"} 0",
            "hawk_relay_bytes_total{peer=\"machine\",direction=\"in\"} 100",
            "hawk_relay_bytes_total{peer=\"dashboard\",direction=\"out\"} 40",
            "hawk_relay_logins_total{result=\"success\"} 1",
            "hawk_relay_logins_total{result=\"failure\"} 2",
            "hawk_relay_mfa_failures_total 1",
            "hawk_relay_rate_limited_total 1",
            "hawk_relay_http_requests_total{route=\"/api/invites/{token}\",class=\"4xx\"} 1",
            "hawk_relay_http_requests_total{route=\"/api/invites/{token}\",class=\"2xx\"} 1",
            "hawk_relay_http_requests_total{route=\"/healthz\",class=\"2xx\"} 1",
            "hawk_relay_audit_queue_depth 0",
            "hawk_relay_audit_queue_capacity 8",
            "hawk_relay_audit_events_dropped_total 0",
            "hawk_relay_db_size_bytes 4096",
            "# TYPE hawk_relay_bytes_total counter",
        ] {
            assert!(text.lines().any(|candidate| candidate == line), "{line} missing from\n{text}");
        }
        assert!(text.contains(&format!("version=\"{}\"", env!("CARGO_PKG_VERSION"))));
        assert!(!text.contains("hawk_relay_backup"));
        // Every sample belongs to a family declared before it.
        let mut declared = Vec::new();
        for line in text.lines() {
            if let Some(name) = line.strip_prefix("# TYPE ").and_then(|rest| rest.split(' ').next()) {
                declared.push(name.to_owned());
            } else if !line.starts_with('#') {
                let name = line.split(['{', ' ']).next().unwrap();
                assert!(declared.iter().any(|family| family == name), "{line}");
            }
        }

        metrics.backups_enabled();
        metrics.backup_succeeded(1_700_000_000);
        metrics.backup_failed();
        let text = render(&metrics, &live, &audit, None);
        assert!(text.contains("hawk_relay_backup_last_success_timestamp_seconds 1700000000\n"));
        assert!(text.contains("hawk_relay_backups_total 1\n") && text.contains("hawk_relay_backup_failures_total 1\n"));
        assert!(!text.contains("hawk_relay_db_size_bytes"));
    }
}
