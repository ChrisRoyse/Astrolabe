//! Loopback-only HTTP listener serving `GET /metrics` and optional origin APIs.
//!
//! Binding any non-loopback address is a hard `CALYX_DAEMON_BIND_FAILED`; the
//! daemon does not start. The handler speaks just enough HTTP/1.1 for a
//! Prometheus scrape compatibility is preserved: `GET /metrics` returns text
//! format v0.0.4. When configured, issue #813 Worker-origin routes are also
//! served on the same loopback listener with bounded JSON bodies and bearer auth.

mod http;

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use crate::error::DaemonError;
use crate::learner_origin::LearnerOriginService;
use crate::metrics::CalyxMetrics;
use http::{
    DEFAULT_BODY_LIMIT, HttpRequest, HttpResponse, IO_TIMEOUT, read_request, write_response,
};

const ACCEPT_IDLE_SLEEP: Duration = Duration::from_millis(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const CONTENT_TYPE: &str = "text/plain; version=0.0.4";
const PLAIN_CONTENT_TYPE: &str = "text/plain; charset=utf-8";
const JSON_CONTENT_TYPE: &str = "application/json";

/// Loopback `/metrics` server.
pub struct MetricsServer {
    listener: TcpListener,
    metrics: Arc<CalyxMetrics>,
    origin: Option<Arc<LearnerOriginService>>,
    active: Arc<AtomicUsize>,
}

impl MetricsServer {
    /// Binds `addr`, refusing any non-loopback IP before touching the OS.
    pub fn bind(addr: SocketAddr, metrics: Arc<CalyxMetrics>) -> Result<Self, DaemonError> {
        Self::bind_inner(addr, metrics, None)
    }

    pub fn bind_with_origin(
        addr: SocketAddr,
        metrics: Arc<CalyxMetrics>,
        origin: Arc<LearnerOriginService>,
    ) -> Result<Self, DaemonError> {
        Self::bind_inner(addr, metrics, Some(origin))
    }

    fn bind_inner(
        addr: SocketAddr,
        metrics: Arc<CalyxMetrics>,
        origin: Option<Arc<LearnerOriginService>>,
    ) -> Result<Self, DaemonError> {
        if !addr.ip().is_loopback() {
            return Err(DaemonError::bind_failed(format!(
                "refused non-loopback bind address {addr}; calyxd serves loopback only"
            )));
        }
        let listener = TcpListener::bind(addr)
            .map_err(|error| DaemonError::bind_failed(format!("bind {addr}: {error}")))?;
        Ok(Self {
            listener,
            metrics,
            origin,
            active: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// The actually-bound address (port 0 resolves here).
    pub fn local_addr(&self) -> Result<SocketAddr, DaemonError> {
        self.listener
            .local_addr()
            .map_err(|error| DaemonError::bind_failed(format!("local_addr: {error}")))
    }

    /// Number of connection handlers currently in flight.
    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    /// Accept loop; each connection is served on its own thread so one stuck
    /// client cannot block the next scrape. The loop returns only after
    /// `cancel_token` fires and in-flight handlers have drained or timed out.
    pub fn run(self, cancel_token: CancellationToken) -> Result<(), DaemonError> {
        self.listener.set_nonblocking(true).map_err(|error| {
            DaemonError::bind_failed(format!("set metrics listener nonblocking: {error}"))
        })?;
        while !cancel_token.is_cancelled() {
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    let metrics = Arc::clone(&self.metrics);
                    let origin = self.origin.as_ref().map(Arc::clone);
                    let active = Arc::clone(&self.active);
                    active.fetch_add(1, Ordering::SeqCst);
                    std::thread::spawn(move || {
                        let outcome = catch_unwind(AssertUnwindSafe(|| {
                            handle_connection(stream, &metrics, origin.as_deref())
                        }));
                        active.fetch_sub(1, Ordering::SeqCst);
                        match outcome {
                            Ok(Ok(())) => {}
                            Ok(Err(detail)) => {
                                eprintln!("calyxd: metrics connection from {peer}: {detail}");
                            }
                            Err(_panic) => {
                                eprintln!(
                                    "calyxd: CALYX_DAEMON_CONN_PANIC: metrics connection from \
                                     {peer} panicked; connection dropped, server continues"
                                );
                            }
                        }
                    });
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(ACCEPT_IDLE_SLEEP);
                }
                Err(error) => {
                    eprintln!("calyxd: accept on metrics listener failed: {error}");
                }
            }
        }

        let deadline = Instant::now() + DRAIN_TIMEOUT;
        while self.active.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
            std::thread::sleep(ACCEPT_IDLE_SLEEP);
        }
        Ok(())
    }
}

/// Serves exactly one HTTP request on `stream`.
fn handle_connection(
    mut stream: TcpStream,
    metrics: &CalyxMetrics,
    origin: Option<&LearnerOriginService>,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set write timeout: {error}"))?;

    let max_body = origin
        .map(LearnerOriginService::max_body_bytes)
        .unwrap_or(DEFAULT_BODY_LIMIT);
    let request = match read_request(&mut stream, max_body) {
        Ok(request) => request,
        Err(error) => {
            let response = HttpResponse {
                status: error.status(),
                content_type: PLAIN_CONTENT_TYPE,
                body: error.body(),
            };
            write_response(&mut stream, &response)?;
            return Err(format!("unreadable request: {error:?}"));
        }
    };

    let response = route(&request, metrics, origin);
    write_response(&mut stream, &response)
}

/// Routes one parsed request to a response.
fn route(
    request: &HttpRequest,
    metrics: &CalyxMetrics,
    origin: Option<&LearnerOriginService>,
) -> HttpResponse {
    if let Some(origin) = origin
        && origin.handles_path(&request.path)
        && request.path != "/metrics"
    {
        let response = origin.handle(
            &request.method,
            &request.path,
            request.header("authorization"),
            &request.body,
        );
        return HttpResponse {
            status: response.status,
            content_type: JSON_CONTENT_TYPE,
            body: response.body,
        };
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/metrics") => match metrics.encode_text() {
            Ok(mut text) => {
                if let Some(origin) = origin {
                    match origin.metrics().encode_text() {
                        Ok(origin_text) => text.push_str(&origin_text),
                        Err(detail) => {
                            eprintln!("calyxd: {detail}");
                            return HttpResponse {
                                status: "500 Internal Server Error",
                                content_type: PLAIN_CONTENT_TYPE,
                                body: format!("{detail}\n"),
                            };
                        }
                    }
                }
                HttpResponse {
                    status: "200 OK",
                    content_type: CONTENT_TYPE,
                    body: text,
                }
            }
            Err(detail) => {
                eprintln!("calyxd: {detail}");
                HttpResponse {
                    status: "500 Internal Server Error",
                    content_type: PLAIN_CONTENT_TYPE,
                    body: format!("{detail}\n"),
                }
            }
        },
        ("GET", _) => HttpResponse {
            status: "404 Not Found",
            content_type: PLAIN_CONTENT_TYPE,
            body: "only /metrics is served\n".to_string(),
        },
        _ => HttpResponse {
            status: "405 Method Not Allowed",
            content_type: PLAIN_CONTENT_TYPE,
            body: "only GET /metrics is served unless learner_origin is configured\n".to_string(),
        },
    }
}

