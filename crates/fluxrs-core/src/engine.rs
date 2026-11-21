//! Proxy engine: accepts connections (explicit proxy or proxyless
//! redirect), decrypts TLS, applies rules and breakpoints, forwards traffic.

use crate::body::{decode_body, is_encoded, set_fixed_length, strip_hop_by_hop, TeeBody};
use crate::cert::CertificateAuthority;
use crate::events::{log, EventSink, LogLevel, ProxyEvent};
use crate::intercept::{Decision, InterceptPhase, Interceptor};
use crate::io::{BoxIo, Rewind, WithGuard};
use crate::model::{Exchange, ExchangeState, HeaderList, RequestData, ResponseData};
use crate::nat::NatTable;
use crate::rawhttp;
use crate::rules::{self, CompiledRule, Rule, RuleError, RuleSet};
use crate::tls::{self, Sniff};
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Version};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{watch, Mutex as AsyncMutex};

pub type ProxyBody = BoxBody<Bytes, ProxyError>;

/// Concrete error type for the HTTP service and bodies.
#[derive(Debug)]
pub struct ProxyError(pub String);

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProxyError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureMode {
    /// Classic explicit HTTP proxy (configure clients to use 127.0.0.1:port).
    Proxy,
    /// Transparent capture with WinDivert, no proxy settings needed (Windows).
    Proxyless,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineConfig {
    pub mode: CaptureMode,
    pub port: u16,
    /// Explicit proxy mode: listen on all interfaces instead of loopback.
    pub listen_any: bool,
    pub decrypt_tls: bool,
    /// Hosts never decrypted (wildcards like `*.example.com`).
    pub bypass_hosts: Vec<String>,
    /// Accept invalid upstream certificates.
    pub insecure_upstream: bool,
    /// Max body bytes kept for display (streaming responses).
    pub max_capture_body: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            mode: if cfg!(windows) {
                CaptureMode::Proxyless
            } else {
                CaptureMode::Proxy
            },
            port: 44344,
            listen_any: false,
            decrypt_tls: true,
            bypass_hosts: vec![],
            insecure_upstream: false,
            max_capture_body: 8 * 1024 * 1024,
        }
    }
}

/// Live, shareable rule set.
#[derive(Clone, Default)]
pub struct RulesHandle(Arc<RwLock<Arc<RuleSet>>>);

impl RulesHandle {
    pub fn set(&self, rules: &[Rule]) -> Result<(), RuleError> {
        let compiled = RuleSet::compile(rules)?;
        *self.0.write() = Arc::new(compiled);
        Ok(())
    }
    pub(crate) fn current(&self) -> Arc<RuleSet> {
        self.0.read().clone()
    }
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn next_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

struct Shared {
    config: EngineConfig,
    ca: Arc<CertificateAuthority>,
    rules: RulesHandle,
    interceptor: Interceptor,
    sink: EventSink,
    tls_client: Arc<rustls::ClientConfig>,
    nat: Option<Arc<NatTable>>,
    local_port: u16,
}

impl Shared {
    fn emit(&self, ex: &Exchange) {
        (self.sink)(ProxyEvent::Exchange(Arc::new(ex.clone())));
    }

    fn bypass(&self, host: &str) -> bool {
        !self.config.decrypt_tls
            || self
                .config
                .bypass_hosts
                .iter()
                .any(|p| tls::host_matches(p, host))
    }
}

/// A running capture engine. Stops when dropped.
pub struct Engine {
    runtime: Option<tokio::runtime::Runtime>,
    shutdown: watch::Sender<bool>,
    local_addr: SocketAddr,
    sink: EventSink,
    #[cfg(windows)]
    redirector: Option<crate::divert::Redirector>,
}

impl Engine {
    pub fn start(
        config: EngineConfig,
        ca: Arc<CertificateAuthority>,
        rules: RulesHandle,
        interceptor: Interceptor,
        sink: EventSink,
    ) -> Result<Engine, String> {
        if config.mode == CaptureMode::Proxyless && !cfg!(windows) {
            return Err("Proxyless capture requires Windows (WinDivert)".into());
        }
        if config.mode == CaptureMode::Proxyless && (config.port == 80 || config.port == 443) {
            return Err("Proxy port must not be 80 or 443 in proxyless mode".into());
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("fluxrs-engine")
            .enable_all()
            .build()
            .map_err(|e| format!("runtime: {e}"))?;

        let ip: IpAddr = match config.mode {
            CaptureMode::Proxyless => IpAddr::from([0, 0, 0, 0]),
            CaptureMode::Proxy if config.listen_any => IpAddr::from([0, 0, 0, 0]),
            CaptureMode::Proxy => IpAddr::from([127, 0, 0, 1]),
        };
        let listener = runtime
            .block_on(TcpListener::bind(SocketAddr::new(ip, config.port)))
            .map_err(|e| format!("cannot listen on port {}: {e}", config.port))?;
        let local_addr = listener.local_addr().map_err(|e| e.to_string())?;

        let nat = (config.mode == CaptureMode::Proxyless)
            .then(|| NatTable::new(local_addr.port(), vec![80, 443]));

        let shared = Arc::new(Shared {
            tls_client: tls::client_config(ca.provider(), config.insecure_upstream),
            config,
            ca,
            rules,
            interceptor,
            sink: sink.clone(),
            nat: nat.clone(),
            local_port: local_addr.port(),
        });

        #[cfg(windows)]
        let redirector = match &nat {
            Some(nat) => {
                crate::firewall::ensure_rule(local_addr.port(), &sink);
                let s = sink.clone();
                let r = crate::divert::Redirector::start(nat.clone(), move |m| {
                    log(&s, LogLevel::Error, m)
                })?;
                Some(r)
            }
            None => None,
        };
        #[cfg(not(windows))]
        let _ = &nat;

        let (shutdown, rx) = watch::channel(false);
        runtime.spawn(accept_loop(listener, shared.clone(), rx));
        let mode = match shared.config.mode {
            CaptureMode::Proxy => "explicit proxy",
            CaptureMode::Proxyless => "proxyless (WinDivert)",
        };
        log(
            &sink,
            LogLevel::Info,
            format!("Capture started: {mode} on {local_addr}"),
        );
        Ok(Engine {
            runtime: Some(runtime),
            shutdown,
            local_addr,
            sink,
            #[cfg(windows)]
            redirector,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stop(&mut self) {
        #[cfg(windows)]
        if let Some(mut r) = self.redirector.take() {
            r.stop();
        }
        let _ = self.shutdown.send(true);
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_timeout(Duration::from_millis(500));
            (self.sink)(ProxyEvent::Stopped(None));
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn accept_loop(listener: TcpListener, shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            res = listener.accept() => match res {
                Ok((stream, peer)) => {
                    let _ = stream.set_nodelay(true);
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        handle_connection(shared, stream, peer).await;
                    });
                }
                Err(e) => {
                    log(&shared.sink, LogLevel::Warn, format!("accept failed: {e}"));
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
}

/// How requests on a connection are routed upstream.
#[derive(Clone, Debug)]
struct ConnCtx {
    client: SocketAddr,
    /// Top level explicit proxy connection (absolute-form URIs, CONNECT).
    explicit: bool,
    scheme: &'static str,
    /// SNI, CONNECT authority host or destination IP.
    host: Option<String>,
    port: u16,
    /// Original destination IP (proxyless).
    ip: Option<IpAddr>,
}

async fn handle_connection(shared: Arc<Shared>, stream: TcpStream, peer: SocketAddr) {
    match &shared.nat {
        None => {
            let ctx = ConnCtx {
                client: peer,
                explicit: true,
                scheme: "http",
                host: None,
                port: 80,
                ip: None,
            };
            serve_http(shared.clone(), Box::new(stream), ctx).await;
        }
        Some(nat) => {
            let SocketAddr::V4(v4) = peer else { return };
            let Some(orig_port) = nat.original_port(*v4.ip(), v4.port()) else {
                return;
            };
            let local_ip = stream
                .local_addr()
                .map(|a| a.ip())
                .unwrap_or(IpAddr::from([127, 0, 0, 1]));
            let client = SocketAddr::new(local_ip, v4.port());
            let server_ip = IpAddr::V4(*v4.ip());
            handle_inner(
                shared,
                Box::new(stream),
                client,
                None,
                Some(server_ip),
                orig_port,
            )
            .await;
        }
    }
}

/// Handle a stream whose destination is known (CONNECT tunnel or
/// transparent redirect): detect TLS, decrypt or tunnel, then serve HTTP.
async fn handle_inner(
    shared: Arc<Shared>,
    mut io: BoxIo,
    client: SocketAddr,
    host_hint: Option<String>,
    ip: Option<IpAddr>,
    port: u16,
) {
    let mut buf = Vec::with_capacity(4096);
    let sniff = loop {
        match tls::sniff_client_hello(&buf) {
            Sniff::NeedMore => {}
            other => break other,
        }
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(30), io.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
        if buf.len() > 64 * 1024 {
            break Sniff::Tls(None);
        }
    };
    let prefix = Bytes::from(buf);
    let fallback_host = host_hint
        .clone()
        .or_else(|| ip.map(|i| i.to_string()))
        .unwrap_or_default();
    match sniff {
        Sniff::NotTls => {
            let ctx = ConnCtx {
                client,
                explicit: false,
                scheme: "http",
                host: host_hint.or_else(|| ip.map(|i| i.to_string())),
                port,
                ip,
            };
            serve_http(shared, Box::new(Rewind::new(prefix, io)), ctx).await;
        }
        Sniff::Tls(sni) => {
            let host = sni.unwrap_or(fallback_host);
            if host.is_empty() {
                return;
            }
            if shared.bypass(&host) {
                tunnel(shared, Rewind::new(prefix, io), client, host, ip, port).await;
                return;
            }
            let cfg = match shared.ca.server_config(&host) {
                Ok(c) => c,
                Err(e) => {
                    log(
                        &shared.sink,
                        LogLevel::Error,
                        format!("cert for {host}: {e}"),
                    );
                    return;
                }
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
            let tls_stream = match tokio::time::timeout(
                Duration::from_secs(30),
                acceptor.accept(Rewind::new(prefix, io)),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    log(
                        &shared.sink,
                        LogLevel::Warn,
                        format!(
                            "TLS handshake with client failed for {host}: {e} (is the FluxRS root CA trusted? Pinned apps can be bypassed in Settings)"
                        ),
                    );
                    return;
                }
                Err(_) => return,
            };
            let ctx = ConnCtx {
                client,
                explicit: false,
                scheme: "https",
                host: Some(host),
                port,
                ip,
            };
            serve_http(shared, Box::new(tls_stream), ctx).await;
        }
        Sniff::NeedMore => unreachable!(),
    }
}

/// Raw TCP passthrough (no decryption).
async fn tunnel<S>(
    shared: Arc<Shared>,
    mut client_io: S,
    client: SocketAddr,
    host: String,
    ip: Option<IpAddr>,
    port: u16,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let started = Instant::now();
    let mut ex = new_exchange(
        Some(client),
        RequestData {
            method: "TUNNEL".into(),
            scheme: "https".into(),
            host: host.clone(),
            port,
            path: "/".into(),
            version: "TLS".into(),
            headers: vec![],
            body: Bytes::new(),
            body_truncated: false,
        },
    );
    shared.emit(&ex);
    let target = Target {
        host,
        port,
        tls: false,
        ip,
    };
    match connect_upstream(&shared, &target).await {
        Ok(mut up) => {
            let res = tokio::io::copy_bidirectional(&mut client_io, &mut up).await;
            ex.state = ExchangeState::Completed;
            if let Ok((a, b)) = res {
                ex.request.headers = vec![
                    ("x-fluxrs-bytes-sent".into(), a.to_string()),
                    ("x-fluxrs-bytes-received".into(), b.to_string()),
                ];
            }
        }
        Err(e) => {
            ex.state = ExchangeState::Failed;
            ex.error = Some(e);
        }
    }
    ex.duration_ms = Some(started.elapsed().as_millis() as u64);
    shared.emit(&ex);
}

fn new_exchange(client: Option<SocketAddr>, request: RequestData) -> Exchange {
    Exchange {
        id: next_id(),
        client,
        started: SystemTime::now(),
        state: ExchangeState::Pending,
        request,
        response: None,
        error: None,
        duration_ms: None,
        ttfb_ms: None,
        applied_rules: vec![],
        intercepted: false,
        upgraded: false,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Target {
    host: String,
    port: u16,
    tls: bool,
    ip: Option<IpAddr>,
}

async fn connect_upstream(shared: &Arc<Shared>, target: &Target) -> Result<BoxIo, String> {
    let addrs: Vec<SocketAddr> = match target.ip {
        Some(ip) => vec![SocketAddr::new(ip, target.port)],
        None => {
            let host = target.host.trim_start_matches('[').trim_end_matches(']');
            tokio::time::timeout(
                Duration::from_secs(10),
                tokio::net::lookup_host((host, target.port)),
            )
            .await
            .map_err(|_| format!("DNS timeout for {host}"))?
            .map_err(|e| format!("DNS lookup failed for {host}: {e}"))?
            .collect()
        }
    };
    // Prefer IPv4 in proxyless mode (only IPv4 is excluded from redirect).
    let mut addrs = addrs;
    if shared.nat.is_some() {
        addrs.sort_by_key(|a| !a.is_ipv4());
    }
    let mut last_err = format!("no address for {}", target.host);
    for addr in addrs {
        // Never connect back into ourselves.
        if addr.port() == shared.local_port && addr.ip().is_loopback() {
            return Err("refusing to connect to the proxy itself (loop)".into());
        }
        match connect_one(shared, addr).await {
            Ok(io) => {
                if !target.tls {
                    return Ok(io);
                }
                let name = tls::server_name(&target.host)?;
                let connector = tokio_rustls::TlsConnector::from(shared.tls_client.clone());
                return match tokio::time::timeout(
                    Duration::from_secs(15),
                    connector.connect(name, io),
                )
                .await
                {
                    Ok(Ok(s)) => Ok(Box::new(s)),
                    Ok(Err(e)) => Err(format!("upstream TLS error ({}): {e}", target.host)),
                    Err(_) => Err(format!("upstream TLS timeout ({})", target.host)),
                };
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

async fn connect_one(shared: &Arc<Shared>, addr: SocketAddr) -> Result<BoxIo, String> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(|e| e.to_string())?;
    let mut guard = None;
    if let (Some(nat), true) = (&shared.nat, addr.is_ipv4()) {
        // Bind first so the local port is known (and excluded from
        // redirection) before the SYN leaves.
        socket
            .bind(SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0))
            .map_err(|e| e.to_string())?;
        let port = socket.local_addr().map_err(|e| e.to_string())?.port();
        guard = Some(nat.register_owned_port(port));
    }
    let stream = tokio::time::timeout(Duration::from_secs(10), socket.connect(addr))
        .await
        .map_err(|_| format!("connect timeout to {addr}"))?
        .map_err(|e| format!("connect to {addr} failed: {e}"))?;
    let _ = stream.set_nodelay(true);
    Ok(Box::new(WithGuard {
        inner: stream,
        _guard: guard,
    }))
}

struct UpstreamConn {
    target: Target,
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
}

fn serve_http(
    shared: Arc<Shared>,
    io: BoxIo,
    ctx: ConnCtx,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    // Boxed with an explicit type: serve_http -> handle_request ->
    // handle_connect -> handle_inner -> serve_http is recursive.
    Box::pin(async move {
        let ctx = Arc::new(ctx);
        let upstream: Arc<AsyncMutex<Option<UpstreamConn>>> = Arc::new(AsyncMutex::new(None));
        let svc = service_fn(move |req| {
            let shared = shared.clone();
            let ctx = ctx.clone();
            let upstream = upstream.clone();
            let fut: std::pin::Pin<Box<dyn std::future::Future<Output = HandlerResult> + Send>> =
                Box::pin(handle_request(shared, ctx, upstream, req));
            fut
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .keep_alive(true)
            .serve_connection(TokioIo::new(io), svc)
            .with_upgrades()
            .await;
    })
}

fn box_err<E: std::fmt::Display>(e: E) -> ProxyError {
    ProxyError(e.to_string())
}

fn headers_to_list(h: &http::HeaderMap) -> HeaderList {
    h.iter()
        .map(|(n, v)| {
            (
                n.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}

fn fill_headers(map: &mut http::HeaderMap, list: &HeaderList) {
    for (n, v) in list {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(n.trim().as_bytes()),
            HeaderValue::from_bytes(v.as_bytes()),
        ) {
            map.append(n, v);
        }
    }
}

fn version_str(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/?",
    }
}

fn full(b: impl Into<Bytes>) -> ProxyBody {
    Full::new(b.into()).map_err(|e| match e {}).boxed()
}

fn empty() -> ProxyBody {
    Empty::<Bytes>::new().map_err(|e| match e {}).boxed()
}

fn simple_response(status: u16, content_type: &str, body: impl Into<Bytes>) -> Response<ProxyBody> {
    let body = body.into();
    let mut r = Response::new(full(body.clone()));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    if let Ok(v) = HeaderValue::from_str(content_type) {
        r.headers_mut().insert(http::header::CONTENT_TYPE, v);
    }
    r.headers_mut()
        .insert(http::header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    r
}

/// Split "host:port" / "[v6]:port" / "host".
pub(crate) fn split_host_port(s: &str) -> (String, Option<u16>) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((h, tail)) = rest.split_once(']') {
            let port = tail.strip_prefix(':').and_then(|p| p.parse().ok());
            return (h.to_string(), port);
        }
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => match p.parse() {
            Ok(port) => (h.to_string(), Some(port)),
            Err(_) => (s.to_string(), None),
        },
        _ => (s.to_string(), None),
    }
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "https" {
        443
    } else {
        80
    }
}

fn host_header_value(host: &str, port: u16, scheme: &str) -> String {
    let h = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == default_port(scheme) {
        h
    } else {
        format!("{h}:{port}")
    }
}

fn info_page(shared: &Shared, path: &str) -> Response<ProxyBody> {
    if path.starts_with("/ca.crt") || path.starts_with("/cert") {
        let mut r = simple_response(
            200,
            "application/x-x509-ca-cert",
            shared.ca.ca_pem().as_bytes().to_vec(),
        );
        r.headers_mut().insert(
            http::header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=\"fluxrs-root-ca.crt\""),
        );
        return r;
    }
    simple_response(
        200,
        "text/html; charset=utf-8",
        "<!doctype html><html><head><title>FluxRS</title></head>\
         <body style=\"font-family:sans-serif;background:#0f1117;color:#e6e8ef;padding:40px\">\
         <h1>FluxRS proxy is running</h1>\
         <p><a style=\"color:#8b7bff\" href=\"/ca.crt\">Download the FluxRS root CA certificate</a></p>\
         </body></html>",
    )
}

type HandlerResult = Result<Response<ProxyBody>, ProxyError>;

async fn handle_request(
    shared: Arc<Shared>,
    ctx: Arc<ConnCtx>,
    upstream: Arc<AsyncMutex<Option<UpstreamConn>>>,
    mut req: Request<Incoming>,
) -> HandlerResult {
    if req.method() == Method::CONNECT {
        return Ok(handle_connect(shared, ctx, req));
    }

    // Resolve where the request goes.
    let (scheme, host, port, ip) = if ctx.explicit {
        let uri = req.uri();
        match (uri.scheme_str(), uri.host()) {
            (Some(s), Some(h)) => {
                let scheme = if s.eq_ignore_ascii_case("https") {
                    "https"
                } else {
                    "http"
                };
                let host = h.trim_start_matches('[').trim_end_matches(']').to_string();
                let port = uri.port_u16().unwrap_or(default_port(scheme));
                let is_self = port == shared.local_port
                    && (host == "localhost"
                        || host.parse::<IpAddr>().is_ok_and(|i| i.is_loopback()));
                if is_self {
                    return Ok(info_page(&shared, uri.path()));
                }
                (scheme, host, port, None)
            }
            _ => return Ok(info_page(&shared, uri.path())),
        }
    } else {
        let from_header = req
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(split_host_port)
            .map(|(h, _)| h)
            .filter(|h| !h.is_empty());
        let host = from_header
            .or_else(|| ctx.host.clone())
            .unwrap_or_else(|| "localhost".into());
        (ctx.scheme, host, ctx.port, ctx.ip)
    };

    let started = Instant::now();
    let is_upgrade = req.headers().contains_key(http::header::UPGRADE);
    let client_upgrade = is_upgrade.then(|| hyper::upgrade::on(&mut req));
    let (parts, body) = req.into_parts();
    let had_body_framing = parts.headers.contains_key(http::header::CONTENT_LENGTH)
        || parts.headers.contains_key(http::header::TRANSFER_ENCODING);
    let body = body.collect().await.map_err(box_err)?.to_bytes();

    let mut rd = RequestData {
        method: parts.method.as_str().to_string(),
        scheme: scheme.to_string(),
        host: host.clone(),
        port,
        path: parts
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into()),
        version: version_str(parts.version).to_string(),
        headers: headers_to_list(&parts.headers),
        body,
        body_truncated: false,
    };
    // Explicit proxies receive absolute-form; drop proxy-only headers.
    rules::remove_header(&mut rd.headers, "proxy-connection");
    rules::remove_header(&mut rd.headers, "proxy-authorization");

    let mut ex = new_exchange(Some(ctx.client), rd.clone());
    let mut ip = ip;

    // Rules (request phase).
    let ruleset = shared.rules.current();
    let matched: Vec<&CompiledRule> = ruleset.matching(&rd);
    ex.applied_rules = matched.iter().map(|r| r.name.clone()).collect();
    let intercept_req = shared
        .interceptor
        .should_intercept(InterceptPhase::Request, &rd);
    if (rules::rules_need_request_body(&matched) || intercept_req) && is_encoded(&rd.headers) {
        if let Some(decoded) = decode_body(&rd.headers, &rd.body) {
            rd.body = decoded;
            rules::remove_header(&mut rd.headers, "content-encoding");
        }
    }
    let outcome = rules::apply_request_actions(&matched, &mut rd);
    if outcome.delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(outcome.delay_ms.min(120_000))).await;
    }
    if outcome.block {
        ex.request = rd;
        ex.state = ExchangeState::Aborted;
        ex.error = Some("Blocked by rule".into());
        ex.duration_ms = Some(started.elapsed().as_millis() as u64);
        shared.emit(&ex);
        return Err(ProxyError("blocked by rule".into()));
    }
    if let Some((new_host, new_port, https)) = outcome.redirect {
        if let Some(h) = https {
            rd.scheme = if h { "https".into() } else { "http".into() };
        }
        rd.port = new_port.unwrap_or(default_port(&rd.scheme));
        rd.host = new_host;
        ip = None;
        rules::set_header(
            &mut rd.headers,
            "Host",
            &host_header_value(&rd.host, rd.port, &rd.scheme),
        );
    }
    if let Some((status, content_type, body)) = outcome.mock {
        ex.request = rd;
        let mut headers = vec![];
        if !content_type.is_empty() {
            headers.push(("content-type".to_string(), content_type.clone()));
        }
        let body = Bytes::from(body.into_bytes());
        set_fixed_length(&mut headers, body.len());
        ex.response = Some(ResponseData {
            status,
            reason: reason_for(status),
            version: "HTTP/1.1".into(),
            headers: headers.clone(),
            body: body.clone(),
            body_truncated: false,
        });
        ex.state = ExchangeState::Completed;
        ex.duration_ms = Some(started.elapsed().as_millis() as u64);
        ex.ttfb_ms = ex.duration_ms;
        shared.emit(&ex);
        return Ok(build_response(status, &headers, full(body)));
    }

    // Breakpoint (request).
    if intercept_req {
        ex.request = rd.clone();
        ex.state = ExchangeState::Intercepted;
        ex.intercepted = true;
        shared.emit(&ex);
        let (raw, binary) =
            rawhttp::format_request(&rd.method, &rd.path, &rd.version, &rd.headers, &rd.body);
        let title = format!("{} {}", rd.method, rd.url());
        let (ticket, rx) =
            shared
                .interceptor
                .ticket(ex.id, InterceptPhase::Request, title, raw, binary);
        (shared.sink)(ProxyEvent::Intercepted(ticket));
        match rx.await {
            Ok(Decision::Drop) => {
                ex.state = ExchangeState::Aborted;
                ex.error = Some("Dropped by user".into());
                ex.duration_ms = Some(started.elapsed().as_millis() as u64);
                shared.emit(&ex);
                return Err(ProxyError("dropped by user".into()));
            }
            Ok(Decision::Forward(Some(edited))) => {
                match rawhttp::parse_request(&edited, binary, &rd.body) {
                    Ok(p) => {
                        let old_host = rd.host.clone();
                        rd.method = p.method;
                        rd.path = p.path;
                        rd.headers = p.headers;
                        rd.body = p.body;
                        if let Some(hv) = rd.header("host").map(|s| s.to_string()) {
                            let (h, p) = split_host_port(&hv);
                            if !h.is_empty() && !h.eq_ignore_ascii_case(&old_host) {
                                rd.host = h;
                                rd.port = p.unwrap_or(default_port(&rd.scheme));
                                ip = None;
                            } else if let Some(p) = p {
                                if p != rd.port {
                                    rd.port = p;
                                    ip = None;
                                }
                            }
                        }
                    }
                    Err(e) => log(
                        &shared.sink,
                        LogLevel::Warn,
                        format!("edited request ignored (parse error: {e})"),
                    ),
                }
            }
            Ok(Decision::Forward(None)) | Err(_) => {}
        }
    }

    ex.request = rd.clone();
    ex.state = ExchangeState::Pending;
    shared.emit(&ex);

    // Build the upstream request.
    let mut up_headers = rd.headers.clone();
    strip_hop_by_hop(&mut up_headers, is_upgrade);
    if !rd.body.is_empty() || had_body_framing {
        set_fixed_length(&mut up_headers, rd.body.len());
    }
    if rd.header("host").is_none() {
        up_headers.insert(
            0,
            (
                "host".into(),
                host_header_value(&rd.host, rd.port, &rd.scheme),
            ),
        );
    }
    let method = match Method::from_bytes(rd.method.as_bytes()) {
        Ok(m) => m,
        Err(_) => return Ok(fail(&shared, &mut ex, started, "invalid HTTP method")),
    };
    let make_req = || -> Result<Request<Full<Bytes>>, String> {
        let mut r = Request::builder()
            .method(method.clone())
            .uri(rd.path.as_str())
            .version(Version::HTTP_11)
            .body(Full::new(rd.body.clone()))
            .map_err(|e| format!("invalid request: {e}"))?;
        fill_headers(r.headers_mut(), &up_headers);
        Ok(r)
    };
    let target = Target {
        host: rd.host.clone(),
        port: rd.port,
        tls: rd.scheme == "https",
        ip,
    };

    // WebSocket / upgrade path.
    if let Some(client_upgrade) = client_upgrade {
        let up_req = match make_req() {
            Ok(r) => r,
            Err(e) => return Ok(fail(&shared, &mut ex, started, &e)),
        };
        return Ok(handle_upgrade(shared, ex, started, target, up_req, client_upgrade).await);
    }

    let resp = match send_upstream(&shared, &upstream, &target, &make_req).await {
        Ok(r) => r,
        Err(e) => return Ok(fail(&shared, &mut ex, started, &e)),
    };
    ex.ttfb_ms = Some(started.elapsed().as_millis() as u64);

    let (rparts, rbody) = resp.into_parts();
    let orig_status = rparts.status.as_u16();
    let mut status = orig_status;
    let mut rheaders = headers_to_list(&rparts.headers);
    rules::apply_response_head_actions(&matched, &mut status, &mut rheaders);
    let intercept_resp = shared
        .interceptor
        .should_intercept(InterceptPhase::Response, &rd);
    let bodiless = rd.method == "HEAD"
        || (100..200).contains(&orig_status)
        || orig_status == 204
        || orig_status == 304;
    let mut reason = rparts.status.canonical_reason().unwrap_or("").to_string();
    let rversion = version_str(rparts.version).to_string();

    if rules::rules_need_response_body(&matched) || intercept_resp {
        // Buffered path: body may be changed.
        let mut body = match rbody.collect().await {
            Ok(b) => b.to_bytes(),
            Err(e) => {
                return Ok(fail(
                    &shared,
                    &mut ex,
                    started,
                    &format!("reading response: {e}"),
                ))
            }
        };
        if is_encoded(&rheaders) {
            if let Some(decoded) = decode_body(&rheaders, &body) {
                body = decoded;
                rules::remove_header(&mut rheaders, "content-encoding");
            }
        }
        rules::apply_response_body_actions(&matched, &mut body);
        if intercept_resp {
            ex.state = ExchangeState::Intercepted;
            ex.intercepted = true;
            ex.response = Some(ResponseData {
                status,
                reason: reason.clone(),
                version: rversion.clone(),
                headers: rheaders.clone(),
                body: body.clone(),
                body_truncated: false,
            });
            shared.emit(&ex);
            let (raw, binary) =
                rawhttp::format_response("HTTP/1.1", status, &reason, &rheaders, &body);
            let title = format!("{} {} → {}", rd.method, rd.url(), status);
            let (ticket, rx) =
                shared
                    .interceptor
                    .ticket(ex.id, InterceptPhase::Response, title, raw, binary);
            (shared.sink)(ProxyEvent::Intercepted(ticket));
            match rx.await {
                Ok(Decision::Drop) => {
                    ex.state = ExchangeState::Aborted;
                    ex.error = Some("Response dropped by user".into());
                    ex.duration_ms = Some(started.elapsed().as_millis() as u64);
                    shared.emit(&ex);
                    return Err(ProxyError("dropped by user".into()));
                }
                Ok(Decision::Forward(Some(edited))) => {
                    match rawhttp::parse_response(&edited, binary, &body) {
                        Ok(p) => {
                            status = p.status;
                            reason = p.reason;
                            rheaders = p.headers;
                            body = p.body;
                        }
                        Err(e) => log(
                            &shared.sink,
                            LogLevel::Warn,
                            format!("edited response ignored (parse error: {e})"),
                        ),
                    }
                }
                Ok(Decision::Forward(None)) | Err(_) => {}
            }
        }
        strip_hop_by_hop(&mut rheaders, false);
        if !bodiless {
            set_fixed_length(&mut rheaders, body.len());
        }
        let send_body = if bodiless { Bytes::new() } else { body.clone() };
        ex.response = Some(ResponseData {
            status,
            reason,
            version: rversion,
            headers: rheaders.clone(),
            body,
            body_truncated: false,
        });
        ex.state = ExchangeState::Completed;
        ex.duration_ms = Some(started.elapsed().as_millis() as u64);
        shared.emit(&ex);
        return Ok(build_response(status, &rheaders, full(send_body)));
    }

    // Streaming path: forward as it arrives, keep a capped copy.
    strip_hop_by_hop(&mut rheaders, false);
    ex.response = Some(ResponseData {
        status,
        reason,
        version: rversion,
        headers: rheaders.clone(),
        body: Bytes::new(),
        body_truncated: false,
    });
    ex.state = ExchangeState::Receiving;
    shared.emit(&ex);
    let shared2 = shared.clone();
    let tee = TeeBody::new(
        rbody,
        shared.config.max_capture_body,
        move |body, truncated, err| {
            let mut ex = ex;
            if let Some(r) = ex.response.as_mut() {
                r.body = body;
                r.body_truncated = truncated;
            }
            ex.duration_ms = Some(started.elapsed().as_millis() as u64);
            match err {
                None => ex.state = ExchangeState::Completed,
                Some(e) => {
                    ex.state = ExchangeState::Failed;
                    ex.error = Some(e);
                }
            }
            shared2.emit(&ex);
        },
    );
    Ok(build_response(
        status,
        &rheaders,
        tee.map_err(box_err).boxed(),
    ))
}

fn reason_for(status: u16) -> String {
    StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("")
        .to_string()
}

fn build_response(status: u16, headers: &HeaderList, body: ProxyBody) -> Response<ProxyBody> {
    let mut r = Response::new(body);
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    fill_headers(r.headers_mut(), headers);
    r
}

fn fail(shared: &Shared, ex: &mut Exchange, started: Instant, msg: &str) -> Response<ProxyBody> {
    ex.state = ExchangeState::Failed;
    ex.error = Some(msg.to_string());
    ex.duration_ms = Some(started.elapsed().as_millis() as u64);
    shared.emit(ex);
    simple_response(
        502,
        "text/plain; charset=utf-8",
        format!("FluxRS: upstream error: {msg}\n"),
    )
}

async fn send_upstream(
    shared: &Arc<Shared>,
    slot: &AsyncMutex<Option<UpstreamConn>>,
    target: &Target,
    make_req: &(dyn Fn() -> Result<Request<Full<Bytes>>, String> + Sync),
) -> Result<Response<Incoming>, String> {
    let mut slot = slot.lock().await;
    // Try a reused connection first.
    if let Some(mut conn) = slot.take() {
        if conn.target == *target && conn.sender.ready().await.is_ok() {
            match conn.sender.send_request(make_req()?).await {
                Ok(resp) => {
                    *slot = Some(conn);
                    return Ok(resp);
                }
                Err(e) if !e.is_canceled() && !e.is_closed() && !e.is_incomplete_message() => {
                    return Err(format!("upstream error: {e}"));
                }
                Err(_) => {} // stale connection: reconnect once
            }
        }
    }
    let io = connect_upstream(shared, target).await?;
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake::<_, Full<Bytes>>(TokioIo::new(io))
        .await
        .map_err(|e| format!("upstream handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = sender
        .send_request(make_req()?)
        .await
        .map_err(|e| format!("upstream error: {e}"))?;
    *slot = Some(UpstreamConn {
        target: target.clone(),
        sender,
    });
    Ok(resp)
}

async fn handle_upgrade(
    shared: Arc<Shared>,
    mut ex: Exchange,
    started: Instant,
    target: Target,
    up_req: Request<Full<Bytes>>,
    client_upgrade: hyper::upgrade::OnUpgrade,
) -> Response<ProxyBody> {
    let io = match connect_upstream(&shared, &target).await {
        Ok(io) => io,
        Err(e) => return fail(&shared, &mut ex, started, &e),
    };
    let (mut sender, conn) = match hyper::client::conn::http1::Builder::new()
        .handshake::<_, Full<Bytes>>(TokioIo::new(io))
        .await
    {
        Ok(x) => x,
        Err(e) => {
            return fail(
                &shared,
                &mut ex,
                started,
                &format!("upstream handshake: {e}"),
            )
        }
    };
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    let mut resp = match sender.send_request(up_req).await {
        Ok(r) => r,
        Err(e) => return fail(&shared, &mut ex, started, &format!("upstream error: {e}")),
    };
    ex.ttfb_ms = Some(started.elapsed().as_millis() as u64);
    let status = resp.status().as_u16();
    let mut headers = headers_to_list(resp.headers());
    if status != 101 {
        let body = resp
            .into_body()
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        strip_hop_by_hop(&mut headers, false);
        set_fixed_length(&mut headers, body.len());
        ex.response = Some(ResponseData {
            status,
            reason: reason_for(status),
            version: "HTTP/1.1".into(),
            headers: headers.clone(),
            body: body.clone(),
            body_truncated: false,
        });
        ex.state = ExchangeState::Completed;
        ex.duration_ms = Some(started.elapsed().as_millis() as u64);
        shared.emit(&ex);
        return build_response(status, &headers, full(body));
    }
    let server_upgrade = hyper::upgrade::on(&mut resp);
    strip_hop_by_hop(&mut headers, true);
    ex.upgraded = true;
    ex.response = Some(ResponseData {
        status,
        reason: "Switching Protocols".into(),
        version: "HTTP/1.1".into(),
        headers: headers.clone(),
        body: Bytes::new(),
        body_truncated: false,
    });
    ex.state = ExchangeState::Receiving;
    shared.emit(&ex);
    let shared2 = shared.clone();
    tokio::spawn(async move {
        match tokio::try_join!(client_upgrade, server_upgrade) {
            Ok((c, s)) => {
                let mut c = TokioIo::new(c);
                let mut s = TokioIo::new(s);
                let _ = tokio::io::copy_bidirectional(&mut c, &mut s).await;
                ex.state = ExchangeState::Completed;
            }
            Err(e) => {
                ex.state = ExchangeState::Failed;
                ex.error = Some(format!("upgrade failed: {e}"));
            }
        }
        ex.duration_ms = Some(started.elapsed().as_millis() as u64);
        shared2.emit(&ex);
    });
    build_response(101, &headers, empty())
}

fn handle_connect(
    shared: Arc<Shared>,
    ctx: Arc<ConnCtx>,
    req: Request<Incoming>,
) -> Response<ProxyBody> {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .unwrap_or_default();
    let (host, port) = split_host_port(&authority);
    let port = port.unwrap_or(443);
    if host.is_empty() {
        return simple_response(400, "text/plain", "bad CONNECT target");
    }
    let client = ctx.client;
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io: BoxIo = Box::new(TokioIo::new(upgraded));
                handle_inner(shared, io, client, Some(host), None, port).await;
            }
            Err(e) => log(
                &shared.sink,
                LogLevel::Warn,
                format!("CONNECT upgrade failed: {e}"),
            ),
        }
    });
    Response::new(empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_split() {
        assert_eq!(split_host_port("a.com:8080"), ("a.com".into(), Some(8080)));
        assert_eq!(split_host_port("a.com"), ("a.com".into(), None));
        assert_eq!(split_host_port("[::1]:443"), ("::1".into(), Some(443)));
        assert_eq!(split_host_port("::1"), ("::1".into(), None));
        assert_eq!(host_header_value("::1", 8080, "http"), "[::1]:8080");
        assert_eq!(host_header_value("a.com", 443, "https"), "a.com");
    }
}
