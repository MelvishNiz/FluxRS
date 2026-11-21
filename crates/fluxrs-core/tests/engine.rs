//! End-to-end tests of the engine in explicit proxy mode.

use bytes::Bytes;
use fluxrs_core::*;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type Events = Arc<Mutex<Vec<Arc<Exchange>>>>;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Upstream echo server: replies with "METHOD PATH BODY".
async fn echo_service(
    req: hyper::Request<hyper::body::Incoming>,
) -> Result<hyper::Response<Full<Bytes>>, std::convert::Infallible> {
    let method = req.method().to_string();
    let path = req.uri().path_and_query().unwrap().to_string();
    let xin = req
        .headers()
        .get("x-in")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    let body = req.into_body().collect().await.unwrap().to_bytes();
    let text = format!(
        "{method} {path} {} x-in={xin} count=123",
        String::from_utf8_lossy(&body)
    );
    Ok(hyper::Response::builder()
        .header("content-type", "text/plain")
        .header("x-server", "echo")
        .body(Full::new(Bytes::from(text)))
        .unwrap())
}

async fn start_plain_upstream() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(s), service_fn(echo_service))
                    .await;
            });
        }
    });
    addr
}

async fn start_tls_upstream() -> SocketAddr {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(s).await {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service_fn(echo_service))
                        .await;
                }
            });
        }
    });
    addr
}

struct Harness {
    engine: Option<Engine>,
    events: Events,
    ca: Arc<CertificateAuthority>,
    interceptor: Interceptor,
    rules: RulesHandle,
    _dir: tempfile::TempDir,
}

impl Harness {
    fn new(on_ticket: impl Fn(InterceptTicket) + Send + Sync + 'static) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let ca = Arc::new(CertificateAuthority::load_or_create(dir.path()).unwrap());
        let events: Events = Arc::default();
        let ev = events.clone();
        let sink: EventSink = Arc::new(move |e| match e {
            ProxyEvent::Exchange(x) => ev.lock().push(x),
            ProxyEvent::Intercepted(t) => on_ticket(t),
            _ => {}
        });
        let rules = RulesHandle::default();
        let interceptor = Interceptor::default();
        let cfg = EngineConfig {
            mode: CaptureMode::Proxy,
            port: 0,
            insecure_upstream: true,
            ..Default::default()
        };
        let engine =
            Engine::start(cfg, ca.clone(), rules.clone(), interceptor.clone(), sink).unwrap();
        Harness {
            engine: Some(engine),
            events,
            ca,
            interceptor,
            rules,
            _dir: dir,
        }
    }

    fn proxy(&self) -> SocketAddr {
        self.engine.as_ref().unwrap().local_addr()
    }

    /// Last snapshot of the exchange whose path contains `needle`.
    fn find(&self, needle: &str) -> Option<Arc<Exchange>> {
        self.events
            .lock()
            .iter()
            .rev()
            .find(|e| e.request.path.contains(needle))
            .cloned()
    }

    fn wait_state(&self, needle: &str, state: ExchangeState) -> Arc<Exchange> {
        for _ in 0..200 {
            if let Some(e) = self.find(needle) {
                if e.state == state {
                    return e;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!(
            "exchange {needle} never reached {state:?}: {:?}",
            self.find(needle)
        );
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(mut e) = self.engine.take() {
            e.stop();
        }
    }
}

async fn send_via_proxy(
    proxy: SocketAddr,
    req: hyper::Request<Full<Bytes>>,
) -> (u16, hyper::HeaderMap, String) {
    let s = TcpStream::connect(proxy).await.unwrap();
    let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(s))
        .await
        .unwrap();
    tokio::spawn(conn);
    let resp = tx.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

#[test]
fn plain_http_with_rewrite_rules() {
    let h = Harness::new(|_| {});
    h.rules
        .set(&[Rule {
            name: "rw".into(),
            enabled: true,
            filters: vec![Filter {
                field: FilterField::Path,
                op: MatchOp::StartsWith,
                value: "/rewrite".into(),
                ..Default::default()
            }],
            actions: vec![
                Action::SetRequestHeader {
                    name: "X-In".into(),
                    value: "added".into(),
                },
                Action::RewritePath {
                    find: "^/rewrite/old".into(),
                    replace: "/rewrite/new".into(),
                },
                Action::SetResponseHeader {
                    name: "X-Out".into(),
                    value: "yes".into(),
                },
                Action::ResponseBodyReplace {
                    find: r"count=\d+".into(),
                    replace: "count=N".into(),
                    regex: true,
                },
            ],
        }])
        .unwrap();
    let rt = runtime();
    let proxy = h.proxy();
    rt.block_on(async {
        let up = start_plain_upstream().await;
        // untouched request
        let req = hyper::Request::get(format!("http://{up}/plain?a=1"))
            .header("host", up.to_string())
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (status, headers, body) = send_via_proxy(proxy, req).await;
        assert_eq!(status, 200);
        assert_eq!(body, "GET /plain?a=1  x-in= count=123");
        assert_eq!(headers.get("x-server").unwrap(), "echo");

        // HEAD keeps content-length but has no body
        let req = hyper::Request::head(format!("http://{up}/headreq"))
            .header("host", up.to_string())
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (status, _, body) = send_via_proxy(proxy, req).await;
        assert_eq!(status, 200);
        assert_eq!(body, "");

        // rewritten request
        let req = hyper::Request::post(format!("http://{up}/rewrite/old"))
            .header("host", up.to_string())
            .body(Full::new(Bytes::from_static(b"payload")))
            .unwrap();
        let (status, headers, body) = send_via_proxy(proxy, req).await;
        assert_eq!(status, 200);
        assert_eq!(body, "POST /rewrite/new payload x-in=added count=N");
        assert_eq!(headers.get("x-out").unwrap(), "yes");
        assert_eq!(
            headers.get("content-length").unwrap(),
            &body.len().to_string()
        );
    });
    let ex = h.wait_state("/plain", ExchangeState::Completed);
    assert_eq!(ex.response.as_ref().unwrap().status, 200);
    assert_eq!(
        &ex.response.as_ref().unwrap().body[..],
        b"GET /plain?a=1  x-in= count=123"
    );
    h.wait_state("/headreq", ExchangeState::Completed);
    let ex = h.wait_state("/rewrite/new", ExchangeState::Completed);
    assert_eq!(ex.applied_rules, vec!["rw".to_string()]);
    drop(rt);
}

#[test]
fn mock_and_block_rules() {
    let h = Harness::new(|_| {});
    h.rules
        .set(&[
            Rule {
                name: "mock".into(),
                enabled: true,
                filters: vec![Filter {
                    field: FilterField::Path,
                    op: MatchOp::Equals,
                    value: "/mock".into(),
                    ..Default::default()
                }],
                actions: vec![Action::MockResponse {
                    status: 201,
                    content_type: "application/json".into(),
                    body: "{\"ok\":true}".into(),
                }],
            },
            Rule {
                name: "block".into(),
                enabled: true,
                filters: vec![Filter {
                    field: FilterField::Path,
                    op: MatchOp::Equals,
                    value: "/block".into(),
                    ..Default::default()
                }],
                actions: vec![Action::Block],
            },
        ])
        .unwrap();
    let rt = runtime();
    let proxy = h.proxy();
    rt.block_on(async {
        // host does not exist: mock must answer without connecting
        let req = hyper::Request::get("http://does-not-exist.invalid/mock")
            .header("host", "does-not-exist.invalid")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (status, headers, body) = send_via_proxy(proxy, req).await;
        assert_eq!(status, 201);
        assert_eq!(body, "{\"ok\":true}");
        assert_eq!(headers.get("content-type").unwrap(), "application/json");

        // blocked: connection closed without response
        let mut s = TcpStream::connect(proxy).await.unwrap();
        s.write_all(b"GET http://does-not-exist.invalid/block HTTP/1.1\r\nHost: does-not-exist.invalid\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
        assert!(!String::from_utf8_lossy(&buf).contains("200 OK"));

        // unknown host: 502 from the proxy
        let req = hyper::Request::get("http://does-not-exist.invalid/other")
            .header("host", "does-not-exist.invalid")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (status, _, _) = send_via_proxy(proxy, req).await;
        assert_eq!(status, 502);
    });
    h.wait_state("/block", ExchangeState::Aborted);
    h.wait_state("/other", ExchangeState::Failed);
    drop(rt);
}

#[test]
fn intercept_edit_request_and_response() {
    let h = Harness::new(|ticket| {
        // Simulate the user editing in the UI (on another thread).
        std::thread::spawn(move || {
            let edited = match ticket.phase {
                InterceptPhase::Request => ticket.raw.replace("/original", "/edited"),
                InterceptPhase::Response => ticket
                    .raw
                    .replacen("200 OK", "202 Accepted", 1)
                    .replace("count=123", "count=999"),
            };
            ticket.resolve(Decision::Forward(Some(edited)));
        });
    });
    h.interceptor
        .set_config(InterceptConfig {
            enabled: true,
            requests: true,
            responses: true,
            filter: Filter {
                field: FilterField::Host,
                op: MatchOp::Equals,
                value: "127.0.0.1".into(),
                ..Default::default()
            },
        })
        .unwrap();
    let rt = runtime();
    let proxy = h.proxy();
    rt.block_on(async {
        let up = start_plain_upstream().await;
        let req = hyper::Request::get(format!("http://{up}/original"))
            .header("host", up.to_string())
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (status, _, body) = send_via_proxy(proxy, req).await;
        assert_eq!(status, 202);
        assert_eq!(body, "GET /edited  x-in= count=999");
    });
    let ex = h.wait_state("/edited", ExchangeState::Completed);
    assert!(ex.intercepted);
    drop(rt);
}

#[test]
fn https_connect_mitm_with_trusted_ca() {
    let h = Harness::new(|_| {});
    h.rules
        .set(&[Rule {
            name: "hdr".into(),
            enabled: true,
            filters: vec![],
            actions: vec![Action::SetResponseHeader {
                name: "X-Mitm".into(),
                value: "1".into(),
            }],
        }])
        .unwrap();
    let rt = runtime();
    let proxy = h.proxy();
    let ca_der = h.ca.ca_der().clone();
    rt.block_on(async {
        let up = start_tls_upstream().await;
        let mut s = TcpStream::connect(proxy).await.unwrap();
        let connect = format!(
            "CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n",
            port = up.port()
        );
        s.write_all(connect.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut b = [0u8; 1];
            s.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
        }
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));

        // Strict verification against the FluxRS root CA only.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_der).unwrap();
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect("localhost".try_into().unwrap(), s)
            .await
            .expect("forged certificate must validate against the FluxRS CA");
        let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(conn);
        for i in 0..2 {
            let req = hyper::Request::get(format!("/secure?i={i}"))
                .header("host", format!("localhost:{}", up.port()))
                .body(Full::new(Bytes::new()))
                .unwrap();
            let resp = tx.send_request(req).await.unwrap();
            assert_eq!(resp.status(), 200);
            assert_eq!(resp.headers().get("x-mitm").unwrap(), "1");
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                String::from_utf8_lossy(&body),
                format!("GET /secure?i={i}  x-in= count=123")
            );
        }
    });
    let ex = h.wait_state("/secure?i=1", ExchangeState::Completed);
    assert_eq!(ex.request.scheme, "https");
    assert_eq!(ex.request.host, "localhost");
    assert!(ex.request.url().starts_with("https://localhost:"));
    let tls = ex.tls.as_ref().expect("tls info recorded");
    assert_eq!(tls.sni.as_deref(), Some("localhost"));
    assert!(tls.client_version.as_deref().unwrap().starts_with("TLS 1."));
    assert!(tls.server_version.is_some());
    let cert = tls.server_cert.as_ref().expect("server certificate");
    assert_eq!(cert.san, vec!["localhost".to_string()]);
    drop(rt);
}

#[test]
fn proxy_serves_ca_certificate() {
    let h = Harness::new(|_| {});
    let rt = runtime();
    let proxy = h.proxy();
    let pem = h.ca.ca_pem().to_string();
    rt.block_on(async {
        let req = hyper::Request::get(format!("http://{proxy}/ca.crt"))
            .header("host", proxy.to_string())
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (status, _, body) = send_via_proxy(proxy, req).await;
        assert_eq!(status, 200);
        assert_eq!(body, pem);
    });
    drop(rt);
}
