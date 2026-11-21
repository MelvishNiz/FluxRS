//! Linux proxyless end-to-end test (iptables REDIRECT).
//!
//! Needs root and iptables, so it only runs when `FLUXRS_NETFILTER_TEST=1`
//! (CI runs it with sudo). Redirection is limited to a test address
//! (10.99.0.1 on the loopback interface) so the host network is untouched.

#![cfg(target_os = "linux")]

use bytes::Bytes;
use fluxrs_core::*;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

const TEST_IP: &str = "10.99.0.1";

async fn echo(
    req: hyper::Request<hyper::body::Incoming>,
) -> Result<hyper::Response<Full<Bytes>>, std::convert::Infallible> {
    let text = format!("upstream saw {}", req.uri().path());
    Ok(hyper::Response::new(Full::new(Bytes::from(text))))
}

async fn serve_plain(l: TcpListener) {
    loop {
        let (s, _) = l.accept().await.unwrap();
        tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(s), service_fn(echo))
                .await;
        });
    }
}

async fn serve_tls(l: TcpListener) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
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
    loop {
        let (s, _) = l.accept().await.unwrap();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Ok(tls) = acceptor.accept(s).await {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service_fn(echo))
                    .await;
            }
        });
    }
}

async fn get<S>(io: S, host: &str, path: &str) -> String
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = hyper::Request::get(path)
        .header("host", host)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = tx.send_request(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&body).into_owned()
}

struct LoAddr;
impl Drop for LoAddr {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["addr", "del", &format!("{TEST_IP}/32"), "dev", "lo"])
            .status();
    }
}

#[test]
fn proxyless_linux_http_and_https() {
    if std::env::var("FLUXRS_NETFILTER_TEST").as_deref() != Ok("1") {
        eprintln!("skipped: set FLUXRS_NETFILTER_TEST=1 and run as root");
        return;
    }
    let _ = Command::new("ip")
        .args(["addr", "add", &format!("{TEST_IP}/32"), "dev", "lo"])
        .status();
    let _cleanup = LoAddr;

    let dir = tempfile::tempdir().unwrap();
    let ca = Arc::new(CertificateAuthority::load_or_create(dir.path()).unwrap());
    let events: Arc<Mutex<Vec<Arc<Exchange>>>> = Arc::default();
    let ev = events.clone();
    let sink: EventSink = Arc::new(move |e| {
        if let ProxyEvent::Exchange(x) = e {
            ev.lock().push(x);
        }
    });
    let cfg = EngineConfig {
        mode: CaptureMode::Proxyless,
        port: 0,
        insecure_upstream: true,
        ..Default::default()
    };
    let mut engine = Engine::start_with(
        cfg,
        ca.clone(),
        RulesHandle::default(),
        Interceptor::default(),
        sink,
        Some(TEST_IP),
    )
    .expect("engine with iptables rules");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (plain, tls) = rt.block_on(async {
        let l80 = TcpListener::bind((TEST_IP, 80)).await.unwrap();
        let l443 = TcpListener::bind((TEST_IP, 443)).await.unwrap();
        tokio::spawn(serve_plain(l80));
        tokio::spawn(serve_tls(l443));

        // Plain HTTP: the client talks to 10.99.0.1:80 directly, no proxy set.
        let s = TcpStream::connect((TEST_IP, 80)).await.unwrap();
        let plain = get(s, "localhost", "/plain").await;

        // HTTPS: must validate against the FluxRS CA (forged certificate).
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.ca_der().clone()).unwrap();
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let s = TcpStream::connect((TEST_IP, 443)).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect("localhost".try_into().unwrap(), s)
            .await
            .expect("certificate forged by FluxRS must validate");
        let secure = get(tls, "localhost", "/secure").await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        (plain, secure)
    });
    engine.stop();
    drop(rt);

    assert_eq!(plain, "upstream saw /plain");
    assert_eq!(tls, "upstream saw /secure");
    let evs = events.lock();
    let find = |p: &str| {
        evs.iter()
            .rev()
            .find(|e| e.request.path == p)
            .cloned()
            .unwrap_or_else(|| panic!("{p} not captured"))
    };
    let p = find("/plain");
    assert_eq!(p.request.scheme, "http");
    assert_eq!(p.request.port, 80);
    let s = find("/secure");
    assert_eq!(s.request.scheme, "https");
    assert_eq!(s.request.port, 443);
    assert!(s.tls.is_some());

    // Rules are removed on stop.
    let out = Command::new("iptables")
        .args(["-t", "nat", "-S", "OUTPUT"])
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&out.stdout).contains("FLUXRS"));
}

#[test]
fn linux_ca_install_and_trust_check() {
    if std::env::var("FLUXRS_NETFILTER_TEST").as_deref() != Ok("1") {
        eprintln!("skipped: set FLUXRS_NETFILTER_TEST=1 and run as root");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let ca = CertificateAuthority::load_or_create(dir.path()).unwrap();
    assert_eq!(ca.os_trust_status(), TrustStatus::NotTrusted);
    let msg = ca.install_in_os_store().expect("install");
    assert!(msg.contains("system store"), "{msg}");
    assert_eq!(ca.os_trust_status(), TrustStatus::Trusted);
    // The system bundle now contains the certificate.
    let bundle = std::fs::read_to_string("/etc/ssl/certs/ca-certificates.crt").unwrap();
    let body: String = ca
        .ca_pem()
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    assert!(bundle.replace('\n', "").contains(&body));
    // cleanup
    let _ = std::fs::remove_file("/usr/local/share/ca-certificates/fluxrs-root-ca.crt");
    let _ = Command::new("update-ca-certificates")
        .arg("--fresh")
        .output();
}
