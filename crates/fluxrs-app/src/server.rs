//! `fluxrs --serve`: headless engine + web UI over HTTP/WebSocket.
//!
//! * `GET /`        static files of the WASM UI (`--web-root`)
//! * `GET /ws`      WebSocket, JSON [`ServerMsg`] / [`ClientMsg`], `?token=`
//! * `GET /ca.crt`  root certificate
//!
//! The host (engine owner) lives on its own thread because the engine
//! manages its own tokio runtime.

use crate::host::Host;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use bytes::Bytes;
use fluxrs_model::protocol::{ClientMsg, ServerMsg};
use fluxrs_model::{Exchange, ExchangeId};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, oneshot};
use tower_http::services::{ServeDir, ServeFile};

/// Bodies larger than this are truncated before being sent to browsers.
const WEB_BODY_CAP: usize = 1024 * 1024;
/// Exchanges replayed to a browser when it connects.
const REPLAY: usize = 2000;
const STORE: usize = 5000;

pub struct ServeOptions {
    pub listen: SocketAddr,
    pub web_root: PathBuf,
    pub token: String,
}

enum Cmd {
    Client(ClientMsg),
    Hello(oneshot::Sender<Vec<Arc<str>>>),
    Wake,
    Shutdown,
}

#[derive(Clone)]
struct AppState {
    cmd: mpsc::Sender<Cmd>,
    events: broadcast::Sender<Arc<str>>,
    token: Arc<str>,
    ca_pem: Arc<Mutex<Option<String>>>,
}

pub fn random_token() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("OS random generator");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Copy of an exchange with bodies capped for the browser.
fn trim(ex: &Arc<Exchange>) -> Arc<Exchange> {
    let big_req = ex.request.body.len() > WEB_BODY_CAP;
    let big_resp = ex
        .response
        .as_ref()
        .is_some_and(|r| r.body.len() > WEB_BODY_CAP);
    if !big_req && !big_resp {
        return ex.clone();
    }
    let mut e = (**ex).clone();
    let cut = |b: &Bytes| b.slice(..b.len().min(WEB_BODY_CAP));
    if big_req {
        e.request.body = cut(&e.request.body);
        e.request.body_truncated = true;
    }
    if let Some(r) = e.response.as_mut() {
        if big_resp {
            r.body = cut(&r.body);
            r.body_truncated = true;
        }
    }
    Arc::new(e)
}

fn encode(msg: &ServerMsg) -> Arc<str> {
    let msg = match msg {
        ServerMsg::Exchange(ex) => ServerMsg::Exchange(trim(ex)),
        other => other.clone(),
    };
    serde_json::to_string(&msg)
        .unwrap_or_else(|e| {
            format!(
                "{{\"type\":\"Log\",\"data\":{{\"level\":\"Error\",\"text\":\"encode: {e}\"}}}}"
            )
        })
        .into()
}

/// Host thread: applies commands, forwards host messages to all browsers
/// and keeps recent exchanges for late joiners.
fn host_loop(
    rx: mpsc::Receiver<Cmd>,
    tx: mpsc::Sender<Cmd>,
    events: broadcast::Sender<Arc<str>>,
    ca_pem: Arc<Mutex<Option<String>>>,
) {
    let wake = tx.clone();
    let mut host = Host::new(Arc::new(move || {
        let _ = wake.send(Cmd::Wake);
    }));
    let mut store: Vec<Arc<Exchange>> = Vec::new();
    let mut index: HashMap<ExchangeId, usize> = HashMap::new();
    loop {
        *ca_pem.lock() = host.ca_pem();
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(Cmd::Client(m)) => host.handle(m),
            Ok(Cmd::Hello(reply)) => {
                let mut out = vec![encode(&host.hello())];
                let skip = store.len().saturating_sub(REPLAY);
                out.extend(
                    store[skip..]
                        .iter()
                        .map(|e| encode(&ServerMsg::Exchange(e.clone()))),
                );
                out.extend(
                    host.ticket_infos()
                        .into_iter()
                        .map(|t| encode(&ServerMsg::Ticket(t))),
                );
                let _ = reply.send(out);
            }
            Ok(Cmd::Wake) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Ok(Cmd::Shutdown) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        for msg in host.poll() {
            match &msg {
                ServerMsg::Exchange(ex) => {
                    if let Some(&i) = index.get(&ex.id) {
                        store[i] = ex.clone();
                    } else {
                        if store.len() >= STORE {
                            store.drain(..STORE / 10);
                            index = store.iter().enumerate().map(|(i, e)| (e.id, i)).collect();
                        }
                        index.insert(ex.id, store.len());
                        store.push(ex.clone());
                    }
                }
                ServerMsg::Cleared => {
                    store.clear();
                    index.clear();
                }
                ServerMsg::Log { text, .. } => println!("{text}"),
                _ => {}
            }
            // No receivers is fine (no browser connected).
            let _ = events.send(encode(&msg));
        }
    }
    host.stop();
}

#[derive(serde::Deserialize)]
struct WsQuery {
    token: Option<String>,
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(q): Query<WsQuery>,
    State(state): State<AppState>,
) -> Response {
    let ok = q
        .token
        .as_deref()
        .is_some_and(|t| constant_time_eq(t.as_bytes(), state.token.as_bytes()));
    if !ok {
        return (StatusCode::UNAUTHORIZED, "invalid or missing token").into_response();
    }
    ws.on_upgrade(move |socket| client(socket, state))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn client(mut socket: WebSocket, state: AppState) {
    // Subscribe before the snapshot so nothing is missed (duplicates are
    // harmless: exchanges are upserted by id).
    let mut events = state.events.subscribe();
    let (tx, rx) = oneshot::channel();
    if state.cmd.send(Cmd::Hello(tx)).is_err() {
        return;
    }
    let Ok(snapshot) = rx.await else { return };
    for m in snapshot {
        if socket.send(Message::Text(m.as_ref().into())).await.is_err() {
            return;
        }
    }
    loop {
        tokio::select! {
            ev = events.recv() => match ev {
                Ok(text) => {
                    if socket.send(Message::Text(text.as_ref().into())).await.is_err() {
                        return;
                    }
                }
                // Too slow: drop the connection, the UI reconnects and
                // receives a fresh snapshot.
                Err(broadcast::error::RecvError::Lagged(_)) => return,
                Err(broadcast::error::RecvError::Closed) => return,
            },
            msg = socket.recv() => match msg {
                Some(Ok(Message::Text(t))) => {
                    match serde_json::from_str::<ClientMsg>(t.as_str()) {
                        Ok(m) => {
                            let _ = state.cmd.send(Cmd::Client(m));
                        }
                        Err(e) => eprintln!("bad client message: {e}"),
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                Some(Ok(_)) => {}
            }
        }
    }
}

async fn ca_cert(State(state): State<AppState>) -> Response {
    match state.ca_pem.lock().clone() {
        Some(pem) => (
            [
                (header::CONTENT_TYPE, "application/x-x509-ca-cert"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"fluxrs-root-ca.crt\"",
                ),
            ],
            pem,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "no root CA").into_response(),
    }
}

pub fn run(opts: ServeOptions) -> Result<(), String> {
    let (cmd_tx, cmd_rx) = mpsc::channel();
    let (events, _) = broadcast::channel::<Arc<str>>(4096);
    let ca_pem = Arc::new(Mutex::new(None));
    let host_thread = {
        let tx = cmd_tx.clone();
        let events = events.clone();
        let ca_pem = ca_pem.clone();
        std::thread::Builder::new()
            .name("fluxrs-host".into())
            .spawn(move || host_loop(cmd_rx, tx, events, ca_pem))
            .map_err(|e| e.to_string())?
    };
    let state = AppState {
        cmd: cmd_tx.clone(),
        events,
        token: opts.token.clone().into(),
        ca_pem,
    };
    let index = opts.web_root.join("index.html");
    if !index.exists() {
        eprintln!(
            "warning: {} not found; build the web UI (see README) or pass --web-root",
            index.display()
        );
    }
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/ca.crt", get(ca_cert))
        .fallback_service(ServeDir::new(&opts.web_root).fallback(ServeFile::new(index)))
        .with_state(state);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(opts.listen)
            .await
            .map_err(|e| format!("cannot listen on {}: {e}", opts.listen))?;
        let shown = if opts.listen.ip().is_unspecified() {
            SocketAddr::new([127, 0, 0, 1].into(), opts.listen.port())
        } else {
            opts.listen
        };
        println!("FluxRS web UI: http://{shown}/#token={}", opts.token);
        if opts.listen.ip().is_unspecified() {
            println!(
                "(listening on all interfaces; use this machine's LAN address from other devices)"
            );
        }
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(|e| e.to_string())
    })?;
    // Stop capture before exiting (removes proxyless redirection).
    let _ = cmd_tx.send(Cmd::Shutdown);
    let _ = host_thread.join();
    println!("FluxRS stopped.");
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_and_compare() {
        let t = random_token();
        assert_eq!(t.len(), 32);
        assert!(constant_time_eq(t.as_bytes(), t.as_bytes()));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
