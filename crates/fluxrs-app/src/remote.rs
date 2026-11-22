//! Browser backend: talks to `fluxrs --serve` over a WebSocket.
//!
//! The page can be served by FluxRS itself (same origin, `#token=...`) or
//! from anywhere else, e.g. GitHub Pages (`#host=127.0.0.1:8800&token=...`,
//! or the connect form). The last host/token are kept in localStorage.

use crate::backend::{Backend, ConnectionState};
use ewebsock::{WsEvent, WsMessage, WsReceiver, WsSender};
use fluxrs_model::protocol::{ClientMsg, ServerMsg};

const STORE_HOST: &str = "fluxrs.host";
const STORE_TOKEN: &str = "fluxrs.token";

/// Where to connect: `host` is `name:port` or a full `ws(s)://` URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub token: String,
}

impl Target {
    /// WebSocket URL. Loopback hosts use `ws://` even from an https page
    /// (browsers allow it); other hosts follow the page scheme.
    fn ws_url(&self, page_https: bool) -> String {
        let h = self.host.trim().trim_end_matches('/');
        let token = encode(&self.token);
        if h.starts_with("ws://") || h.starts_with("wss://") {
            let base = h.trim_end_matches("/ws");
            return format!("{base}/ws?token={token}");
        }
        let h = h
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        let secure = page_https && !is_loopback(h);
        let scheme = if secure { "wss" } else { "ws" };
        format!("{scheme}://{h}/ws?token={token}")
    }

    fn http_base(&self, page_https: bool) -> String {
        let h = self.host.trim().trim_end_matches('/');
        if let Some(rest) = h.strip_prefix("ws://") {
            return format!("http://{}", rest.trim_end_matches("/ws"));
        }
        if let Some(rest) = h.strip_prefix("wss://") {
            return format!("https://{}", rest.trim_end_matches("/ws"));
        }
        if h.starts_with("http://") || h.starts_with("https://") {
            return h.to_string();
        }
        let secure = page_https && !is_loopback(h);
        format!("{}://{h}", if secure { "https" } else { "http" })
    }
}

fn is_loopback(host: &str) -> bool {
    let name = host
        .rsplit_once(':')
        .filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit()))
        .map(|(n, _)| n)
        .unwrap_or(host)
        .trim_start_matches('[')
        .trim_end_matches(']');
    name == "localhost" || name.starts_with("127.") || name == "::1"
}

/// Minimal percent-encoding for the token query parameter.
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn hash_param(hash: &str, key: &str) -> Option<String> {
    hash.trim_start_matches('#')
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        .map(|v| v.to_string())
        .filter(|v| !v.is_empty())
}

fn storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok()?
}

fn page() -> (String, bool, String) {
    let loc = web_sys::window().expect("window").location();
    let https = loc.protocol().unwrap_or_default() == "https:";
    (
        loc.host().unwrap_or_default(),
        https,
        loc.hash().unwrap_or_default(),
    )
}

/// Decide the initial target from the URL hash, then localStorage.
pub fn initial_target() -> Option<Target> {
    let (page_host, _, hash) = page();
    let token = hash_param(&hash, "token");
    if let Some(host) = hash_param(&hash, "host") {
        return Some(Target {
            host,
            token: token.unwrap_or_default(),
        });
    }
    if let Some(token) = token {
        // Served by `fluxrs --serve` itself.
        return Some(Target {
            host: page_host,
            token,
        });
    }
    let st = storage()?;
    let host = st.get_item(STORE_HOST).ok()??;
    let token = st.get_item(STORE_TOKEN).ok()?.unwrap_or_default();
    Some(Target { host, token })
}

pub struct RemoteBackend {
    target: Option<Target>,
    page_https: bool,
    ctx: eframe::egui::Context,
    conn: Option<(WsSender, WsReceiver)>,
    state: ConnectionState,
    /// Time (egui seconds) of the next reconnect attempt.
    retry_at: f64,
    queue: Vec<ClientMsg>,
}

impl RemoteBackend {
    pub fn new(target: Option<Target>, ctx: &eframe::egui::Context) -> Self {
        let (_, page_https, _) = page();
        let mut b = RemoteBackend {
            target,
            page_https,
            ctx: ctx.clone(),
            conn: None,
            state: ConnectionState::NeedsSetup,
            retry_at: 0.0,
            queue: Vec::new(),
        };
        b.connect();
        b
    }

    fn connect(&mut self) {
        let Some(target) = &self.target else {
            self.state = ConnectionState::NeedsSetup;
            return;
        };
        let url = target.ws_url(self.page_https);
        let ctx = self.ctx.clone();
        match ewebsock::connect_with_wakeup(&url, ewebsock::Options::default(), move || {
            ctx.request_repaint()
        }) {
            Ok(c) => {
                self.conn = Some(c);
                self.state = ConnectionState::Connecting;
            }
            Err(e) => self.fail(e),
        }
    }

    fn fail(&mut self, reason: String) {
        self.conn = None;
        self.state = ConnectionState::Disconnected(reason);
        self.retry_at = self.ctx.input(|i| i.time) + 2.0;
    }

    fn remember(&self) {
        if let (Some(st), Some(t)) = (storage(), &self.target) {
            let _ = st.set_item(STORE_HOST, &t.host);
            let _ = st.set_item(STORE_TOKEN, &t.token);
        }
    }
}

impl Backend for RemoteBackend {
    fn poll(&mut self) -> Vec<ServerMsg> {
        let mut out = Vec::new();
        if self.conn.is_none() {
            if self.target.is_some() && self.ctx.input(|i| i.time) >= self.retry_at {
                self.connect();
            }
            return out;
        }
        let mut failure = None;
        if let Some((_, rx)) = &self.conn {
            while let Some(ev) = rx.try_recv() {
                match ev {
                    WsEvent::Opened => self.state = ConnectionState::Connected,
                    WsEvent::Message(WsMessage::Text(t)) => {
                        match serde_json::from_str::<ServerMsg>(&t) {
                            Ok(m) => out.push(m),
                            Err(e) => web_log(&format!("bad server message: {e}")),
                        }
                    }
                    WsEvent::Message(_) => {}
                    WsEvent::Error(e) => failure = Some(e),
                    WsEvent::Closed => failure = Some("connection closed".into()),
                }
            }
        }
        if !out.is_empty() {
            // The host accepted us: remember it for the next visit.
            self.remember();
        }
        if let Some(e) = failure {
            self.fail(e);
        } else if self.state == ConnectionState::Connected && !self.queue.is_empty() {
            for m in std::mem::take(&mut self.queue) {
                self.send(m);
            }
        }
        out
    }

    fn send(&mut self, msg: ClientMsg) {
        match (&mut self.conn, &self.state) {
            (Some((tx, _)), ConnectionState::Connected) => {
                if let Ok(text) = serde_json::to_string(&msg) {
                    tx.send(WsMessage::Text(text));
                }
            }
            // Sent once the connection is (re)established.
            _ => self.queue.push(msg),
        }
    }

    fn is_local(&self) -> bool {
        false
    }

    fn connection(&self) -> Option<ConnectionState> {
        Some(self.state.clone())
    }

    fn target(&self) -> Option<(String, String)> {
        self.target
            .as_ref()
            .map(|t| (t.host.clone(), t.token.clone()))
    }

    fn configure(&mut self, host: &str, token: &str) {
        self.conn = None;
        self.queue.clear();
        self.target = Some(Target {
            host: host.trim().to_string(),
            token: token.trim().to_string(),
        });
        self.retry_at = 0.0;
        self.connect();
    }

    fn http_base(&self) -> Option<String> {
        self.target.as_ref().map(|t| t.http_base(self.page_https))
    }
}

fn web_log(msg: &str) {
    web_sys::console::warn_1(&msg.into());
}
