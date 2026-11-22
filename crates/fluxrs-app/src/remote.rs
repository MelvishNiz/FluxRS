//! Browser backend: talks to `fluxrs --serve` over a WebSocket.

use crate::backend::{Backend, ConnectionState};
use ewebsock::{WsEvent, WsMessage, WsReceiver, WsSender};
use fluxrs_model::protocol::{ClientMsg, ServerMsg};

pub struct RemoteBackend {
    url: String,
    ctx: eframe::egui::Context,
    conn: Option<(WsSender, WsReceiver)>,
    state: ConnectionState,
    /// Time (egui seconds) of the next reconnect attempt.
    retry_at: f64,
    queue: Vec<ClientMsg>,
}

impl RemoteBackend {
    pub fn new(url: String, ctx: &eframe::egui::Context) -> Self {
        let mut b = RemoteBackend {
            url,
            ctx: ctx.clone(),
            conn: None,
            state: ConnectionState::Connecting,
            retry_at: 0.0,
            queue: Vec::new(),
        };
        b.connect();
        b
    }

    fn connect(&mut self) {
        let ctx = self.ctx.clone();
        match ewebsock::connect_with_wakeup(&self.url, ewebsock::Options::default(), move || {
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
}

impl Backend for RemoteBackend {
    fn poll(&mut self) -> Vec<ServerMsg> {
        let mut out = Vec::new();
        if self.conn.is_none() {
            if self.ctx.input(|i| i.time) >= self.retry_at {
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
}

fn web_log(msg: &str) {
    web_sys::console::warn_1(&msg.into());
}

/// `ws(s)://<page host>/ws?token=<#token=...>` for the page we were served from.
pub fn default_url() -> String {
    let loc = web_sys::window().expect("window").location();
    let proto = if loc.protocol().unwrap_or_default() == "https:" {
        "wss"
    } else {
        "ws"
    };
    let host = loc.host().unwrap_or_default();
    let hash = loc.hash().unwrap_or_default();
    let token = hash
        .trim_start_matches('#')
        .split('&')
        .find_map(|kv| kv.strip_prefix("token="))
        .unwrap_or_default()
        .to_string();
    format!("{proto}://{host}/ws?token={token}")
}
