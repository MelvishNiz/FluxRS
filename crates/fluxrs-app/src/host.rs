//! Native host: owns the capture engine, the root CA, settings and rules.
//!
//! The UI talks to it only through [`ClientMsg`] / [`ServerMsg`].

use crate::store;
use fluxrs_core::protocol::{CaInfo, ClientMsg, Hello, ServerMsg, Status, PROTOCOL_VERSION};
use fluxrs_core::{
    CertificateAuthority, Decision, Engine, EventSink, InterceptTicket, Interceptor, LogLevel,
    ProxyEvent, Rule, RulesHandle, TrustStatus,
};
use fluxrs_model::Settings;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub type Notify = Arc<dyn Fn() + Send + Sync>;

pub struct Host {
    data_dir: PathBuf,
    ca: Option<Arc<CertificateAuthority>>,
    ca_error: Option<String>,
    trust: Arc<Mutex<Option<TrustStatus>>>,
    trust_changed: Arc<AtomicBool>,
    settings: Settings,
    rules: Vec<Rule>,
    rules_handle: RulesHandle,
    rules_error: Option<String>,
    interceptor: Interceptor,
    intercept_error: Option<String>,
    engine: Option<Engine>,
    status: Status,
    inbox: Arc<Mutex<Vec<ProxyEvent>>>,
    tickets: HashMap<u64, InterceptTicket>,
    out: Vec<ServerMsg>,
    notify: Notify,
}

impl Host {
    pub fn new(notify: Notify) -> Host {
        let data_dir = store::data_dir();
        let settings = store::load_settings(&data_dir);
        let rules = store::load_rules(&data_dir);
        let (ca, ca_error) = match CertificateAuthority::load_or_create(&data_dir) {
            Ok(ca) => (Some(Arc::new(ca)), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let rules_handle = RulesHandle::default();
        let rules_error = rules_handle.set(&rules).err().map(|e| e.to_string());
        let interceptor = Interceptor::default();
        let intercept_error = interceptor
            .set_config(settings.intercept.clone())
            .err()
            .map(|e| e.to_string());
        let mut host = Host {
            data_dir,
            ca,
            ca_error,
            trust: Arc::default(),
            trust_changed: Arc::default(),
            settings,
            rules,
            rules_handle,
            rules_error,
            interceptor,
            intercept_error,
            engine: None,
            status: Status::default(),
            inbox: Arc::default(),
            tickets: HashMap::new(),
            out: Vec::new(),
            notify,
        };
        host.log(
            LogLevel::Info,
            format!("Data directory: {}", host.data_dir.display()),
        );
        host.refresh_trust();
        host
    }

    fn log(&mut self, level: LogLevel, text: impl Into<String>) {
        self.out.push(ServerMsg::Log {
            level,
            text: text.into(),
        });
    }

    fn toast(&mut self, text: impl Into<String>, ok: bool) {
        self.out.push(ServerMsg::Toast {
            text: text.into(),
            ok,
        });
    }

    fn ca_info(&self) -> Option<CaInfo> {
        self.ca.as_ref().map(|ca| CaInfo {
            pem: ca.ca_pem().to_string(),
            path: ca.ca_cert_path().display().to_string(),
            serial: ca.serial_hex(),
        })
    }

    /// Full state for a newly connected interface.
    pub fn hello(&self) -> ServerMsg {
        ServerMsg::Hello(Box::new(Hello {
            protocol: PROTOCOL_VERSION,
            version: env!("CARGO_PKG_VERSION").to_string(),
            os: std::env::consts::OS.to_string(),
            settings: self.settings.clone(),
            rules: self.rules.clone(),
            rules_error: self.rules_error.clone(),
            intercept_error: self.intercept_error.clone(),
            status: self.status.clone(),
            ca: self.ca_info(),
            ca_error: self.ca_error.clone(),
            trust: *self.trust.lock(),
        }))
    }

    fn refresh_trust(&mut self) {
        let Some(ca) = self.ca.clone() else { return };
        let slot = self.trust.clone();
        let flag = self.trust_changed.clone();
        let notify = self.notify.clone();
        *slot.lock() = None;
        self.out.push(ServerMsg::Trust(None));
        std::thread::spawn(move || {
            let status = ca.os_trust_status();
            *slot.lock() = Some(status);
            flag.store(true, Ordering::SeqCst);
            notify();
        });
    }

    fn set_status(&mut self) {
        self.status.running = self.engine.is_some();
        self.status.addr = self.engine.as_ref().map(|e| e.local_addr().to_string());
        self.out.push(ServerMsg::Status(self.status.clone()));
    }

    fn release_tickets(&mut self) {
        for (id, t) in self.tickets.drain() {
            t.resolve(Decision::Forward(None));
            self.out.push(ServerMsg::TicketClosed(id));
        }
    }

    pub fn handle(&mut self, msg: ClientMsg) {
        match msg {
            ClientMsg::Start => self.start(),
            ClientMsg::Stop => self.stop(),
            ClientMsg::Clear => self.out.push(ServerMsg::Cleared),
            ClientMsg::SetSettings(s) => {
                let intercept_changed = s.intercept != self.settings.intercept;
                self.settings = s;
                if intercept_changed {
                    self.intercept_error = self
                        .interceptor
                        .set_config(self.settings.intercept.clone())
                        .err()
                        .map(|e| e.to_string());
                    self.out
                        .push(ServerMsg::InterceptError(self.intercept_error.clone()));
                    if !self.settings.intercept.enabled {
                        self.release_tickets();
                    }
                }
                if let Err(e) = store::save_settings(&self.data_dir, &self.settings) {
                    self.log(LogLevel::Error, format!("save settings: {e}"));
                }
            }
            ClientMsg::SetRules(rules) => {
                self.rules_error = self.rules_handle.set(&rules).err().map(|e| e.to_string());
                self.rules = rules;
                self.out
                    .push(ServerMsg::RulesError(self.rules_error.clone()));
                if let Err(e) = store::save_rules(&self.data_dir, &self.rules) {
                    self.log(LogLevel::Error, format!("save rules: {e}"));
                }
            }
            ClientMsg::Resolve {
                ticket_id,
                decision,
            } => {
                if let Some(t) = self.tickets.remove(&ticket_id) {
                    t.resolve(decision);
                    self.out.push(ServerMsg::TicketClosed(ticket_id));
                }
            }
            ClientMsg::InstallCa => {
                if let Some(ca) = self.ca.clone() {
                    match ca.install_in_os_store() {
                        Ok(msg) => {
                            self.log(LogLevel::Info, msg.clone());
                            self.toast(msg, true);
                        }
                        Err(e) => {
                            self.log(LogLevel::Error, e.to_string());
                            self.toast(e.to_string(), false);
                        }
                    }
                    self.refresh_trust();
                }
            }
            ClientMsg::RefreshTrust => self.refresh_trust(),
            ClientMsg::RegenerateCa => {
                self.stop();
                match CertificateAuthority::regenerate(&self.data_dir) {
                    Ok(new) => {
                        self.ca = Some(Arc::new(new));
                        self.ca_error = None;
                        self.toast("New root CA generated — install it again", true);
                    }
                    Err(e) => self.toast(format!("Regenerate failed: {e}"), false),
                }
                self.out.push(ServerMsg::Ca {
                    ca: self.ca_info(),
                    error: self.ca_error.clone(),
                });
                self.refresh_trust();
            }
        }
        (self.notify)();
    }

    fn start(&mut self) {
        if self.engine.is_some() {
            return;
        }
        let Some(ca) = self.ca.clone() else {
            self.status.error = Some("Root CA unavailable".into());
            self.set_status();
            return;
        };
        let inbox = self.inbox.clone();
        let notify = self.notify.clone();
        let sink: EventSink = Arc::new(move |ev| {
            inbox.lock().push(ev);
            notify();
        });
        match Engine::start(
            self.settings.engine.clone(),
            ca,
            self.rules_handle.clone(),
            self.interceptor.clone(),
            sink,
        ) {
            Ok(engine) => {
                let addr = engine.local_addr();
                self.engine = Some(engine);
                self.status.error = None;
                self.toast(format!("Capture running on {addr}"), true);
            }
            Err(e) => {
                self.log(LogLevel::Error, format!("Start failed: {e}"));
                self.toast(format!("Start failed: {e}"), false);
                self.status.error = Some(e);
            }
        }
        self.set_status();
    }

    pub fn stop(&mut self) {
        self.release_tickets();
        if let Some(mut e) = self.engine.take() {
            e.stop();
            self.toast("Capture stopped", true);
        }
        self.drain_engine();
        self.set_status();
    }

    fn drain_engine(&mut self) {
        let events = std::mem::take(&mut *self.inbox.lock());
        for ev in events {
            match ev {
                ProxyEvent::Exchange(ex) => self.out.push(ServerMsg::Exchange(ex)),
                ProxyEvent::Intercepted(ticket) => {
                    if self.settings.intercept.enabled {
                        self.out.push(ServerMsg::Ticket(ticket.info()));
                        self.tickets.insert(ticket.ticket_id, ticket);
                    } else {
                        ticket.resolve(Decision::Forward(None));
                    }
                }
                ProxyEvent::Log(level, text) => self.log(level, text),
                ProxyEvent::Stopped(Some(e)) => {
                    self.log(LogLevel::Error, format!("Engine stopped: {e}"))
                }
                ProxyEvent::Stopped(None) => {}
            }
        }
    }

    /// Messages produced since the last call.
    pub fn poll(&mut self) -> Vec<ServerMsg> {
        self.drain_engine();
        if self.trust_changed.swap(false, Ordering::SeqCst) {
            let t = *self.trust.lock();
            self.out.push(ServerMsg::Trust(t));
        }
        std::mem::take(&mut self.out)
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.stop();
    }
}
