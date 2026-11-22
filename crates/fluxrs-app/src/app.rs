//! Application state, event handling and the main layout.
//!
//! The UI never touches the engine directly: it mirrors host state from
//! [`ServerMsg`]s and sends [`ClientMsg`]s through a [`Backend`], so the
//! same code runs on the desktop and in the browser.

use crate::backend::{Backend, ConnectionState};
use crate::theme::{self, icon, *};
use crate::views;
use eframe::egui::{self, Margin, RichText, Stroke};
use fluxrs_model::protocol::{CaInfo, ClientMsg, ServerMsg, Status};
use fluxrs_model::{
    CaptureMode, Decision, Exchange, ExchangeId, LogLevel, Rule, Settings, TicketInfo, TrustStatus,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

const MAX_EXCHANGES: usize = 20_000;
const MAX_LOGS: usize = 2_000;

/// Sidebar entry: view, icon, label, counter, counter color.
type NavItem = (View, &'static str, &'static str, usize, egui::Color32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Traffic,
    Intercept,
    Rules,
    Settings,
    Logs,
}

impl View {
    fn title(self) -> (&'static str, &'static str) {
        match self {
            View::Traffic => ("Traffic", "Every HTTP and HTTPS exchange, live"),
            View::Intercept => ("Intercept", "Pause, edit and replay messages in flight"),
            View::Rules => (
                "Rewrite rules",
                "Change requests and responses automatically",
            ),
            View::Settings => ("Settings", "Capture, HTTPS certificate and about"),
            View::Logs => ("Logs", "Engine diagnostics"),
        }
    }
}

pub struct LogLine {
    /// Time since the Unix epoch.
    pub time: Duration,
    pub level: LogLevel,
    pub text: String,
}

pub struct PendingTicket {
    pub info: TicketInfo,
    pub edited: String,
}

pub struct Toast {
    pub text: String,
    pub color: egui::Color32,
    pub until: f64,
}

pub struct FluxApp {
    backend: Box<dyn Backend>,
    /// Hello received from the host.
    pub ready: bool,
    pub host_os: String,
    pub ca: Option<CaInfo>,
    pub ca_error: Option<String>,
    trust: Option<TrustStatus>,
    pub settings: Settings,
    pub rules: Vec<Rule>,
    pub rules_error: Option<String>,
    pub intercept_error: Option<String>,
    pub status: Status,

    pub exchanges: Vec<Arc<Exchange>>,
    index: HashMap<ExchangeId, usize>,
    pub tickets: Vec<PendingTicket>,
    pub logs: VecDeque<LogLine>,
    pub view: View,
    pub toasts: Vec<Toast>,

    pub traffic: views::traffic::TrafficState,
    pub rules_ui: views::rules::RulesState,
    pub intercept_ui: views::intercept::InterceptState,
    pub settings_ui: views::settings::SettingsState,
    /// Remote connect form (host, token).
    connect_form: Option<(String, String)>,
}

fn now() -> Duration {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
}

impl FluxApp {
    pub fn new(cc: &eframe::CreationContext<'_>, backend: Box<dyn Backend>) -> Self {
        theme::apply(&cc.egui_ctx);
        let mut app = FluxApp {
            backend,
            ready: false,
            host_os: String::new(),
            ca: None,
            ca_error: None,
            trust: None,
            settings: Settings::default(),
            rules: Vec::new(),
            rules_error: None,
            intercept_error: None,
            status: Status::default(),
            exchanges: Vec::new(),
            index: HashMap::new(),
            tickets: Vec::new(),
            logs: VecDeque::new(),
            view: View::Traffic,
            toasts: Vec::new(),
            traffic: Default::default(),
            rules_ui: Default::default(),
            intercept_ui: Default::default(),
            settings_ui: Default::default(),
            connect_form: None,
        };
        app.process_messages(&cc.egui_ctx);
        app
    }

    /// Apply `--view <name>` and `--start` (desktop command line).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn apply_args(&mut self, args: &[String], ctx: &egui::Context) {
        if let Some(v) = args
            .iter()
            .position(|a| a == "--view")
            .and_then(|i| args.get(i + 1))
        {
            self.view = match v.as_str() {
                "intercept" => View::Intercept,
                "rules" => View::Rules,
                "settings" => View::Settings,
                "logs" => View::Logs,
                _ => View::Traffic,
            };
        }
        if args.iter().any(|a| a == "--start") {
            self.start(ctx);
            self.process_messages(ctx);
        }
    }

    pub fn is_local(&self) -> bool {
        self.backend.is_local()
    }

    pub fn log(&mut self, level: LogLevel, text: impl Into<String>) {
        self.logs.push_back(LogLine {
            time: now(),
            level,
            text: text.into(),
        });
        while self.logs.len() > MAX_LOGS {
            self.logs.pop_front();
        }
    }

    pub fn toast(&mut self, ctx: &egui::Context, text: impl Into<String>, color: egui::Color32) {
        let now = ctx.input(|i| i.time);
        self.toasts.push(Toast {
            text: text.into(),
            color,
            until: now + 3.5,
        });
    }

    /// Remote: HTTP base URL of the connected host.
    pub fn http_base(&self) -> Option<String> {
        self.backend.http_base()
    }

    fn send(&mut self, msg: ClientMsg) {
        self.backend.send(msg);
    }

    pub fn refresh_ca_trust(&mut self, _ctx: &egui::Context) {
        self.send(ClientMsg::RefreshTrust);
    }

    pub fn ca_trust(&self) -> Option<TrustStatus> {
        self.trust
    }

    pub fn install_ca(&mut self, _ctx: &egui::Context) {
        self.send(ClientMsg::InstallCa);
    }

    pub fn regenerate_ca(&mut self) {
        self.send(ClientMsg::RegenerateCa);
    }

    pub fn is_running(&self) -> bool {
        self.status.running
    }

    /// Address the engine listens on, when running.
    pub fn local_addr(&self) -> Option<&str> {
        self.status.addr.as_deref()
    }

    pub fn start(&mut self, _ctx: &egui::Context) {
        self.send(ClientMsg::Start);
    }

    pub fn stop(&mut self) {
        self.tickets.clear();
        self.send(ClientMsg::Stop);
    }

    /// Forward every paused message unchanged.
    pub fn release_all_tickets(&mut self) {
        let ids: Vec<u64> = self.tickets.drain(..).map(|t| t.info.ticket_id).collect();
        for ticket_id in ids {
            self.send(ClientMsg::Resolve {
                ticket_id,
                decision: Decision::Forward(None),
            });
        }
    }

    pub fn resolve_ticket(&mut self, idx: usize, decision: Decision) {
        if idx < self.tickets.len() {
            let t = self.tickets.remove(idx);
            self.send(ClientMsg::Resolve {
                ticket_id: t.info.ticket_id,
                decision,
            });
        }
    }

    pub fn clear_traffic(&mut self) {
        self.exchanges.clear();
        self.index.clear();
        self.traffic.selected = None;
        self.send(ClientMsg::Clear);
    }

    pub fn exchange(&self, id: ExchangeId) -> Option<&Arc<Exchange>> {
        self.index.get(&id).map(|i| &self.exchanges[*i])
    }

    pub fn save_settings(&mut self) {
        self.send(ClientMsg::SetSettings(self.settings.clone()));
    }

    /// Recompile + persist rules after an edit (the host validates them).
    pub fn rules_changed(&mut self) {
        self.send(ClientMsg::SetRules(self.rules.clone()));
    }

    pub fn intercept_changed(&mut self) {
        if !self.settings.intercept.enabled {
            self.tickets.clear();
        }
        self.save_settings();
    }

    fn process_messages(&mut self, ctx: &egui::Context) {
        for msg in self.backend.poll() {
            match msg {
                ServerMsg::Hello(h) => {
                    let h = *h;
                    self.ready = true;
                    self.host_os = h.os;
                    self.settings = h.settings;
                    self.rules = h.rules;
                    self.rules_error = h.rules_error;
                    self.intercept_error = h.intercept_error;
                    self.status = h.status;
                    self.ca = h.ca;
                    self.ca_error = h.ca_error;
                    self.trust = h.trust;
                    self.settings_ui = Default::default();
                    // A reconnect replays the current state.
                    self.exchanges.clear();
                    self.index.clear();
                    self.tickets.clear();
                }
                ServerMsg::Status(s) => self.status = s,
                ServerMsg::Exchange(ex) => self.upsert(ex),
                ServerMsg::Cleared => {
                    self.exchanges.clear();
                    self.index.clear();
                    self.traffic.selected = None;
                }
                ServerMsg::Ticket(info) => {
                    if !self
                        .tickets
                        .iter()
                        .any(|t| t.info.ticket_id == info.ticket_id)
                    {
                        let edited = info.raw.clone();
                        self.tickets.push(PendingTicket { info, edited });
                    }
                }
                ServerMsg::TicketClosed(id) => self.tickets.retain(|t| t.info.ticket_id != id),
                ServerMsg::Log { level, text } => self.log(level, text),
                ServerMsg::RulesError(e) => self.rules_error = e,
                ServerMsg::InterceptError(e) => self.intercept_error = e,
                ServerMsg::Trust(t) => self.trust = t,
                ServerMsg::Ca { ca, error } => {
                    self.ca = ca;
                    self.ca_error = error;
                }
                ServerMsg::Toast { text, ok } => {
                    let color = if ok { GREEN } else { RED };
                    self.toast(ctx, text, color);
                }
            }
        }
    }

    fn upsert(&mut self, ex: Arc<Exchange>) {
        if let Some(&i) = self.index.get(&ex.id) {
            self.exchanges[i] = ex;
            return;
        }
        if self.exchanges.len() >= MAX_EXCHANGES {
            let drop_n = MAX_EXCHANGES / 10;
            self.exchanges.drain(..drop_n);
            self.index = self
                .exchanges
                .iter()
                .enumerate()
                .map(|(i, e)| (e.id, i))
                .collect();
        }
        self.index.insert(ex.id, self.exchanges.len());
        self.exchanges.push(ex);
    }

    // ------------------------------------------------------------ chrome

    fn header(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.horizontal(|ui| {
            let (title, subtitle) = self.view.title();
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                ui.label(strong(title, 17.0, TEXT));
                ui.label(RichText::new(subtitle).size(12.0).color(TEXT_FAINT));
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Record button
                if self.is_running() {
                    if primary_button(ui, icon::SQUARE, "Stop", RED).clicked() {
                        self.stop();
                        self.toast(&ctx, "Capture stopped", TEXT_DIM);
                    }
                } else if primary_button(ui, icon::PLAY, "Start capture", GREEN).clicked() {
                    self.start(&ctx);
                }
                ui.add_space(4.0);

                // Capture mode
                ui.add_enabled_ui(!self.is_running(), |ui| {
                    let mut mode = self.settings.engine.mode;
                    if segmented(
                        ui,
                        &mut mode,
                        &[
                            (CaptureMode::Proxy, Some(icon::GLOBE), "Proxy"),
                            (CaptureMode::Proxyless, Some(icon::ZAP), "Proxyless"),
                        ],
                    ) {
                        self.settings.engine.mode = mode;
                        self.save_settings();
                    }
                })
                .response
                .on_disabled_hover_text("Stop capture to change the mode");
                ui.add_space(8.0);

                // Breakpoints
                let mut on = self.settings.intercept.enabled;
                if toggle(ui, &mut on).changed() {
                    self.settings.intercept.enabled = on;
                    self.intercept_changed();
                    if on {
                        self.view = View::Intercept;
                    }
                }
                ui.label(RichText::new("Breakpoints").color(if on { ACCENT_HI } else { TEXT_DIM }));
                badge(ui, self.tickets.len(), YELLOW);
            });
        });
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.add_space(14.0);
        ui.horizontal(|ui| {
            ui.add_space(4.0);
            logo(ui, 30.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                ui.label(strong("FluxRS", 15.0, TEXT));
                ui.label(RichText::new("HTTP Debugger").size(11.0).color(TEXT_FAINT));
            });
        });
        ui.add_space(18.0);

        let active_rules = self.rules.iter().filter(|r| r.enabled).count();
        let sections: [(&str, Vec<NavItem>); 2] = [
            (
                "Workspace",
                vec![
                    (
                        View::Traffic,
                        icon::ACTIVITY,
                        "Traffic",
                        self.exchanges.len(),
                        TEXT_FAINT,
                    ),
                    (
                        View::Intercept,
                        icon::PAUSE,
                        "Intercept",
                        self.tickets.len(),
                        YELLOW,
                    ),
                    (
                        View::Rules,
                        icon::WAND,
                        "Rewrite rules",
                        active_rules,
                        ACCENT,
                    ),
                ],
            ),
            (
                "System",
                vec![
                    (View::Settings, icon::SETTINGS, "Settings", 0, TEXT_FAINT),
                    (View::Logs, icon::SCROLL, "Logs", 0, TEXT_FAINT),
                ],
            ),
        ];
        for (title, items) in sections {
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                caption(ui, title);
            });
            ui.add_space(2.0);
            for (view, ic, label, count, color) in items {
                self.nav_item(ui, view, ic, label, count, color);
            }
            ui.add_space(12.0);
        }

        // Bottom: HTTPS + capture status.
        let space = ui.available_height() - 156.0;
        if space > 0.0 {
            ui.add_space(space);
        }
        card().inner_margin(Margin::same(12)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            let trust = self.ca_trust();
            let (ic, color, title) = match trust {
                Some(TrustStatus::Trusted) => (icon::SHIELD_CHECK, GREEN, "HTTPS ready"),
                Some(TrustStatus::NotTrusted) => {
                    (icon::SHIELD_ALERT, YELLOW, "Certificate not trusted")
                }
                Some(TrustStatus::Unknown) => (icon::KEY, TEXT_DIM, "HTTPS certificate"),
                None => (icon::KEY, TEXT_FAINT, "Checking certificate…"),
            };
            ui.horizontal(|ui| {
                ui.label(ico(ic, 15.0, color));
                ui.label(strong(title, 12.5, TEXT));
            });
            if trust == Some(TrustStatus::NotTrusted) {
                ui.add_space(2.0);
                if ui
                    .add(
                        egui::Button::new(strong(
                            if self.is_local() {
                                "Install certificate"
                            } else {
                                "Install on host"
                            },
                            12.0,
                            YELLOW,
                        ))
                        .fill(YELLOW.gamma_multiply(0.12))
                        .stroke(Stroke::new(1.0, YELLOW.gamma_multiply(0.4)))
                        .min_size(egui::vec2(ui.available_width(), 26.0)),
                    )
                    .clicked()
                {
                    self.install_ca(&ctx);
                }
            } else {
                ui.label(
                    RichText::new(if self.settings.engine.decrypt_tls {
                        "Decryption on"
                    } else {
                        "Decryption off"
                    })
                    .size(11.5)
                    .color(TEXT_FAINT),
                );
            }
            ui.add_space(6.0);
            ui.separator();
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                if self.is_running() {
                    live_dot(ui, GREEN);
                } else {
                    dot(ui, TEXT_FAINT, 3.5);
                }
                let mode = match self.settings.engine.mode {
                    CaptureMode::Proxyless => "Proxyless",
                    CaptureMode::Proxy => "Explicit proxy",
                };
                ui.label(
                    RichText::new(if self.is_running() {
                        format!("{mode} · live")
                    } else {
                        format!("{mode} · idle")
                    })
                    .size(12.0)
                    .color(TEXT_DIM),
                );
            });
        });
        ui.add_space(12.0);
    }

    fn nav_item(
        &mut self,
        ui: &mut egui::Ui,
        view: View,
        ic: &str,
        label: &str,
        count: usize,
        color: egui::Color32,
    ) {
        let selected = self.view == view;
        let (rect, resp) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 34.0), egui::Sense::click());
        let painter = ui.painter();
        if selected {
            painter.rect_filled(rect, egui::CornerRadius::from(8u8), RAISED);
            painter.rect_filled(
                egui::Rect::from_min_size(
                    egui::pos2(rect.left(), rect.top() + 9.0),
                    egui::vec2(3.0, 16.0),
                ),
                egui::CornerRadius::from(2u8),
                ACCENT,
            );
        } else if resp.hovered() {
            painter.rect_filled(rect, egui::CornerRadius::from(8u8), SURFACE);
        }
        let fg = if selected { TEXT } else { TEXT_DIM };
        let icon_galley = painter.layout_no_wrap(
            ic.to_string(),
            egui::FontId::new(15.0, icon_family()),
            if selected { ACCENT_HI } else { TEXT_FAINT },
        );
        let y = rect.center().y;
        painter.galley(
            egui::pos2(rect.left() + 14.0, y - icon_galley.size().y / 2.0),
            icon_galley,
            fg,
        );
        let font = if selected {
            sb(13.0)
        } else {
            egui::FontId::proportional(13.0)
        };
        let text = painter.layout_no_wrap(label.to_string(), font, fg);
        painter.galley(
            egui::pos2(rect.left() + 40.0, y - text.size().y / 2.0),
            text,
            fg,
        );
        if count > 0 {
            if color == TEXT_FAINT {
                let g = painter.layout_no_wrap(
                    count.to_string(),
                    egui::FontId::proportional(11.5),
                    TEXT_FAINT,
                );
                painter.galley(
                    egui::pos2(rect.right() - 12.0 - g.size().x, y - g.size().y / 2.0),
                    g,
                    TEXT_FAINT,
                );
            } else {
                let g = painter.layout_no_wrap(count.to_string(), sb(10.5), egui::Color32::BLACK);
                let w = (g.size().x + 10.0).max(18.0);
                let r = egui::Rect::from_center_size(
                    egui::pos2(rect.right() - 12.0 - w / 2.0, y),
                    egui::vec2(w, 17.0),
                );
                painter.rect_filled(r, egui::CornerRadius::from(9u8), color);
                painter.galley(r.center() - g.size() / 2.0, g, egui::Color32::BLACK);
            }
        }
        if resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        if resp.clicked() {
            self.view = view;
        }
        ui.add_space(2.0);
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_centered(|ui| {
            let (color, text) = match (&self.status.addr, &self.status.error) {
                (Some(addr), _) if self.status.running => (GREEN, format!("Capturing on {addr}")),
                (_, Some(err)) => (RED, format!("Error: {err}")),
                _ => (TEXT_FAINT, "Idle".to_string()),
            };
            dot(ui, color, 3.0);
            ui.label(RichText::new(text).size(11.5).color(TEXT_DIM));
            ui.label(RichText::new("·").color(TEXT_FAINT));
            ui.label(
                RichText::new(format!("{} exchanges", self.exchanges.len()))
                    .size(11.5)
                    .color(TEXT_DIM),
            );
            ui.label(RichText::new("·").color(TEXT_FAINT));
            let active = self.rules.iter().filter(|r| r.enabled).count();
            ui.label(
                RichText::new(format!("{active} active rules"))
                    .size(11.5)
                    .color(if self.rules_error.is_some() {
                        RED
                    } else {
                        TEXT_DIM
                    }),
            );
            if let Some(last) = self.logs.back() {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let c = match last.level {
                        LogLevel::Info => TEXT_FAINT,
                        LogLevel::Warn => YELLOW,
                        LogLevel::Error => RED,
                    };
                    ui.add(
                        egui::Label::new(RichText::new(&last.text).size(11.5).color(c)).truncate(),
                    );
                });
            }
        });
    }

    /// Remote UI: connection state and the connect form. Returns false
    /// while there is no host state to show.
    fn connection_banner(&mut self, ui: &mut egui::Ui, state: &ConnectionState) -> bool {
        if self.ready && *state == ConnectionState::Connected {
            self.connect_form = None;
            return true;
        }
        let show_form = self.connect_form.is_some()
            || matches!(state, ConnectionState::NeedsSetup)
            || (!self.ready && matches!(state, ConnectionState::Disconnected(_)));
        if self.ready && !show_form {
            // Keep the last known state visible behind a banner.
            let text = match state {
                ConnectionState::Disconnected(e) => e.clone(),
                _ => String::new(),
            };
            let mut change = false;
            egui::Panel::top("conn_banner")
                .frame(
                    egui::Frame::new()
                        .fill(RED.gamma_multiply(0.15))
                        .inner_margin(Margin::symmetric(16, 6)),
                )
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(ico(icon::CIRCLE_ALERT, 14.0, RED));
                        ui.label(strong("Connection lost — retrying", 13.0, TEXT));
                        ui.label(RichText::new(text).size(12.0).color(TEXT_DIM));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            change = ghost_button(ui, icon::SERVER, "Change host").clicked();
                        });
                    });
                });
            if change {
                self.open_connect_form();
            }
            return true;
        }
        if show_form {
            self.connect_screen(ui, state);
            return false;
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BG))
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(ui.available_height() * 0.35);
                    logo(ui, 56.0);
                    ui.add_space(14.0);
                    ui.label(strong("Connecting to FluxRS…", 18.0, TEXT));
                    if let Some((host, _)) = self.backend.target() {
                        ui.label(RichText::new(host).font(mono(12.5)).color(TEXT_DIM));
                    }
                    ui.add_space(10.0);
                    ui.spinner();
                });
            });
        false
    }

    fn open_connect_form(&mut self) {
        let (host, token) = self.backend.target().unwrap_or_default();
        let host = if host.is_empty() {
            "127.0.0.1:8800".to_string()
        } else {
            host
        };
        self.connect_form = Some((host, token));
    }

    fn connect_screen(&mut self, ui: &mut egui::Ui, state: &ConnectionState) {
        if self.connect_form.is_none() {
            self.open_connect_form();
        }
        let mut submit = false;
        let mut cancel = false;
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BG))
            .show(ui, |ui| {
                let avail = ui.available_rect_before_wrap();
                let w = 460.0f32.min(avail.width() - 32.0);
                let top = avail.top() + (avail.height() * 0.12).max(16.0);
                let rect = egui::Rect::from_min_max(
                    egui::pos2(avail.center().x - w / 2.0, top),
                    egui::pos2(avail.center().x + w / 2.0, avail.bottom()),
                );
                ui.scope_builder(
                    egui::UiBuilder::new()
                        .max_rect(rect)
                        .layout(egui::Layout::top_down(egui::Align::Center)),
                    |ui| {
                        logo(ui, 56.0);
                        ui.add_space(12.0);
                        ui.label(strong("Connect to FluxRS", 22.0, TEXT));
                        ui.label(
                            RichText::new("The capture engine runs on your computer. Start it with:")
                                .color(TEXT_DIM),
                        );
                        ui.add_space(6.0);
                        inset().show(ui, |ui| {
                            ui.label(RichText::new("fluxrs --serve").font(mono(13.0)).color(CYAN));
                        });
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new(
                                "then open the link it prints, or enter its address and token below.",
                            )
                            .size(12.0)
                            .color(TEXT_FAINT),
                        );
                        ui.add_space(16.0);
                        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                            card().show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                let form = self.connect_form.as_mut().expect("form");
                                caption(ui, "Host");
                                let host = ui.add(
                                    egui::TextEdit::singleline(&mut form.0)
                                        .hint_text("127.0.0.1:8800")
                                        .font(mono(13.0))
                                        .desired_width(f32::INFINITY),
                                );
                                ui.add_space(8.0);
                                caption(ui, "Token");
                                let token = ui.add(
                                    egui::TextEdit::singleline(&mut form.1)
                                        .hint_text("printed by fluxrs --serve")
                                        .font(mono(13.0))
                                        .password(true)
                                        .desired_width(f32::INFINITY),
                                );
                                let enter = (host.lost_focus() || token.lost_focus())
                                    && ui.input(|i| i.key_pressed(egui::Key::Enter));
                                ui.add_space(12.0);
                                if let ConnectionState::Disconnected(e) = state {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.label(ico(icon::CIRCLE_ALERT, 13.0, RED));
                                        ui.label(
                                            RichText::new(format!("Could not connect: {e}"))
                                                .size(12.0)
                                                .color(RED),
                                        );
                                    });
                                    ui.add_space(8.0);
                                }
                                ui.horizontal(|ui| {
                                    submit = primary_button(ui, icon::SEND, "Connect", ACCENT)
                                        .clicked()
                                        || enter;
                                    if self.ready
                                        && ghost_button(ui, icon::X, "Cancel").clicked()
                                    {
                                        cancel = true;
                                    }
                                });
                                ui.add_space(10.0);
                                ui.label(
                                    RichText::new(
                                        "From an https page such as GitHub Pages, browsers only allow plain ws:// connections to localhost / 127.0.0.1. For another machine, open the link served by that machine.",
                                    )
                                    .size(11.5)
                                    .color(TEXT_FAINT),
                                );
                            });
                        });
                    },
                );
            });
        if submit {
            if let Some((host, token)) = self.connect_form.take() {
                self.ready = false;
                self.backend.configure(&host, &token);
            }
        } else if cancel {
            self.connect_form = None;
        }
    }

    fn show_toasts(&mut self, ui: &mut egui::Ui) {
        let now = ui.input(|i| i.time);
        self.toasts.retain(|t| t.until > now);
        if self.toasts.is_empty() {
            return;
        }
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(250));
        egui::Area::new(egui::Id::unique("fluxrs_toasts"))
            .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-18.0, -42.0))
            .order(egui::Order::Foreground)
            .show(ui.ctx(), |ui| {
                for t in &self.toasts {
                    egui::Frame::new()
                        .fill(RAISED)
                        .stroke(Stroke::new(1.0, BORDER_STRONG))
                        .corner_radius(egui::CornerRadius::from(10u8))
                        .inner_margin(Margin::symmetric(14, 10))
                        .shadow(egui::Shadow {
                            offset: [0, 6],
                            blur: 18,
                            spread: 0,
                            color: egui::Color32::from_black_alpha(120),
                        })
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                dot(ui, t.color, 4.0);
                                ui.label(&t.text);
                            });
                        });
                    ui.add_space(6.0);
                }
            });
    }
}

impl eframe::App for FluxApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.process_messages(&ctx);
        if let Some(state) = self.backend.connection() {
            if state != ConnectionState::Connected {
                // Keep polling while (re)connecting.
                ctx.request_repaint_after(Duration::from_millis(500));
            }
            if !self.connection_banner(ui, &state) {
                return;
            }
        }

        egui::Panel::left("sidebar")
            .resizable(false)
            .exact_size(224.0)
            .frame(
                egui::Frame::new()
                    .fill(SIDEBAR)
                    .inner_margin(Margin::symmetric(10, 0))
                    .stroke(Stroke::new(1.0, BORDER)),
            )
            .show(ui, |ui| self.sidebar(ui));

        egui::Panel::top("header")
            .frame(
                egui::Frame::new()
                    .fill(BG)
                    .inner_margin(Margin::symmetric(20, 12))
                    .stroke(Stroke::new(1.0, BORDER)),
            )
            .show(ui, |ui| self.header(ui));

        egui::Panel::bottom("status_bar")
            .exact_size(28.0)
            .frame(
                egui::Frame::new()
                    .fill(SIDEBAR)
                    .inner_margin(Margin::symmetric(16, 0))
                    .stroke(Stroke::new(1.0, BORDER)),
            )
            .show(ui, |ui| self.status_bar(ui));

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(BG)
                    .inner_margin(Margin::symmetric(20, 16)),
            )
            .show(ui, |ui| match self.view {
                View::Traffic => views::traffic::show(self, ui),
                View::Intercept => views::intercept::show(self, ui),
                View::Rules => views::rules::show(self, ui),
                View::Settings => views::settings::show(self, ui),
                View::Logs => views::logs::show(self, ui),
            });

        self.show_toasts(ui);
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Desktop: stop capture (and remove proxyless redirection) on exit.
        if self.is_local() {
            self.stop();
        }
    }
}
