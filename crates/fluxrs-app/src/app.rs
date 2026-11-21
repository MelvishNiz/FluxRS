//! Application state, event handling and the main layout.

use crate::store::{self, Settings};
use crate::theme::{self, *};
use crate::views;
use eframe::egui::{self, Margin, RichText, Stroke};
use fluxrs_core::{
    CaptureMode, CertificateAuthority, Decision, Engine, EventSink, Exchange, ExchangeId,
    InterceptTicket, Interceptor, LogLevel, ProxyEvent, Rule, RulesHandle,
};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

const MAX_EXCHANGES: usize = 20_000;
const MAX_LOGS: usize = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Traffic,
    Intercept,
    Rules,
    Settings,
    Logs,
}

pub struct LogLine {
    pub time: SystemTime,
    pub level: LogLevel,
    pub text: String,
}

pub struct PendingTicket {
    pub ticket: Option<InterceptTicket>,
    pub edited: String,
}

pub struct Toast {
    pub text: String,
    pub color: egui::Color32,
    pub until: f64,
}

pub struct FluxApp {
    pub data_dir: PathBuf,
    pub ca: Option<Arc<CertificateAuthority>>,
    pub ca_error: Option<String>,
    pub settings: Settings,
    pub rules: Vec<Rule>,
    pub rules_handle: RulesHandle,
    pub rules_error: Option<String>,
    pub interceptor: Interceptor,
    pub intercept_error: Option<String>,
    pub engine: Option<Engine>,
    pub engine_error: Option<String>,
    inbox: Arc<Mutex<Vec<ProxyEvent>>>,

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
}

impl FluxApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);
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
        let mut app = FluxApp {
            data_dir,
            ca,
            ca_error,
            settings,
            rules,
            rules_handle,
            rules_error,
            interceptor,
            intercept_error,
            engine: None,
            engine_error: None,
            inbox: Arc::default(),
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
        };
        app.log(
            LogLevel::Info,
            format!("Data directory: {}", app.data_dir.display()),
        );
        // Command line: --start (begin capture), --view <traffic|intercept|rules|settings|logs>
        let args: Vec<String> = std::env::args().collect();
        if let Some(v) = args
            .iter()
            .position(|a| a == "--view")
            .and_then(|i| args.get(i + 1))
        {
            app.view = match v.as_str() {
                "intercept" => View::Intercept,
                "rules" => View::Rules,
                "settings" => View::Settings,
                "logs" => View::Logs,
                _ => View::Traffic,
            };
        }
        if args.iter().any(|a| a == "--start") {
            app.start(&cc.egui_ctx);
        }
        app
    }

    pub fn log(&mut self, level: LogLevel, text: impl Into<String>) {
        self.logs.push_back(LogLine {
            time: SystemTime::now(),
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

    pub fn is_running(&self) -> bool {
        self.engine.is_some()
    }

    pub fn start(&mut self, ctx: &egui::Context) {
        if self.engine.is_some() {
            return;
        }
        let Some(ca) = self.ca.clone() else {
            self.engine_error = Some("Root CA unavailable".into());
            return;
        };
        let inbox = self.inbox.clone();
        let repaint = ctx.clone();
        let sink: EventSink = Arc::new(move |ev| {
            inbox.lock().push(ev);
            repaint.request_repaint();
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
                self.engine_error = None;
                self.toast(ctx, format!("Capture running on {addr}"), GREEN);
            }
            Err(e) => {
                self.log(LogLevel::Error, format!("Start failed: {e}"));
                self.toast(ctx, format!("Start failed: {e}"), RED);
                self.engine_error = Some(e);
            }
        }
    }

    pub fn stop(&mut self) {
        self.release_all_tickets();
        if let Some(mut e) = self.engine.take() {
            e.stop();
        }
        self.drain_events();
    }

    /// Forward every paused message unchanged.
    pub fn release_all_tickets(&mut self) {
        for t in self.tickets.drain(..) {
            if let Some(ticket) = t.ticket {
                ticket.resolve(Decision::Forward(None));
            }
        }
    }

    pub fn resolve_ticket(&mut self, idx: usize, decision: Decision) {
        if idx < self.tickets.len() {
            let t = self.tickets.remove(idx);
            if let Some(ticket) = t.ticket {
                ticket.resolve(decision);
            }
        }
    }

    pub fn clear_traffic(&mut self) {
        self.exchanges.clear();
        self.index.clear();
        self.traffic.selected = None;
    }

    pub fn exchange(&self, id: ExchangeId) -> Option<&Arc<Exchange>> {
        self.index.get(&id).map(|i| &self.exchanges[*i])
    }

    pub fn save_settings(&mut self) {
        if let Err(e) = store::save_settings(&self.data_dir, &self.settings) {
            self.log(LogLevel::Error, format!("save settings: {e}"));
        }
    }

    /// Recompile + persist rules after an edit.
    pub fn rules_changed(&mut self) {
        match self.rules_handle.set(&self.rules) {
            Ok(()) => self.rules_error = None,
            Err(e) => self.rules_error = Some(e.to_string()),
        }
        if let Err(e) = store::save_rules(&self.data_dir, &self.rules) {
            self.log(LogLevel::Error, format!("save rules: {e}"));
        }
    }

    pub fn intercept_changed(&mut self) {
        match self.interceptor.set_config(self.settings.intercept.clone()) {
            Ok(()) => self.intercept_error = None,
            Err(e) => self.intercept_error = Some(e.to_string()),
        }
        if !self.settings.intercept.enabled {
            self.release_all_tickets();
        }
        self.save_settings();
    }

    fn drain_events(&mut self) {
        let events = std::mem::take(&mut *self.inbox.lock());
        for ev in events {
            match ev {
                ProxyEvent::Exchange(ex) => self.upsert(ex),
                ProxyEvent::Intercepted(ticket) => {
                    if self.settings.intercept.enabled {
                        let edited = ticket.raw.clone();
                        self.tickets.push(PendingTicket {
                            ticket: Some(ticket),
                            edited,
                        });
                    } else {
                        ticket.resolve(Decision::Forward(None));
                    }
                }
                ProxyEvent::Log(level, text) => self.log(level, text),
                ProxyEvent::Stopped(err) => {
                    if let Some(e) = err {
                        self.log(LogLevel::Error, format!("Engine stopped: {e}"));
                    }
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

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.horizontal_centered(|ui| {
            logo(ui, 28.0);
            ui.add_space(2.0);
            ui.vertical(|ui| {
                ui.add_space(2.0);
                ui.label(RichText::new("FluxRS").size(16.0).strong());
                ui.label(RichText::new("HTTP Debugger").size(10.5).color(TEXT_DIM));
            });
            ui.add_space(18.0);

            // Capture mode segmented control.
            let running = self.is_running();
            ui.add_enabled_ui(!running, |ui| {
                let mode = &mut self.settings.engine.mode;
                let before = *mode;
                egui::Frame::new()
                    .fill(BG)
                    .corner_radius(egui::CornerRadius::from(9u8))
                    .inner_margin(Margin::same(3))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 2.0;
                            ui.selectable_value(mode, CaptureMode::Proxyless, "⚡ Proxyless");
                            ui.selectable_value(mode, CaptureMode::Proxy, "🌐 Proxy");
                        });
                    });
                if *mode != before {
                    self.save_settings();
                }
            });

            ui.add_space(8.0);
            if running {
                if primary_button(ui, "■  Stop capture", RED).clicked() {
                    self.stop();
                    self.toast(&ctx, "Capture stopped", TEXT_DIM);
                }
                let addr = self
                    .engine
                    .as_ref()
                    .map(|e| e.local_addr().to_string())
                    .unwrap_or_default();
                pill(ui, format!("• LIVE  {addr}"), GREEN);
            } else if primary_button(ui, "▶  Start capture", GREEN).clicked() {
                self.start(&ctx);
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button("🗑  Clear")
                    .on_hover_text("Clear captured traffic")
                    .clicked()
                {
                    self.clear_traffic();
                }
                ui.add_space(8.0);
                let mut on = self.settings.intercept.enabled;
                let r = toggle(ui, &mut on);
                if r.changed() {
                    self.settings.intercept.enabled = on;
                    self.intercept_changed();
                    if on {
                        self.view = View::Intercept;
                    }
                }
                ui.label(
                    RichText::new("Breakpoints")
                        .color(if on { ACCENT } else { TEXT_DIM })
                        .strong(),
                );
                badge(ui, self.tickets.len(), YELLOW);
            });
        });
    }

    fn nav(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        let active_rules = self.rules.iter().filter(|r| r.enabled).count();
        let items: [(View, &str, &str, usize, egui::Color32); 5] = [
            (
                View::Traffic,
                "📡",
                "Traffic",
                self.exchanges.len(),
                TEXT_FAINT,
            ),
            (
                View::Intercept,
                "⏸",
                "Intercept",
                self.tickets.len(),
                YELLOW,
            ),
            (View::Rules, "✏", "Rewrite rules", active_rules, ACCENT),
            (View::Settings, "⚙", "Settings", 0, TEXT_FAINT),
            (View::Logs, "📜", "Logs", 0, TEXT_FAINT),
        ];
        for (view, icon, label, count, color) in items {
            let selected = self.view == view;
            let fill = if selected {
                ACCENT_SOFT
            } else {
                egui::Color32::TRANSPARENT
            };
            let resp = egui::Frame::new()
                .fill(fill)
                .corner_radius(egui::CornerRadius::from(8u8))
                .inner_margin(Margin::symmetric(10, 7))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(icon).size(15.0).color(if selected {
                            ACCENT
                        } else {
                            TEXT_DIM
                        }));
                        ui.label(
                            RichText::new(label)
                                .color(if selected { TEXT } else { TEXT_DIM })
                                .strong(),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if count > 0 {
                                if color == TEXT_FAINT {
                                    ui.label(
                                        RichText::new(count.to_string())
                                            .size(11.0)
                                            .color(TEXT_FAINT),
                                    );
                                } else {
                                    badge(ui, count, color);
                                }
                            }
                        });
                    });
                })
                .response
                .interact(egui::Sense::click());
            if resp.clicked() {
                self.view = view;
            }
            if resp.hovered() && !selected {
                ui.painter().rect_stroke(
                    resp.rect,
                    egui::CornerRadius::from(8u8),
                    Stroke::new(1.0, BORDER),
                    egui::StrokeKind::Inside,
                );
            }
            ui.add_space(2.0);
        }

        {
            // Pin the info card to the bottom of the sidebar.
            let space = ui.available_height() - 96.0;
            if space > 0.0 {
                ui.add_space(space);
            }
            card().inner_margin(Margin::same(10)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                {
                    ui.label(RichText::new("Mode").size(11.0).color(TEXT_FAINT));
                    let (txt, col) = match self.settings.engine.mode {
                        CaptureMode::Proxyless => ("Proxyless (WinDivert)", CYAN),
                        CaptureMode::Proxy => ("Explicit proxy", BLUE),
                    };
                    ui.label(RichText::new(txt).color(col).strong());
                    ui.label(
                        RichText::new(if self.settings.engine.decrypt_tls {
                            "HTTPS decryption on"
                        } else {
                            "HTTPS decryption off"
                        })
                        .size(11.0)
                        .color(TEXT_DIM),
                    );
                }
            });
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_centered(|ui| {
            let (dot, text) = match (&self.engine, &self.engine_error) {
                (Some(e), _) => (GREEN, format!("Capturing on {}", e.local_addr())),
                (None, Some(err)) => (RED, format!("Error: {err}")),
                (None, None) => (TEXT_FAINT, "Idle".to_string()),
            };
            ui.label(RichText::new("•").size(18.0).color(dot));
            ui.label(RichText::new(text).size(12.0).color(TEXT_DIM));
            ui.separator();
            ui.label(
                RichText::new(format!("{} exchanges", self.exchanges.len()))
                    .size(12.0)
                    .color(TEXT_DIM),
            );
            ui.separator();
            let active = self.rules.iter().filter(|r| r.enabled).count();
            ui.label(
                RichText::new(format!("{active} active rules"))
                    .size(12.0)
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

    fn show_toasts(&mut self, ui: &mut egui::Ui) {
        let now = ui.input(|i| i.time);
        self.toasts.retain(|t| t.until > now);
        if self.toasts.is_empty() {
            return;
        }
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(250));
        egui::Area::new(egui::Id::unique("fluxrs_toasts"))
            .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-16.0, -40.0))
            .order(egui::Order::Foreground)
            .show(ui.ctx(), |ui| {
                for t in &self.toasts {
                    egui::Frame::new()
                        .fill(SURFACE_HI)
                        .stroke(Stroke::new(1.0, t.color.gamma_multiply(0.6)))
                        .corner_radius(egui::CornerRadius::from(10u8))
                        .inner_margin(Margin::symmetric(14, 10))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("•").size(18.0).color(t.color));
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
        self.drain_events();

        egui::Panel::top("top_bar")
            .frame(
                egui::Frame::new()
                    .fill(PANEL)
                    .inner_margin(Margin::symmetric(14, 10))
                    .stroke(Stroke::new(1.0, BORDER)),
            )
            .show(ui, |ui| self.top_bar(ui));

        egui::Panel::bottom("status_bar")
            .frame(
                egui::Frame::new()
                    .fill(PANEL)
                    .inner_margin(Margin::symmetric(14, 5))
                    .stroke(Stroke::new(1.0, BORDER)),
            )
            .show(ui, |ui| self.status_bar(ui));

        egui::Panel::left("nav")
            .resizable(false)
            .exact_size(210.0)
            .frame(
                egui::Frame::new()
                    .fill(PANEL)
                    .inner_margin(Margin::symmetric(10, 4))
                    .stroke(Stroke::new(1.0, BORDER)),
            )
            .show(ui, |ui| self.nav(ui));

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BG).inner_margin(Margin::same(14)))
            .show(ui, |ui| match self.view {
                View::Traffic => views::traffic::show(self, ui),
                View::Intercept => views::intercept::show(self, ui),
                View::Rules => views::rules::show(self, ui),
                View::Settings => views::settings::show(self, ui),
                View::Logs => views::logs::show(self, ui),
            });

        self.show_toasts(ui);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.stop();
    }
}
