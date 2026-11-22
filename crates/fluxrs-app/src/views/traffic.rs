//! Traffic list + exchange inspector.

use crate::app::{FluxApp, View};
use crate::theme::{icon, *};
use bytes::Bytes;
use eframe::egui::{self, Margin, RichText, Stroke};
use egui_extras::{Column, TableBuilder};
use fluxrs_model::{
    codec::decode_body, Action, CaptureMode, Exchange, ExchangeId, ExchangeState, Filter,
    FilterField, HeaderList, MatchOp, Rule, TrustStatus,
};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DetailTab {
    #[default]
    Request,
    Response,
    Https,
    Timing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StatusFilter {
    #[default]
    All,
    S2xx,
    S3xx,
    S4xx,
    S5xx,
    Errors,
}

#[derive(Default)]
pub struct TrafficState {
    pub selected: Option<ExchangeId>,
    pub search: String,
    pub status: StatusFilter,
    pub hide_tunnels: bool,
    pub follow: bool,
    pub tab: DetailTab,
    pub raw_body: bool,
    cache: Option<BodyCache>,
}

struct BodyCache {
    exchange: Arc<Exchange>,
    raw: bool,
    request: String,
    response: String,
}

fn matches(ex: &Exchange, st: &TrafficState, needle: &str) -> bool {
    if st.hide_tunnels && ex.request.method == "TUNNEL" {
        return false;
    }
    let status = ex.response.as_ref().map(|r| r.status);
    let ok = match st.status {
        StatusFilter::All => true,
        StatusFilter::S2xx => matches!(status, Some(200..=299)),
        StatusFilter::S3xx => matches!(status, Some(300..=399)),
        StatusFilter::S4xx => matches!(status, Some(400..=499)),
        StatusFilter::S5xx => matches!(status, Some(500..=599)),
        StatusFilter::Errors => is_error(ex),
    };
    if !ok {
        return false;
    }
    if needle.is_empty() {
        return true;
    }
    let url = ex.request.url().to_lowercase();
    url.contains(needle)
        || ex.request.method.to_lowercase() == needle
        || status.is_some_and(|s| s.to_string() == needle)
}

fn is_error(ex: &Exchange) -> bool {
    matches!(ex.state, ExchangeState::Failed | ExchangeState::Aborted)
}

fn short_type(ex: &Exchange) -> String {
    let ct = ex.content_type().unwrap_or("");
    let main = ct.split(';').next().unwrap_or("").trim();
    match main {
        "" if ex.upgraded => "websocket".into(),
        "" => String::new(),
        m => m.rsplit('/').next().unwrap_or(m).to_string(),
    }
}

pub fn show(app: &mut FluxApp, ui: &mut egui::Ui) {
    let ctx = ui.ctx().clone();
    if app.settings.engine.decrypt_tls && app.ca_trust() == Some(TrustStatus::NotTrusted) {
        if banner(
            ui,
            YELLOW,
            icon::SHIELD_ALERT,
            "HTTPS traffic can't be decrypted until the FluxRS root certificate is trusted.",
            Some("Install certificate"),
        ) {
            app.install_ca(&ctx);
        }
        ui.add_space(12.0);
    }

    if app.exchanges.is_empty() {
        onboarding(app, ui);
        return;
    }

    stats(app, ui);
    ui.add_space(12.0);
    toolbar(app, ui);
    ui.add_space(10.0);

    let selected = app
        .traffic
        .selected
        .and_then(|id| app.exchange(id).cloned());
    if let Some(ex) = selected {
        let w = ui.available_width();
        egui::Panel::right("details")
            .resizable(true)
            .default_size(w * 0.44)
            .size_range(380.0..=w * 0.75)
            .show_separator_line(false)
            .frame(egui::Frame::new().inner_margin(Margin {
                left: 12,
                right: 0,
                top: 0,
                bottom: 0,
            }))
            .show(ui, |ui| details(app, ui, ex));
    }

    egui::CentralPanel::default()
        .frame(egui::Frame::new())
        .show(ui, |ui| table(app, ui));
}

fn stats(app: &FluxApp, ui: &mut egui::Ui) {
    let total = app.exchanges.len();
    let errors = app.exchanges.iter().filter(|e| is_error(e)).count();
    let client_errors = app
        .exchanges
        .iter()
        .filter(|e| e.response.as_ref().is_some_and(|r| r.status >= 400))
        .count();
    let bytes: usize = app
        .exchanges
        .iter()
        .filter_map(|e| e.response.as_ref())
        .map(|r| r.body.len())
        .sum();
    let durations: Vec<u64> = app
        .exchanges
        .iter()
        .filter(|e| e.request.method != "TUNNEL")
        .filter_map(|e| e.duration_ms)
        .collect();
    let avg = if durations.is_empty() {
        0
    } else {
        durations.iter().sum::<u64>() / durations.len() as u64
    };
    let https = app
        .exchanges
        .iter()
        .filter(|e| e.request.scheme == "https")
        .count();
    ui.columns(4, |cols| {
        stat_tile(
            &mut cols[0],
            icon::ACTIVITY,
            "Requests",
            &total.to_string(),
            &format!("{https} HTTPS"),
            ACCENT_HI,
        );
        stat_tile(
            &mut cols[1],
            icon::CIRCLE_ALERT,
            "Errors",
            &(errors + client_errors).to_string(),
            &format!("{errors} failed"),
            if errors + client_errors > 0 {
                ORANGE
            } else {
                GREEN
            },
        );
        stat_tile(
            &mut cols[2],
            icon::DOWNLOAD,
            "Received",
            &human_bytes(bytes),
            "bodies",
            CYAN,
        );
        stat_tile(
            &mut cols[3],
            icon::GAUGE,
            "Avg duration",
            &human_ms(avg),
            "",
            PINK,
        );
    });
}

fn toolbar(app: &mut FluxApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        egui::Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, BORDER_STRONG))
            .corner_radius(egui::CornerRadius::from(8u8))
            .inner_margin(Margin::symmetric(10, 3))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(ico(icon::SEARCH, 14.0, TEXT_FAINT));
                    ui.add(
                        egui::TextEdit::singleline(&mut app.traffic.search)
                            .hint_text("Filter by URL, method or status")
                            .frame(egui::Frame::NONE)
                            .desired_width(260.0),
                    );
                    if !app.traffic.search.is_empty()
                        && icon_button(ui, icon::X, "Clear filter").clicked()
                    {
                        app.traffic.search.clear();
                    }
                });
            });
        ui.add_space(4.0);
        segmented(
            ui,
            &mut app.traffic.status,
            &[
                (StatusFilter::All, None, "All"),
                (StatusFilter::S2xx, None, "2xx"),
                (StatusFilter::S3xx, None, "3xx"),
                (StatusFilter::S4xx, None, "4xx"),
                (StatusFilter::S5xx, None, "5xx"),
                (StatusFilter::Errors, None, "Failed"),
            ],
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ghost_button(ui, icon::TRASH, "Clear").clicked() {
                app.clear_traffic();
            }
            ui.add_space(6.0);
            ui.checkbox(&mut app.traffic.follow, "Follow");
            ui.checkbox(&mut app.traffic.hide_tunnels, "Hide tunnels");
        });
    });
}

fn table(app: &mut FluxApp, ui: &mut egui::Ui) {
    let needle = app.traffic.search.trim().to_lowercase();
    let rows: Vec<Arc<Exchange>> = app
        .exchanges
        .iter()
        .filter(|e| matches(e, &app.traffic, &needle))
        .cloned()
        .collect();
    let max_ms = rows
        .iter()
        .filter(|e| e.request.method != "TUNNEL")
        .filter_map(|e| e.duration_ms)
        .max()
        .unwrap_or(1)
        .max(1);

    egui::Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(egui::CornerRadius::from(12u8))
        .inner_margin(Margin::symmetric(6, 4))
        .show(ui, |ui| {
            ui.set_min_size(ui.available_size());
            if rows.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(60.0);
                    ui.label(ico(icon::SEARCH, 26.0, TEXT_FAINT));
                    ui.label(RichText::new("No exchange matches the filter").color(TEXT_DIM));
                });
                return;
            }
            let mut clicked: Option<ExchangeId> = None;
            let mut table = TableBuilder::new(ui)
                .id_salt("traffic_table")
                .striped(false)
                .resizable(false)
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::exact(64.0))
                .column(Column::exact(74.0))
                .column(Column::initial(210.0).at_least(90.0).clip(true))
                .column(Column::remainder().at_least(140.0).clip(true))
                .column(Column::initial(76.0).clip(true))
                .column(Column::exact(70.0))
                .column(Column::exact(118.0))
                .auto_shrink([false, false])
                .min_scrolled_height(0.0);
            if app.traffic.follow {
                table = table.scroll_to_row(rows.len() - 1, Some(egui::Align::BOTTOM));
            }
            table
                .header(30.0, |mut h| {
                    for title in [
                        "Status", "Method", "Host", "Path", "Type", "Size", "Duration",
                    ] {
                        h.col(|ui| {
                            ui.label(strong(title.to_uppercase(), 10.5, TEXT_FAINT));
                        });
                    }
                })
                .body(|body| {
                    body.rows(30.0, rows.len(), |mut row| {
                        let ex = &rows[row.index()];
                        row.set_selected(app.traffic.selected == Some(ex.id));
                        let tunnel = ex.request.method == "TUNNEL";
                        row.col(|ui| status_cell(ui, ex));
                        row.col(|ui| {
                            ui.label(
                                RichText::new(&ex.request.method)
                                    .font(mono(12.0))
                                    .color(method_color(&ex.request.method)),
                            );
                            if ex.intercepted {
                                ui.label(ico(icon::PAUSE, 11.0, YELLOW))
                                    .on_hover_text("Edited at a breakpoint");
                            }
                        });
                        row.col(|ui| {
                            if ex.request.scheme == "https" {
                                let c = if tunnel { TEXT_FAINT } else { GREEN };
                                ui.label(ico(icon::LOCK, 12.0, c)).on_hover_text(if tunnel {
                                    "HTTPS tunnel (not decrypted)"
                                } else {
                                    "HTTPS, decrypted"
                                });
                            }
                            let mut host = ex.request.host.clone();
                            if !matches!(
                                (ex.request.scheme.as_str(), ex.request.port),
                                ("http", 80) | ("https", 443)
                            ) {
                                host = format!("{host}:{}", ex.request.port);
                            }
                            ui.add(
                                egui::Label::new(RichText::new(host).color(if tunnel {
                                    TEXT_FAINT
                                } else {
                                    TEXT
                                }))
                                .truncate(),
                            );
                        });
                        row.col(|ui| {
                            if !ex.applied_rules.is_empty() {
                                ui.label(ico(icon::WAND, 12.0, ACCENT_HI))
                                    .on_hover_text(ex.applied_rules.join(", "));
                            }
                            ui.add(
                                egui::Label::new(
                                    RichText::new(if tunnel { "" } else { &ex.request.path })
                                        .font(mono(12.0))
                                        .color(TEXT_DIM),
                                )
                                .truncate(),
                            );
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(short_type(ex)).size(12.0).color(TEXT_DIM));
                        });
                        row.col(|ui| {
                            let size = ex.response.as_ref().map(|r| r.body.len()).unwrap_or(0);
                            if size > 0 {
                                ui.label(
                                    RichText::new(human_bytes(size)).size(12.0).color(TEXT_DIM),
                                );
                            }
                        });
                        row.col(|ui| duration_cell(ui, ex, max_ms));
                        if row.response().clicked() {
                            clicked = Some(ex.id);
                        }
                    });
                });
            if let Some(id) = clicked {
                app.traffic.selected = if app.traffic.selected == Some(id) {
                    None
                } else {
                    Some(id)
                };
            }
        });
}

fn duration_cell(ui: &mut egui::Ui, ex: &Exchange, max_ms: u64) {
    let Some(ms) = ex.duration_ms else {
        if !matches!(ex.state, ExchangeState::Completed) {
            ui.label(RichText::new("…").color(TEXT_FAINT));
        }
        return;
    };
    let (rect, _) = ui.allocate_exact_size(egui::vec2(46.0, 6.0), egui::Sense::hover());
    let frac = if ex.request.method == "TUNNEL" {
        0.0
    } else {
        (ms as f32 / max_ms as f32).clamp(0.04, 1.0)
    };
    let p = ui.painter();
    p.rect_filled(rect, egui::CornerRadius::from(3u8), RAISED);
    let color = if ms > 1000 { ORANGE } else { ACCENT };
    if frac > 0.0 {
        p.rect_filled(
            egui::Rect::from_min_size(rect.min, egui::vec2(rect.width() * frac, rect.height())),
            egui::CornerRadius::from(3u8),
            color,
        );
    }
    ui.label(RichText::new(human_ms(ms)).size(11.5).color(TEXT_DIM));
}

fn status_cell(ui: &mut egui::Ui, ex: &Exchange) {
    match (&ex.response, ex.state) {
        (_, ExchangeState::Intercepted) => {
            dot(ui, YELLOW, 3.5);
            ui.label(strong("Paused", 11.5, YELLOW));
        }
        (_, ExchangeState::Aborted) | (None, ExchangeState::Failed) => {
            dot(ui, RED, 3.5);
            ui.label(RichText::new("Error").font(mono(12.0)).color(RED))
                .on_hover_text(ex.error.clone().unwrap_or_default());
        }
        (Some(r), _) => {
            dot(ui, status_color(r.status), 3.5);
            ui.label(
                RichText::new(r.status.to_string())
                    .font(mono(12.0))
                    .color(status_color(r.status)),
            );
        }
        (None, _) if ex.request.method == "TUNNEL" => {
            let c = if ex.state == ExchangeState::Completed {
                TEXT_FAINT
            } else {
                CYAN
            };
            dot(ui, c, 3.5);
            ui.label(RichText::new("TLS").font(mono(12.0)).color(c));
        }
        (None, _) => {
            ui.spinner();
        }
    }
}

fn onboarding(app: &mut FluxApp, ui: &mut egui::Ui) {
    let ctx = ui.ctx().clone();
    ui.vertical_centered(|ui| {
        ui.add_space((ui.available_height() * 0.12).max(10.0));
        logo(ui, 64.0);
        ui.add_space(16.0);
        ui.label(strong("Inspect any HTTP(S) traffic", 24.0, TEXT));
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "FluxRS captures requests from every app on this PC — no proxy settings needed.",
            )
            .size(14.0)
            .color(TEXT_DIM),
        );
        ui.add_space(26.0);
    });

    let trust = app.ca_trust();
    let cert_done = trust == Some(TrustStatus::Trusted);
    let running = app.is_running();
    let width = ui.available_width().min(900.0);
    let pad = ((ui.available_width() - width) / 2.0).max(0.0);
    let mut install = false;
    let mut start = false;
    ui.horizontal(|ui| {
        ui.add_space(pad);
        ui.allocate_ui(egui::vec2(width, 200.0), |ui| {
            ui.columns(3, |cols| {
                install = step(
                    &mut cols[0],
                    1,
                    icon::SHIELD_CHECK,
                    "Trust the certificate",
                    "Needed once to decrypt HTTPS.",
                    cert_done,
                    if cert_done || trust == Some(TrustStatus::Unknown) {
                        None
                    } else {
                        Some("Install")
                    },
                );
                start = step(
                    &mut cols[1],
                    2,
                    icon::PLAY,
                    "Start capturing",
                    match app.settings.engine.mode {
                        CaptureMode::Proxyless => "Proxyless mode: all apps, no setup.",
                        CaptureMode::Proxy => "Explicit proxy on 127.0.0.1.",
                    },
                    running,
                    (!running).then_some("Start"),
                );
                step(
                    &mut cols[2],
                    3,
                    icon::GLOBE,
                    "Use any app",
                    "Open a browser or run your client. Traffic appears here.",
                    false,
                    None,
                );
            });
        });
    });
    if install {
        app.install_ca(&ctx);
    }
    if start {
        app.start(&ctx);
    }
    if running && app.settings.engine.mode == CaptureMode::Proxy {
        ui.add_space(14.0);
        ui.vertical_centered(|ui| {
            let addr = app.local_addr().unwrap_or_default().to_string();
            ui.label(
                RichText::new(format!("Set your client's HTTP proxy to {addr}"))
                    .font(mono(12.5))
                    .color(TEXT_DIM),
            );
        });
    }
}

/// Onboarding step card. Returns true when its action is clicked.
fn step(
    ui: &mut egui::Ui,
    n: usize,
    ic: &str,
    title: &str,
    text: &str,
    done: bool,
    action: Option<&str>,
) -> bool {
    let mut clicked = false;
    card().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.set_min_height(150.0);
        ui.horizontal(|ui| {
            egui::Frame::new()
                .fill(if done {
                    GREEN.gamma_multiply(0.15)
                } else {
                    ACCENT_SOFT
                })
                .corner_radius(egui::CornerRadius::from(9u8))
                .inner_margin(Margin::same(8))
                .show(ui, |ui| {
                    ui.label(ico(
                        if done { icon::CHECK } else { ic },
                        18.0,
                        if done { GREEN } else { ACCENT_HI },
                    ));
                });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(strong(format!("STEP {n}"), 10.5, TEXT_FAINT));
            });
        });
        ui.add_space(10.0);
        ui.label(strong(title, 14.5, TEXT));
        ui.label(RichText::new(text).size(12.5).color(TEXT_DIM));
        ui.add_space(8.0);
        if let Some(a) = action {
            clicked = primary_button(ui, ic, a, ACCENT).clicked();
        } else if done {
            ui.label(strong("Done", 12.0, GREEN));
        }
    });
    clicked
}

fn body_to_text(headers: &HeaderList, body: &Bytes, raw: bool) -> String {
    if body.is_empty() {
        return String::new();
    }
    let decoded = if raw {
        body.clone()
    } else {
        decode_body(headers, body).unwrap_or_else(|| body.clone())
    };
    let shown = &decoded[..decoded.len().min(2 * 1024 * 1024)];
    match std::str::from_utf8(shown) {
        Ok(text) if !text.contains('\0') => {
            let ct = fluxrs_model::header_value(headers, "content-type").unwrap_or("");
            if !raw && (ct.contains("json") || text.trim_start().starts_with('{')) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
                    if let Ok(pretty) = serde_json::to_string_pretty(&v) {
                        return pretty;
                    }
                }
            }
            let mut s = text.to_string();
            if decoded.len() > shown.len() {
                s.push_str("\n\n… (truncated for display)");
            }
            s
        }
        _ => hex_dump(&decoded[..decoded.len().min(64 * 1024)], decoded.len()),
    }
}

fn hex_dump(data: &[u8], total: usize) -> String {
    let mut out = format!("Binary body ({}), hex view:\n\n", human_bytes(total));
    for (i, chunk) in data.chunks(16).enumerate() {
        out.push_str(&format!("{:08x}  ", i * 16));
        for j in 0..16 {
            match chunk.get(j) {
                Some(b) => out.push_str(&format!("{b:02x} ")),
                None => out.push_str("   "),
            }
        }
        out.push(' ');
        for b in chunk {
            out.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        out.push('\n');
    }
    out
}

fn ensure_cache(st: &mut TrafficState, ex: &Arc<Exchange>) {
    let fresh = st
        .cache
        .as_ref()
        .is_some_and(|c| Arc::ptr_eq(&c.exchange, ex) && c.raw == st.raw_body);
    if fresh {
        return;
    }
    let request = body_to_text(&ex.request.headers, &ex.request.body, st.raw_body);
    let response = ex
        .response
        .as_ref()
        .map(|r| body_to_text(&r.headers, &r.body, st.raw_body))
        .unwrap_or_default();
    st.cache = Some(BodyCache {
        exchange: ex.clone(),
        raw: st.raw_body,
        request,
        response,
    });
}

fn details(app: &mut FluxApp, ui: &mut egui::Ui, ex: Arc<Exchange>) {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(egui::CornerRadius::from(12u8))
        .inner_margin(Margin::same(16))
        .show(ui, |ui| {
            ui.set_min_size(ui.available_size());
            // Header
            ui.horizontal(|ui| {
                pill(ui, &ex.request.method, method_color(&ex.request.method));
                if let Some(r) = &ex.response {
                    pill(
                        ui,
                        format!("{} {}", r.status, r.reason),
                        status_color(r.status),
                    );
                }
                let (state, c) = match ex.state {
                    ExchangeState::Pending => ("Pending", CYAN),
                    ExchangeState::Intercepted => ("Paused", YELLOW),
                    ExchangeState::Receiving => ("Receiving", CYAN),
                    ExchangeState::Completed => ("Completed", TEXT_DIM),
                    ExchangeState::Failed => ("Failed", RED),
                    ExchangeState::Aborted => ("Aborted", RED),
                };
                pill(ui, state, c);
                if let Some(ms) = ex.duration_ms {
                    ui.label(ico(icon::CLOCK, 12.0, TEXT_FAINT));
                    ui.label(RichText::new(human_ms(ms)).size(12.0).color(TEXT_DIM));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if icon_button(ui, icon::X, "Close").clicked() {
                        app.traffic.selected = None;
                    }
                });
            });
            ui.add_space(10.0);
            inset().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.add(
                    egui::Label::new(RichText::new(ex.request.url()).font(mono(12.5)).color(TEXT))
                        .wrap(),
                );
            });
            if let Some(err) = &ex.error {
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(ico(icon::CIRCLE_ALERT, 14.0, RED));
                    ui.label(RichText::new(err).color(RED));
                });
            }
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ghost_button(ui, icon::COPY, "URL").clicked() {
                    ui.ctx().copy_text(ex.request.url());
                }
                if ghost_button(ui, icon::TERMINAL, "cURL").clicked() {
                    ui.ctx().copy_text(to_curl(&ex));
                }
                if ghost_button(ui, icon::LIST_PLUS, "Create rule")
                    .on_hover_text("New rewrite rule matching this host and path")
                    .clicked()
                {
                    app.rules.push(rule_from(&ex));
                    app.rules_ui.selected = Some(app.rules.len() - 1);
                    app.rules_changed();
                    app.view = View::Rules;
                }
            });
            ui.add_space(14.0);
            tabs(
                ui,
                &mut app.traffic.tab,
                &[
                    (DetailTab::Request, "Request"),
                    (DetailTab::Response, "Response"),
                    (DetailTab::Https, "HTTPS"),
                    (DetailTab::Timing, "Timing"),
                ],
            );
            ensure_cache(&mut app.traffic, &ex);
            let tab = app.traffic.tab;
            let mut raw = app.traffic.raw_body;
            let cache = app.traffic.cache.as_ref().expect("cache filled");
            egui::ScrollArea::vertical()
                .id_salt(("detail_scroll", ex.id, tab as u8))
                .auto_shrink([false, false])
                .show(ui, |ui| match tab {
                    DetailTab::Request => {
                        let line = format!(
                            "{} {} {}",
                            ex.request.method, ex.request.path, ex.request.version
                        );
                        message_view(
                            ui,
                            &line,
                            &ex.request.headers,
                            &cache.request,
                            ex.request.body.len(),
                            &mut raw,
                        );
                    }
                    DetailTab::Response => match &ex.response {
                        Some(r) => {
                            let mut line = format!("{} {} {}", r.version, r.status, r.reason);
                            if r.body_truncated {
                                line.push_str("  (capture truncated)");
                            }
                            message_view(
                                ui,
                                &line,
                                &r.headers,
                                &cache.response,
                                r.body.len(),
                                &mut raw,
                            );
                        }
                        None => empty_note(ui, icon::CLOCK, "No response yet"),
                    },
                    DetailTab::Https => https_view(ui, &ex),
                    DetailTab::Timing => timing_view(ui, &ex),
                });
            app.traffic.raw_body = raw;
        });
}

fn empty_note(ui: &mut egui::Ui, ic: &str, text: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(30.0);
        ui.label(ico(ic, 24.0, TEXT_FAINT));
        ui.label(RichText::new(text).color(TEXT_DIM));
    });
}

fn message_view(
    ui: &mut egui::Ui,
    start_line: &str,
    headers: &HeaderList,
    body: &str,
    size: usize,
    raw: &mut bool,
) {
    inset().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(RichText::new(start_line).font(mono(12.5)).color(CYAN));
    });
    ui.add_space(12.0);
    ui.horizontal(|ui| {
        caption(ui, &format!("Headers · {}", headers.len()));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if icon_button(ui, icon::COPY, "Copy headers").clicked() {
                let text: String = headers.iter().map(|(n, v)| format!("{n}: {v}\n")).collect();
                ui.ctx().copy_text(text);
            }
        });
    });
    egui::Grid::new(ui.next_auto_id())
        .num_columns(2)
        .spacing([16.0, 6.0])
        .min_col_width(120.0)
        .show(ui, |ui| {
            for (n, v) in headers {
                ui.label(RichText::new(n).font(mono(12.0)).color(ACCENT_HI));
                ui.add(egui::Label::new(RichText::new(v).font(mono(12.0)).color(TEXT)).wrap());
                ui.end_row();
            }
        });
    ui.add_space(14.0);
    ui.horizontal(|ui| {
        caption(ui, &format!("Body · {}", human_bytes(size)));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if !body.is_empty() && icon_button(ui, icon::COPY, "Copy body").clicked() {
                ui.ctx().copy_text(body.to_string());
            }
            // right-to-left layout: listed in reverse visual order
            segmented(ui, raw, &[(true, None, "Raw"), (false, None, "Pretty")]);
        });
    });
    ui.add_space(4.0);
    if body.is_empty() {
        ui.label(RichText::new("No body").color(TEXT_FAINT).italics());
    } else {
        // `&mut &str` makes the editor read-only but selectable.
        ui.add(
            egui::TextEdit::multiline(&mut { body })
                .font(mono(12.0))
                .code_editor()
                .desired_width(f32::INFINITY)
                .desired_rows(14),
        );
    }
}

fn kv(ui: &mut egui::Ui, k: &str, v: impl Into<String>) {
    ui.label(RichText::new(k).color(TEXT_DIM));
    ui.add(egui::Label::new(RichText::new(v.into()).font(mono(12.0))).wrap());
    ui.end_row();
}

fn tls_leg(
    ui: &mut egui::Ui,
    id: &str,
    ic: &str,
    title: &str,
    version: &Option<String>,
    cipher: &Option<String>,
    extra: (&str, String),
) {
    card().inner_margin(Margin::same(12)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(ico(ic, 14.0, ACCENT_HI));
            ui.label(strong(title, 13.0, TEXT));
            if let Some(v) = version {
                pill(ui, v, GREEN);
            }
        });
        ui.add_space(6.0);
        egui::Grid::new(id)
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                kv(
                    ui,
                    "Protocol",
                    version.clone().unwrap_or_else(|| "—".into()),
                );
                kv(
                    ui,
                    "Cipher suite",
                    cipher.clone().unwrap_or_else(|| "—".into()),
                );
                kv(ui, extra.0, extra.1);
            });
    });
    ui.add_space(10.0);
}

fn https_view(ui: &mut egui::Ui, ex: &Exchange) {
    let Some(tls) = &ex.tls else {
        if ex.request.method == "TUNNEL" {
            empty_note(
                ui,
                icon::LOCK,
                "Encrypted tunnel — this host is not decrypted (bypass list or decryption off)",
            );
        } else {
            empty_note(ui, icon::GLOBE, "Plain HTTP — no TLS on this exchange");
        }
        return;
    };
    tls_leg(
        ui,
        "tls_client",
        icon::MONITOR,
        "Client → FluxRS",
        &tls.client_version,
        &tls.client_cipher,
        (
            "SNI / ALPN",
            format!(
                "{} / {}",
                tls.sni.clone().unwrap_or_else(|| "—".into()),
                tls.client_alpn.clone().unwrap_or_else(|| "—".into())
            ),
        ),
    );
    tls_leg(
        ui,
        "tls_server",
        icon::SERVER,
        "FluxRS → Server",
        &tls.server_version,
        &tls.server_cipher,
        ("Chain length", tls.server_chain_len.to_string()),
    );
    if let Some(cert) = &tls.server_cert {
        card().inner_margin(Margin::same(12)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(ico(icon::SHIELD_CHECK, 14.0, GREEN));
                ui.label(strong("Server certificate", 13.0, TEXT));
            });
            ui.add_space(6.0);
            egui::Grid::new("tls_cert")
                .num_columns(2)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    kv(ui, "Subject", cert.subject.clone());
                    kv(ui, "Issuer", cert.issuer.clone());
                    kv(ui, "Valid from", cert.not_before.clone());
                    kv(ui, "Valid until", cert.not_after.clone());
                    kv(ui, "Serial", cert.serial.clone());
                });
            if !cert.san.is_empty() {
                ui.add_space(8.0);
                caption(ui, "Subject alternative names");
                ui.horizontal_wrapped(|ui| {
                    for s in cert.san.iter().take(40) {
                        pill(ui, s, TEXT_DIM);
                    }
                    if cert.san.len() > 40 {
                        ui.label(
                            RichText::new(format!("+{} more", cert.san.len() - 40))
                                .color(TEXT_FAINT),
                        );
                    }
                });
            }
        });
    }
}

fn clock(t: std::time::SystemTime) -> String {
    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let s = d.as_secs();
    format!(
        "{:02}:{:02}:{:02}.{:03} UTC",
        (s / 3600) % 24,
        (s / 60) % 60,
        s % 60,
        d.subsec_millis()
    )
}

fn timing_view(ui: &mut egui::Ui, ex: &Exchange) {
    if let (Some(total), Some(ttfb)) = (ex.duration_ms, ex.ttfb_ms) {
        caption(ui, "Timeline");
        ui.add_space(4.0);
        let (rect, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 12.0), egui::Sense::hover());
        let p = ui.painter();
        p.rect_filled(rect, egui::CornerRadius::from(6u8), RAISED);
        let total_f = total.max(1) as f32;
        let wait_w = (rect.width() * (ttfb as f32 / total_f).clamp(0.0, 1.0)).max(3.0);
        if wait_w < rect.width() {
            p.rect_filled(rect, egui::CornerRadius::from(6u8), CYAN);
        }
        p.rect_filled(
            egui::Rect::from_min_size(rect.min, egui::vec2(wait_w, rect.height())),
            egui::CornerRadius::from(6u8),
            ACCENT,
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            dot(ui, ACCENT, 4.0);
            ui.label(RichText::new(format!("Waiting {}", human_ms(ttfb))).color(TEXT_DIM));
            ui.add_space(10.0);
            dot(ui, CYAN, 4.0);
            ui.label(
                RichText::new(format!("Content {}", human_ms(total.saturating_sub(ttfb))))
                    .color(TEXT_DIM),
            );
        });
        ui.add_space(14.0);
    }
    egui::Grid::new("timing_grid")
        .num_columns(2)
        .spacing([18.0, 8.0])
        .show(ui, |ui| {
            kv(ui, "Started", clock(ex.started));
            kv(ui, "Exchange", format!("#{}", ex.id));
            kv(
                ui,
                "Client",
                ex.client.map(|c| c.to_string()).unwrap_or_default(),
            );
            kv(
                ui,
                "Server",
                format!("{}:{}", ex.request.host, ex.request.port),
            );
            kv(
                ui,
                "Time to headers",
                ex.ttfb_ms.map(human_ms).unwrap_or_else(|| "—".into()),
            );
            kv(
                ui,
                "Total",
                ex.duration_ms.map(human_ms).unwrap_or_else(|| "—".into()),
            );
            kv(ui, "Request body", human_bytes(ex.request.body.len()));
            kv(
                ui,
                "Response body",
                ex.response
                    .as_ref()
                    .map(|r| human_bytes(r.body.len()))
                    .unwrap_or_else(|| "—".into()),
            );
            kv(
                ui,
                "Rules applied",
                if ex.applied_rules.is_empty() {
                    "none".to_string()
                } else {
                    ex.applied_rules.join(", ")
                },
            );
            kv(
                ui,
                "Breakpoint",
                if ex.intercepted { "edited" } else { "no" },
            );
            kv(ui, "WebSocket", if ex.upgraded { "upgraded" } else { "no" });
        });
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn to_curl(ex: &Exchange) -> String {
    let mut out = format!(
        "curl -X {} {}",
        ex.request.method,
        shell_quote(&ex.request.url())
    );
    for (n, v) in &ex.request.headers {
        if n.eq_ignore_ascii_case("host") || n.eq_ignore_ascii_case("content-length") {
            continue;
        }
        out.push_str(&format!(" \\\n  -H {}", shell_quote(&format!("{n}: {v}"))));
    }
    if !ex.request.body.is_empty() {
        out.push_str(&format!(
            " \\\n  --data-binary {}",
            shell_quote(&String::from_utf8_lossy(&ex.request.body))
        ));
    }
    if fluxrs_model::header_value(&ex.request.headers, "accept-encoding").is_some() {
        out.push_str(" \\\n  --compressed");
    }
    out
}

fn rule_from(ex: &Exchange) -> Rule {
    let path = ex.request.path.split('?').next().unwrap_or("/").to_string();
    Rule {
        name: format!("{} {}{}", ex.request.method, ex.request.host, path),
        enabled: false,
        filters: vec![
            Filter {
                field: FilterField::Host,
                op: MatchOp::Equals,
                value: ex.request.host.clone(),
                ..Default::default()
            },
            Filter {
                field: FilterField::Path,
                op: MatchOp::StartsWith,
                value: path,
                ..Default::default()
            },
        ],
        actions: vec![Action::SetResponseHeader {
            name: "X-FluxRS".into(),
            value: "rewritten".into(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_curl() {
        let h = hex_dump(&[0, 65, 66, 255], 4);
        assert!(h.contains("00 41 42 ff"));
        assert!(h.contains(".AB."));
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn pretty_json_body() {
        let headers = vec![("content-type".to_string(), "application/json".to_string())];
        let t = body_to_text(&headers, &Bytes::from_static(b"{\"a\":1}"), false);
        assert_eq!(t, "{\n  \"a\": 1\n}");
        let raw = body_to_text(&headers, &Bytes::from_static(b"{\"a\":1}"), true);
        assert_eq!(raw, "{\"a\":1}");
    }

    #[test]
    fn clock_format() {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_millis(3_723_045);
        assert_eq!(clock(t), "01:02:03.045 UTC");
    }
}
