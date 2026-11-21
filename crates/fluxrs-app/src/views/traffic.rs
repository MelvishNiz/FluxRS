//! Traffic list + exchange details.

use crate::app::{FluxApp, View};
use crate::theme::*;
use bytes::Bytes;
use eframe::egui::{self, Margin, RichText};
use egui_extras::{Column, TableBuilder};
use fluxrs_core::{
    body::decode_body, Action, Exchange, ExchangeId, ExchangeState, Filter, FilterField,
    HeaderList, MatchOp, Rule,
};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DetailTab {
    #[default]
    Request,
    Response,
    Overview,
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
        StatusFilter::Errors => matches!(ex.state, ExchangeState::Failed | ExchangeState::Aborted),
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

fn short_type(ex: &Exchange) -> String {
    let ct = ex.content_type().unwrap_or("");
    let main = ct.split(';').next().unwrap_or("").trim();
    match main {
        "" => {
            if ex.upgraded {
                "websocket".into()
            } else {
                String::new()
            }
        }
        m => m.rsplit('/').next().unwrap_or(m).to_string(),
    }
}

pub fn show(app: &mut FluxApp, ui: &mut egui::Ui) {
    toolbar(app, ui);
    ui.add_space(8.0);

    let selected = app
        .traffic
        .selected
        .and_then(|id| app.exchange(id).cloned());
    if let Some(ex) = selected {
        egui::Panel::right("details")
            .resizable(true)
            .default_size(ui.available_width() * 0.46)
            .size_range(360.0..=ui.available_width() * 0.75)
            .frame(egui::Frame::new().inner_margin(Margin {
                left: 10,
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

fn toolbar(app: &mut FluxApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        egui::Frame::new()
            .fill(SURFACE)
            .stroke(egui::Stroke::new(1.0, BORDER))
            .corner_radius(egui::CornerRadius::from(8u8))
            .inner_margin(Margin::symmetric(8, 2))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("🔍").color(TEXT_DIM));
                    ui.add(
                        egui::TextEdit::singleline(&mut app.traffic.search)
                            .hint_text("Filter by URL, method or status…")
                            .frame(egui::Frame::NONE)
                            .desired_width(300.0),
                    );
                    if !app.traffic.search.is_empty() && ui.small_button("✖").clicked() {
                        app.traffic.search.clear();
                    }
                });
            });
        ui.add_space(6.0);
        let chips = [
            (StatusFilter::All, "All", TEXT_DIM),
            (StatusFilter::S2xx, "2xx", GREEN),
            (StatusFilter::S3xx, "3xx", BLUE),
            (StatusFilter::S4xx, "4xx", ORANGE),
            (StatusFilter::S5xx, "5xx", RED),
            (StatusFilter::Errors, "Errors", PINK),
        ];
        for (f, label, color) in chips {
            let sel = app.traffic.status == f;
            let text = RichText::new(label).color(if sel { color } else { TEXT_DIM });
            if ui.selectable_label(sel, text).clicked() {
                app.traffic.status = f;
            }
        }
        ui.add_space(6.0);
        ui.checkbox(&mut app.traffic.hide_tunnels, "Hide tunnels");
        ui.checkbox(&mut app.traffic.follow, "Auto-scroll");
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

    if app.exchanges.is_empty() {
        empty_state(app, ui);
        return;
    }

    card().inner_margin(Margin::same(4)).show(ui, |ui| {
        ui.set_min_size(ui.available_size());
        let mut clicked: Option<ExchangeId> = None;
        let mut table = TableBuilder::new(ui)
            .id_salt("traffic_table")
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::exact(52.0))
            .column(Column::exact(74.0))
            .column(Column::exact(58.0))
            .column(Column::initial(200.0).at_least(80.0).clip(true))
            .column(Column::remainder().at_least(120.0).clip(true))
            .column(Column::initial(80.0).clip(true))
            .column(Column::exact(72.0))
            .column(Column::exact(72.0))
            .auto_shrink([false, false])
            .min_scrolled_height(0.0);
        if app.traffic.follow && !rows.is_empty() {
            table = table.scroll_to_row(rows.len() - 1, Some(egui::Align::BOTTOM));
        }
        table
            .header(26.0, |mut h| {
                for title in [
                    "#", "Method", "Status", "Host", "Path", "Type", "Size", "Time",
                ] {
                    h.col(|ui| {
                        ui.label(RichText::new(title).size(11.5).color(TEXT_FAINT).strong());
                    });
                }
            })
            .body(|body| {
                body.rows(26.0, rows.len(), |mut row| {
                    let ex = &rows[row.index()];
                    row.set_selected(app.traffic.selected == Some(ex.id));
                    let dim = ex.request.method == "TUNNEL";
                    row.col(|ui| {
                        ui.label(
                            RichText::new(ex.id.to_string())
                                .size(11.5)
                                .color(TEXT_FAINT),
                        );
                    });
                    row.col(|ui| {
                        let mut t = RichText::new(&ex.request.method)
                            .monospace()
                            .strong()
                            .color(method_color(&ex.request.method));
                        if ex.intercepted {
                            t = t.underline();
                        }
                        ui.label(t);
                    });
                    row.col(|ui| status_cell(ui, ex));
                    row.col(|ui| {
                        let mut host = ex.request.host.clone();
                        if !matches!(
                            (ex.request.scheme.as_str(), ex.request.port),
                            ("http", 80) | ("https", 443)
                        ) {
                            host = format!("{host}:{}", ex.request.port);
                        }
                        let lock = if ex.request.scheme == "https" {
                            "🔒 "
                        } else {
                            ""
                        };
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!("{lock}{host}")).color(if dim {
                                    TEXT_FAINT
                                } else {
                                    TEXT
                                }),
                            )
                            .truncate(),
                        );
                    });
                    row.col(|ui| {
                        let mut path = RichText::new(&ex.request.path).color(if dim {
                            TEXT_FAINT
                        } else {
                            TEXT_DIM
                        });
                        if !ex.applied_rules.is_empty() {
                            path = path.color(ACCENT);
                        }
                        ui.add(egui::Label::new(path).truncate());
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(short_type(ex)).size(12.0).color(TEXT_DIM));
                    });
                    row.col(|ui| {
                        let size = ex.response.as_ref().map(|r| r.body.len()).unwrap_or(0);
                        if size > 0 {
                            ui.label(RichText::new(human_bytes(size)).size(12.0).color(TEXT_DIM));
                        }
                    });
                    row.col(|ui| {
                        if let Some(ms) = ex.duration_ms {
                            let c = if ms > 1000 { ORANGE } else { TEXT_DIM };
                            ui.label(RichText::new(human_ms(ms)).size(12.0).color(c));
                        }
                    });
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

fn status_cell(ui: &mut egui::Ui, ex: &Exchange) {
    match (&ex.response, ex.state) {
        (_, ExchangeState::Intercepted) => {
            ui.label(RichText::new("⏸").color(YELLOW).strong());
        }
        (_, ExchangeState::Failed) | (_, ExchangeState::Aborted)
            if ex.response.is_none() || ex.state == ExchangeState::Aborted =>
        {
            ui.label(RichText::new("ERR").color(RED).strong().monospace())
                .on_hover_text(ex.error.clone().unwrap_or_default());
        }
        (Some(r), _) => {
            ui.label(
                RichText::new(r.status.to_string())
                    .color(status_color(r.status))
                    .strong()
                    .monospace(),
            );
        }
        (None, _) if ex.request.method == "TUNNEL" => {
            let c = if ex.state == ExchangeState::Completed {
                TEXT_FAINT
            } else {
                CYAN
            };
            ui.label(RichText::new("TLS").color(c).monospace());
        }
        (None, _) => {
            ui.spinner();
        }
    }
}

fn empty_state(app: &mut FluxApp, ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(ui.available_height() * 0.22);
        logo(ui, 56.0);
        ui.add_space(14.0);
        ui.label(RichText::new("No traffic captured yet").size(20.0).strong());
        ui.add_space(4.0);
        let hint = if app.is_running() {
            match app.settings.engine.mode {
                fluxrs_core::CaptureMode::Proxyless => {
                    "Capture is live. Open a browser or any app — HTTP/HTTPS traffic appears here automatically.".to_string()
                }
                fluxrs_core::CaptureMode::Proxy => format!(
                    "Configure your client to use the HTTP proxy {}",
                    app.engine
                        .as_ref()
                        .map(|e| e.local_addr().to_string())
                        .unwrap_or_default()
                ),
            }
        } else {
            "Press Start capture to begin. Proxyless mode needs no proxy configuration.".to_string()
        };
        ui.label(RichText::new(hint).color(TEXT_DIM));
        ui.add_space(14.0);
        if !app.is_running() {
            let ctx = ui.ctx().clone();
            if primary_button(ui, "▶  Start capture", GREEN).clicked() {
                app.start(&ctx);
            }
        }
    });
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
            let ct = fluxrs_core::model::header_value(headers, "content-type").unwrap_or("");
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
    card().inner_margin(Margin::same(12)).show(ui, |ui| {
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
                ExchangeState::Pending => ("pending", CYAN),
                ExchangeState::Intercepted => ("paused", YELLOW),
                ExchangeState::Receiving => ("receiving", CYAN),
                ExchangeState::Completed => ("done", TEXT_DIM),
                ExchangeState::Failed => ("failed", RED),
                ExchangeState::Aborted => ("aborted", RED),
            };
            pill(ui, state, c);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("✖").on_hover_text("Close").clicked() {
                    app.traffic.selected = None;
                }
            });
        });
        ui.add_space(6.0);
        ui.add(egui::Label::new(RichText::new(ex.request.url()).monospace().color(TEXT)).wrap());
        if let Some(err) = &ex.error {
            ui.add_space(4.0);
            ui.label(RichText::new(format!("⚠ {err}")).color(RED));
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("📋 Copy URL").clicked() {
                ui.ctx().copy_text(ex.request.url());
            }
            if ui.button("📋 Copy as cURL").clicked() {
                ui.ctx().copy_text(to_curl(&ex));
            }
            if ui
                .button("✏ Create rule")
                .on_hover_text("New rewrite rule matching this host and path")
                .clicked()
            {
                app.rules.push(rule_from(&ex));
                app.rules_ui.selected = Some(app.rules.len() - 1);
                app.rules_changed();
                app.view = View::Rules;
            }
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let tabs = [
                (DetailTab::Request, "Request"),
                (DetailTab::Response, "Response"),
                (DetailTab::Overview, "Overview"),
            ];
            for (t, label) in tabs {
                if ui.selectable_label(app.traffic.tab == t, label).clicked() {
                    app.traffic.tab = t;
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.checkbox(&mut app.traffic.raw_body, "Raw body");
            });
        });
        ui.separator();
        ensure_cache(&mut app.traffic, &ex);
        let cache = app.traffic.cache.as_ref().expect("cache filled");
        egui::ScrollArea::vertical()
            .id_salt(("detail_scroll", ex.id, app.traffic.tab as u8))
            .auto_shrink([false, false])
            .show(ui, |ui| match app.traffic.tab {
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
                    );
                }
                DetailTab::Response => match &ex.response {
                    Some(r) => {
                        let line = format!("{} {} {}", r.version, r.status, r.reason);
                        let mut note = String::new();
                        if r.body_truncated {
                            note = " (capture truncated)".into();
                        }
                        message_view(
                            ui,
                            &format!("{line}{note}"),
                            &r.headers,
                            &cache.response,
                            r.body.len(),
                        );
                    }
                    None => {
                        ui.label(RichText::new("No response yet.").color(TEXT_FAINT));
                    }
                },
                DetailTab::Overview => overview(ui, &ex),
            });
    });
}

fn message_view(
    ui: &mut egui::Ui,
    start_line: &str,
    headers: &HeaderList,
    body: &str,
    size: usize,
) {
    ui.label(RichText::new(start_line).monospace().strong().color(CYAN));
    ui.add_space(6.0);
    ui.label(
        RichText::new(format!("HEADERS ({})", headers.len()))
            .size(11.0)
            .color(TEXT_FAINT)
            .strong(),
    );
    egui::Grid::new(ui.next_auto_id())
        .num_columns(2)
        .spacing([14.0, 4.0])
        .striped(true)
        .show(ui, |ui| {
            for (n, v) in headers {
                ui.label(RichText::new(n).monospace().color(ACCENT));
                ui.add(egui::Label::new(RichText::new(v).monospace()).wrap());
                ui.end_row();
            }
        });
    ui.add_space(10.0);
    ui.label(
        RichText::new(format!("BODY ({})", human_bytes(size)))
            .size(11.0)
            .color(TEXT_FAINT)
            .strong(),
    );
    if body.is_empty() {
        ui.label(RichText::new("empty").color(TEXT_FAINT).italics());
    } else {
        ui.add(
            // `&mut &str` makes the editor read-only but selectable.
            egui::TextEdit::multiline(&mut { body })
                .code_editor()
                .desired_width(f32::INFINITY)
                .desired_rows(12),
        );
    }
}

fn overview(ui: &mut egui::Ui, ex: &Exchange) {
    egui::Grid::new("overview_grid")
        .num_columns(2)
        .spacing([18.0, 8.0])
        .show(ui, |ui| {
            let mut row = |k: &str, v: String| {
                ui.label(RichText::new(k).color(TEXT_DIM));
                ui.add(egui::Label::new(RichText::new(v).monospace()).wrap());
                ui.end_row();
            };
            row("Exchange", format!("#{}", ex.id));
            row(
                "Client",
                ex.client.map(|c| c.to_string()).unwrap_or_default(),
            );
            row("Server", format!("{}:{}", ex.request.host, ex.request.port));
            row("Scheme", ex.request.scheme.clone());
            row(
                "Time to headers",
                ex.ttfb_ms.map(human_ms).unwrap_or_else(|| "—".into()),
            );
            row(
                "Total duration",
                ex.duration_ms.map(human_ms).unwrap_or_else(|| "—".into()),
            );
            row("Request body", human_bytes(ex.request.body.len()));
            row(
                "Response body",
                ex.response
                    .as_ref()
                    .map(|r| human_bytes(r.body.len()))
                    .unwrap_or_else(|| "—".into()),
            );
            row(
                "Rules applied",
                if ex.applied_rules.is_empty() {
                    "none".into()
                } else {
                    ex.applied_rules.join(", ")
                },
            );
            row(
                "Intercepted",
                if ex.intercepted {
                    "yes".into()
                } else {
                    "no".into()
                },
            );
            row(
                "Upgraded",
                if ex.upgraded {
                    "yes (WebSocket)".into()
                } else {
                    "no".into()
                },
            );
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
    if fluxrs_core::model::header_value(&ex.request.headers, "accept-encoding").is_some() {
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
}
