//! Rewrite rules editor.

use crate::app::FluxApp;
use crate::theme::{icon, *};
use eframe::egui::{self, Margin, RichText};
use fluxrs_model::{Action, Filter, FilterField, MatchOp, Rule};

#[derive(Default)]
pub struct RulesState {
    pub selected: Option<usize>,
}

pub fn show(app: &mut FluxApp, ui: &mut egui::Ui) {
    if let Some(err) = app.rules_error.clone() {
        banner(
            ui,
            RED,
            icon::CIRCLE_ALERT,
            &format!("{err} — rules are not applied until fixed"),
            None,
        );
        ui.add_space(10.0);
    }

    egui::Panel::left("rule_list")
        .resizable(true)
        .default_size(300.0)
        .size_range(220.0..=480.0)
        .show_separator_line(false)
        .frame(egui::Frame::new().inner_margin(Margin {
            left: 0,
            right: 12,
            top: 0,
            bottom: 0,
        }))
        .show(ui, |ui| rule_list(app, ui));

    egui::CentralPanel::default()
        .frame(egui::Frame::new())
        .show(ui, |ui| match app.rules_ui.selected {
            Some(i) if i < app.rules.len() => rule_editor(app, ui, i),
            _ => {
                card().show(ui, |ui| {
                    ui.set_min_size(ui.available_size());
                    ui.vertical_centered(|ui| {
                        ui.add_space(ui.available_height() * 0.3);
                        ui.label(ico(icon::WAND, 30.0, TEXT_FAINT));
                        ui.label(
                            RichText::new("Select a rule or create a new one").color(TEXT_DIM),
                        );
                    });
                });
            }
        });
}

fn rule_list(app: &mut FluxApp, ui: &mut egui::Ui) {
    let mut changed = false;
    ui.horizontal(|ui| {
        caption(ui, &format!("{} rules", app.rules.len()));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if primary_button(ui, icon::PLUS, "New rule", ACCENT).clicked() {
                app.rules.push(Rule::default());
                app.rules_ui.selected = Some(app.rules.len() - 1);
                changed = true;
            }
        });
    });
    ui.add_space(8.0);
    let mut action: Option<(usize, &'static str)> = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let n = app.rules.len();
            for i in 0..n {
                let selected = app.rules_ui.selected == Some(i);
                let rule = &mut app.rules[i];
                let resp = egui::Frame::new()
                    .fill(if selected { RAISED } else { SURFACE })
                    .stroke(egui::Stroke::new(
                        1.0,
                        if selected { ACCENT } else { BORDER },
                    ))
                    .corner_radius(egui::CornerRadius::from(10u8))
                    .inner_margin(Margin::same(12))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            if toggle(ui, &mut rule.enabled).changed() {
                                changed = true;
                            }
                            ui.add(
                                egui::Label::new(strong(
                                    &rule.name,
                                    13.0,
                                    if rule.enabled { TEXT } else { TEXT_DIM },
                                ))
                                .truncate(),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!(
                                    "{} filter(s) · {} action(s)",
                                    rule.filters.len(),
                                    rule.actions.len()
                                ))
                                .size(11.0)
                                .color(TEXT_FAINT),
                            );
                            if selected {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if icon_button(ui, icon::TRASH, "Delete").clicked() {
                                            action = Some((i, "delete"));
                                        }
                                        if icon_button(ui, icon::COPY_PLUS, "Duplicate").clicked() {
                                            action = Some((i, "dup"));
                                        }
                                        if i + 1 < n
                                            && icon_button(ui, icon::CHEVRON_DOWN, "Move down")
                                                .clicked()
                                        {
                                            action = Some((i, "down"));
                                        }
                                        if i > 0
                                            && icon_button(ui, icon::CHEVRON_UP, "Move up")
                                                .clicked()
                                        {
                                            action = Some((i, "up"));
                                        }
                                    },
                                );
                            }
                        });
                    })
                    .response
                    .interact(egui::Sense::click());
                if resp.clicked() {
                    app.rules_ui.selected = Some(i);
                }
                ui.add_space(6.0);
            }
        });
    if let Some((i, what)) = action {
        match what {
            "delete" => {
                app.rules.remove(i);
                app.rules_ui.selected = if app.rules.is_empty() {
                    None
                } else {
                    Some(i.min(app.rules.len() - 1))
                };
            }
            "dup" => {
                let mut r = app.rules[i].clone();
                r.name = format!("{} (copy)", r.name);
                app.rules.insert(i + 1, r);
                app.rules_ui.selected = Some(i + 1);
            }
            "up" => {
                app.rules.swap(i, i - 1);
                app.rules_ui.selected = Some(i - 1);
            }
            "down" => {
                app.rules.swap(i, i + 1);
                app.rules_ui.selected = Some(i + 1);
            }
            _ => {}
        }
        changed = true;
    }
    if changed {
        app.rules_changed();
    }
}

/// Inline editor for one filter. Returns true when changed.
pub fn filter_editor(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    f: &mut Filter,
) -> bool {
    let mut changed = false;
    ui.push_id(id, |ui| {
        egui::ComboBox::from_id_salt("field")
            .width(110.0)
            .selected_text(f.field.label())
            .show_ui(ui, |ui| {
                for field in FilterField::ALL {
                    changed |= ui
                        .selectable_value(&mut f.field, field, field.label())
                        .changed();
                }
            });
        if f.field == FilterField::RequestHeader {
            changed |= ui
                .add(
                    egui::TextEdit::singleline(&mut f.header_name)
                        .hint_text("Header name")
                        .desired_width(110.0),
                )
                .changed();
        }
        egui::ComboBox::from_id_salt("op")
            .width(110.0)
            .selected_text(f.op.label())
            .show_ui(ui, |ui| {
                for op in MatchOp::ALL {
                    changed |= ui.selectable_value(&mut f.op, op, op.label()).changed();
                }
            });
        changed |= ui
            .add(
                egui::TextEdit::singleline(&mut f.value)
                    .hint_text(match f.op {
                        MatchOp::Regex => "regular expression",
                        _ => "value",
                    })
                    .desired_width(200.0)
                    .font(egui::TextStyle::Monospace),
            )
            .changed();
        changed |= ui
            .toggle_value(&mut f.negate, "NOT")
            .on_hover_text("Invert the match")
            .changed();
        let mut cs = !f.case_insensitive;
        if ui
            .toggle_value(&mut cs, "Aa")
            .on_hover_text("Case sensitive")
            .changed()
        {
            f.case_insensitive = !cs;
            changed = true;
        }
    });
    changed
}

fn text_field(ui: &mut egui::Ui, label: &str, value: &mut String, width: f32) -> bool {
    ui.label(RichText::new(label).color(TEXT_DIM));
    ui.add(
        egui::TextEdit::singleline(value)
            .desired_width(width)
            .font(egui::TextStyle::Monospace),
    )
    .changed()
}

fn body_field(ui: &mut egui::Ui, value: &mut String) -> bool {
    ui.add(
        egui::TextEdit::multiline(value)
            .code_editor()
            .desired_rows(5)
            .desired_width(f32::INFINITY),
    )
    .changed()
}

fn action_editor(ui: &mut egui::Ui, a: &mut Action) -> bool {
    let mut c = false;
    match a {
        Action::SetRequestHeader { name, value } | Action::SetResponseHeader { name, value } => {
            ui.horizontal(|ui| {
                c |= text_field(ui, "Name", name, 180.0);
                c |= text_field(ui, "Value", value, 260.0);
            });
        }
        Action::RemoveRequestHeader { name } | Action::RemoveResponseHeader { name } => {
            ui.horizontal(|ui| c |= text_field(ui, "Name", name, 220.0));
        }
        Action::SetMethod { method } => {
            ui.horizontal(|ui| c |= text_field(ui, "Method", method, 100.0));
        }
        Action::RewritePath { find, replace } => {
            ui.horizontal(|ui| {
                c |= text_field(ui, "Find (regex)", find, 200.0);
                c |= text_field(ui, "Replace", replace, 200.0);
            });
            ui.label(
                RichText::new("Applies to path + query. Use $1, $2… for capture groups.")
                    .size(11.0)
                    .color(TEXT_FAINT),
            );
        }
        Action::RedirectHost { host, port, https } => {
            ui.horizontal(|ui| {
                c |= text_field(ui, "Host", host, 200.0);
                let mut has_port = port.is_some();
                if ui.checkbox(&mut has_port, "Port").changed() {
                    *port = if has_port { Some(8080) } else { None };
                    c = true;
                }
                if let Some(p) = port {
                    c |= ui.add(egui::DragValue::new(p).range(1..=65535)).changed();
                }
                let label = match https {
                    None => "keep scheme",
                    Some(true) => "https",
                    Some(false) => "http",
                };
                egui::ComboBox::from_id_salt("scheme")
                    .selected_text(label)
                    .width(110.0)
                    .show_ui(ui, |ui| {
                        c |= ui.selectable_value(https, None, "keep scheme").changed();
                        c |= ui.selectable_value(https, Some(false), "http").changed();
                        c |= ui.selectable_value(https, Some(true), "https").changed();
                    });
            });
        }
        Action::ReplaceRequestBody { body } | Action::ReplaceResponseBody { body } => {
            c |= body_field(ui, body);
        }
        Action::RequestBodyReplace {
            find,
            replace,
            regex,
        }
        | Action::ResponseBodyReplace {
            find,
            replace,
            regex,
        } => {
            ui.horizontal(|ui| {
                c |= text_field(ui, "Find", find, 200.0);
                c |= text_field(ui, "Replace", replace, 200.0);
                c |= ui.checkbox(regex, "Regex").changed();
            });
            ui.label(
                RichText::new(
                    "Body is decoded (gzip/br/deflate) before replacing; text bodies only.",
                )
                .size(11.0)
                .color(TEXT_FAINT),
            );
        }
        Action::SetResponseStatus { status } => {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Status").color(TEXT_DIM));
                c |= ui
                    .add(egui::DragValue::new(status).range(100..=999))
                    .changed();
            });
        }
        Action::MockResponse {
            status,
            content_type,
            body,
        } => {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Status").color(TEXT_DIM));
                c |= ui
                    .add(egui::DragValue::new(status).range(100..=999))
                    .changed();
                c |= text_field(ui, "Content-Type", content_type, 220.0);
            });
            c |= body_field(ui, body);
        }
        Action::Block => {
            ui.label(
                RichText::new("The connection is closed without contacting the server.")
                    .color(TEXT_DIM),
            );
        }
        Action::Delay { ms } => {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Delay").color(TEXT_DIM));
                c |= ui
                    .add(egui::DragValue::new(ms).range(0..=120_000).suffix(" ms"))
                    .changed();
            });
        }
    }
    c
}

fn rule_editor(app: &mut FluxApp, ui: &mut egui::Ui, idx: usize) {
    let mut changed = false;
    card().show(ui, |ui| {
        ui.set_min_size(ui.available_size());
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let rule = &mut app.rules[idx];
                ui.horizontal(|ui| {
                    changed |= toggle(ui, &mut rule.enabled).changed();
                    changed |= ui
                        .add(
                            egui::TextEdit::singleline(&mut rule.name)
                                .font(sb(18.0))
                                .frame(egui::Frame::NONE)
                                .desired_width(f32::INFINITY),
                        )
                        .changed();
                });
                ui.add_space(12.0);

                // Filters
                caption(ui, "When all filters match");
                ui.add_space(4.0);
                let mut remove_filter = None;
                for (i, f) in rule.filters.iter_mut().enumerate() {
                    ui.horizontal(|ui| {
                        changed |= filter_editor(ui, ("rule_filter", idx, i), f);
                        if icon_button(ui, icon::X, "Remove filter").clicked() {
                            remove_filter = Some(i);
                        }
                    });
                }
                if let Some(i) = remove_filter {
                    rule.filters.remove(i);
                    changed = true;
                }
                if rule.filters.is_empty() {
                    ui.label(
                        RichText::new("No filters: the rule matches every exchange.")
                            .color(YELLOW)
                            .size(12.0),
                    );
                }
                if ghost_button(ui, icon::PLUS, "Add filter").clicked() {
                    rule.filters.push(Filter::default());
                    changed = true;
                }

                ui.add_space(16.0);
                caption(ui, "Then apply actions");
                ui.add_space(4.0);
                let mut remove_action = None;
                for (i, a) in rule.actions.iter_mut().enumerate() {
                    egui::Frame::new()
                        .fill(CODE_BG)
                        .stroke(egui::Stroke::new(1.0, BORDER))
                        .corner_radius(egui::CornerRadius::from(10u8))
                        .inner_margin(Margin::same(12))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                let color = action_color(a);
                                pill(ui, a.kind_label(), color);
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if icon_button(ui, icon::TRASH, "Remove action").clicked() {
                                            remove_action = Some(i);
                                        }
                                    },
                                );
                            });
                            ui.add_space(4.0);
                            ui.push_id(("action", idx, i), |ui| {
                                changed |= action_editor(ui, a);
                            });
                        });
                    ui.add_space(6.0);
                }
                if let Some(i) = remove_action {
                    rule.actions.remove(i);
                    changed = true;
                }
                ui.menu_button(
                    (ico(icon::PLUS, 14.0, TEXT_DIM), RichText::new("Add action")),
                    |ui| {
                        for t in Action::templates() {
                            if ui.button(t.kind_label()).clicked() {
                                rule.actions.push(t);
                                changed = true;
                                ui.close();
                            }
                        }
                    },
                );
            });
    });
    if changed {
        app.rules_changed();
    }
}

fn action_color(a: &Action) -> egui::Color32 {
    match a {
        Action::SetRequestHeader { .. }
        | Action::RemoveRequestHeader { .. }
        | Action::SetMethod { .. }
        | Action::RewritePath { .. }
        | Action::ReplaceRequestBody { .. }
        | Action::RequestBodyReplace { .. } => BLUE,
        Action::SetResponseHeader { .. }
        | Action::RemoveResponseHeader { .. }
        | Action::SetResponseStatus { .. }
        | Action::ReplaceResponseBody { .. }
        | Action::ResponseBodyReplace { .. } => PINK,
        Action::RedirectHost { .. } => CYAN,
        Action::MockResponse { .. } => GREEN,
        Action::Block => RED,
        Action::Delay { .. } => YELLOW,
    }
}
