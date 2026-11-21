//! Breakpoints: queue of paused requests/responses with a raw editor.

use crate::app::FluxApp;
use crate::theme::*;
use crate::views::rules::filter_editor;
use eframe::egui::{self, Margin, RichText};
use fluxrs_core::{Decision, InterceptPhase};

#[derive(Default)]
pub struct InterceptState {
    pub selected: usize,
}

pub fn show(app: &mut FluxApp, ui: &mut egui::Ui) {
    section_title(
        ui,
        "Intercept",
        "Pause matching requests or responses, edit them as raw HTTP, then forward or drop.",
    );
    config_card(app, ui);
    ui.add_space(10.0);

    if app.tickets.is_empty() {
        card().show(ui, |ui| {
            ui.set_min_size(ui.available_size());
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() * 0.25);
                ui.label(RichText::new("⏸").size(40.0).color(TEXT_FAINT));
                ui.add_space(6.0);
                ui.label(RichText::new("Nothing is paused").size(18.0).strong());
                ui.label(
                    RichText::new(if app.settings.intercept.enabled {
                        "Waiting for traffic matching the breakpoint filter…"
                    } else {
                        "Turn on breakpoints to pause traffic here."
                    })
                    .color(TEXT_DIM),
                );
            });
        });
        return;
    }
    if app.intercept_ui.selected >= app.tickets.len() {
        app.intercept_ui.selected = app.tickets.len() - 1;
    }

    egui::Panel::left("ticket_list")
        .resizable(true)
        .default_size(320.0)
        .size_range(220.0..=520.0)
        .frame(egui::Frame::new().inner_margin(Margin {
            left: 0,
            right: 10,
            top: 0,
            bottom: 0,
        }))
        .show(ui, |ui| ticket_list(app, ui));

    egui::CentralPanel::default()
        .frame(egui::Frame::new())
        .show(ui, |ui| editor(app, ui));
}

fn config_card(app: &mut FluxApp, ui: &mut egui::Ui) {
    card().show(ui, |ui| {
        ui.set_width(ui.available_width());
        let mut changed = false;
        ui.horizontal(|ui| {
            let cfg = &mut app.settings.intercept;
            changed |= toggle(ui, &mut cfg.enabled).changed();
            ui.label(RichText::new("Breakpoints enabled").strong());
            ui.add_space(16.0);
            changed |= ui.checkbox(&mut cfg.requests, "Requests").changed();
            changed |= ui.checkbox(&mut cfg.responses, "Responses").changed();
            ui.add_space(16.0);
            ui.label(RichText::new("Only when").color(TEXT_DIM));
            changed |= filter_editor(ui, "intercept_filter", &mut cfg.filter);
        });
        if let Some(err) = &app.intercept_error {
            ui.label(RichText::new(err).color(RED));
        } else if app.settings.intercept.filter.value.is_empty() {
            ui.label(
                RichText::new("Empty filter value = pause every exchange.")
                    .size(11.5)
                    .color(TEXT_FAINT),
            );
        }
        if changed {
            app.intercept_changed();
        }
    });
}

fn ticket_list(app: &mut FluxApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("PAUSED ({})", app.tickets.len()))
                .size(11.0)
                .color(TEXT_FAINT)
                .strong(),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.small_button("Forward all").clicked() {
                app.release_all_tickets();
            }
        });
    });
    ui.add_space(4.0);
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let mut clicked = None;
            for (i, t) in app.tickets.iter().enumerate() {
                let Some(ticket) = &t.ticket else { continue };
                let selected = i == app.intercept_ui.selected;
                let resp = egui::Frame::new()
                    .fill(if selected { ACCENT_SOFT } else { SURFACE })
                    .stroke(egui::Stroke::new(
                        1.0,
                        if selected { ACCENT } else { BORDER },
                    ))
                    .corner_radius(egui::CornerRadius::from(10u8))
                    .inner_margin(Margin::same(10))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            match ticket.phase {
                                InterceptPhase::Request => pill(ui, "REQUEST", BLUE),
                                InterceptPhase::Response => pill(ui, "RESPONSE", PINK),
                            };
                            ui.label(
                                RichText::new(format!("#{}", ticket.exchange_id))
                                    .size(11.0)
                                    .color(TEXT_FAINT),
                            );
                            if t.edited != ticket.raw {
                                ui.label(RichText::new("edited").size(11.0).color(YELLOW));
                            }
                        });
                        ui.add(
                            egui::Label::new(RichText::new(&ticket.title).monospace().size(12.0))
                                .truncate(),
                        );
                    })
                    .response
                    .interact(egui::Sense::click());
                if resp.clicked() {
                    clicked = Some(i);
                }
                ui.add_space(6.0);
            }
            if let Some(i) = clicked {
                app.intercept_ui.selected = i;
            }
        });
}

fn editor(app: &mut FluxApp, ui: &mut egui::Ui) {
    let idx = app.intercept_ui.selected;
    let mut action: Option<Decision> = None;
    // Consume Ctrl+Enter before the text editor sees it (no stray newline).
    let ctrl_enter = ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter));
    card().show(ui, |ui| {
        ui.set_min_size(ui.available_size());
        let pending = &mut app.tickets[idx];
        let Some(ticket) = &pending.ticket else { return };
        ui.horizontal(|ui| {
            match ticket.phase {
                InterceptPhase::Request => pill(ui, "REQUEST", BLUE),
                InterceptPhase::Response => pill(ui, "RESPONSE", PINK),
            };
            ui.add(egui::Label::new(RichText::new(&ticket.title).monospace().strong()).truncate());
        });
        if ticket.binary_body {
            ui.label(
                RichText::new("Binary body is shown as a placeholder — keep the placeholder line to send the original bytes.")
                    .size(11.5)
                    .color(YELLOW),
            );
        }
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if primary_button(ui, "▶  Forward", GREEN)
                .on_hover_text("Ctrl+Enter")
                .clicked()
            {
                action = Some(Decision::Forward(Some(pending.edited.clone())));
            }
            if primary_button(ui, "✖  Drop", RED).clicked() {
                action = Some(Decision::Drop);
            }
            if ui
                .button("↺  Reset edits")
                .on_hover_text("Restore the original message")
                .clicked()
            {
                pending.edited = ticket.raw.clone();
            }
            if ui.button("Forward unchanged").clicked() {
                action = Some(Decision::Forward(None));
            }
        });
        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .id_salt(("ticket_editor", ticket.ticket_id))
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_sized(
                    ui.available_size(),
                    egui::TextEdit::multiline(&mut pending.edited)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .lock_focus(true),
                );
            });
        if ctrl_enter && action.is_none() {
            action = Some(Decision::Forward(Some(pending.edited.clone())));
        }
    });
    if let Some(decision) = action {
        app.resolve_ticket(idx, decision);
    }
}
