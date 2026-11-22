//! Breakpoints: queue of paused requests/responses with a raw editor.

use crate::app::FluxApp;
use crate::theme::{icon, *};
use crate::views::rules::filter_editor;
use eframe::egui::{self, Margin, RichText, Stroke};
use fluxrs_model::{Decision, InterceptPhase};

#[derive(Default)]
pub struct InterceptState {
    pub selected: usize,
}

fn phase_pill(ui: &mut egui::Ui, phase: InterceptPhase) {
    match phase {
        InterceptPhase::Request => pill(ui, "REQUEST", BLUE),
        InterceptPhase::Response => pill(ui, "RESPONSE", PINK),
    };
}

pub fn show(app: &mut FluxApp, ui: &mut egui::Ui) {
    config_card(app, ui);
    ui.add_space(14.0);

    if app.tickets.is_empty() {
        card().show(ui, |ui| {
            ui.set_min_size(ui.available_size());
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() * 0.28);
                egui::Frame::new()
                    .fill(ACCENT_SOFT)
                    .corner_radius(egui::CornerRadius::from(14u8))
                    .inner_margin(Margin::same(14))
                    .show(ui, |ui| {
                        ui.label(ico(icon::PAUSE, 26.0, ACCENT_HI));
                    });
                ui.add_space(12.0);
                ui.label(strong("Nothing is paused", 18.0, TEXT));
                ui.add_space(2.0);
                ui.label(
                    RichText::new(if app.settings.intercept.enabled {
                        "Waiting for traffic that matches the breakpoint filter…"
                    } else {
                        "Turn on breakpoints to pause matching traffic here."
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
        .default_size(330.0)
        .size_range(240.0..=520.0)
        .show_separator_line(false)
        .frame(egui::Frame::new().inner_margin(Margin {
            left: 0,
            right: 12,
            top: 0,
            bottom: 0,
        }))
        .show(ui, |ui| ticket_list(app, ui));

    egui::CentralPanel::default()
        .frame(egui::Frame::new())
        .show(ui, |ui| editor(app, ui));
}

fn config_card(app: &mut FluxApp, ui: &mut egui::Ui) {
    card()
        .inner_margin(Margin::symmetric(16, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let mut changed = false;
            ui.horizontal(|ui| {
                let cfg = &mut app.settings.intercept;
                changed |= toggle(ui, &mut cfg.enabled).changed();
                ui.label(strong("Breakpoints", 13.0, TEXT));
                ui.add_space(14.0);
                ui.separator();
                ui.add_space(6.0);
                ui.label(RichText::new("Pause").color(TEXT_DIM));
                changed |= ui.checkbox(&mut cfg.requests, "Requests").changed();
                changed |= ui.checkbox(&mut cfg.responses, "Responses").changed();
                ui.add_space(10.0);
                ui.label(RichText::new("when").color(TEXT_DIM));
                changed |= filter_editor(ui, "intercept_filter", &mut cfg.filter);
            });
            if let Some(err) = &app.intercept_error {
                ui.label(RichText::new(err).color(RED));
            } else if app.settings.intercept.filter.value.is_empty() {
                ui.horizontal(|ui| {
                    ui.label(ico(icon::INFO, 12.0, TEXT_FAINT));
                    ui.label(
                        RichText::new("Empty filter value pauses every exchange.")
                            .size(11.5)
                            .color(TEXT_FAINT),
                    );
                });
            }
            if changed {
                app.intercept_changed();
            }
        });
}

fn ticket_list(app: &mut FluxApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        caption(ui, &format!("Paused · {}", app.tickets.len()));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ghost_button(ui, icon::SEND, "Forward all").clicked() {
                app.release_all_tickets();
            }
        });
    });
    ui.add_space(6.0);
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let mut clicked = None;
            for (i, t) in app.tickets.iter().enumerate() {
                let ticket = &t.info;
                let selected = i == app.intercept_ui.selected;
                let resp = egui::Frame::new()
                    .fill(if selected { RAISED } else { SURFACE })
                    .stroke(Stroke::new(1.0, if selected { ACCENT } else { BORDER }))
                    .corner_radius(egui::CornerRadius::from(10u8))
                    .inner_margin(Margin::same(12))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            phase_pill(ui, ticket.phase);
                            ui.label(
                                RichText::new(format!("#{}", ticket.exchange_id))
                                    .size(11.0)
                                    .color(TEXT_FAINT),
                            );
                            if t.edited != ticket.raw {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        pill(ui, "edited", YELLOW);
                                    },
                                );
                            }
                        });
                        ui.add_space(4.0);
                        ui.add(
                            egui::Label::new(
                                RichText::new(&ticket.title).font(mono(12.0)).color(TEXT),
                            )
                            .truncate(),
                        );
                    })
                    .response
                    .interact(egui::Sense::click());
                if resp.hovered() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
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
        let ticket = pending.info.clone();
        ui.horizontal(|ui| {
            phase_pill(ui, ticket.phase);
            ui.add(
                egui::Label::new(RichText::new(&ticket.title).font(mono(12.5)).color(TEXT))
                    .truncate(),
            );
        });
        if ticket.binary_body {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(ico(icon::INFO, 12.0, YELLOW));
                ui.label(
                    RichText::new(
                        "Binary body shown as a placeholder. Keep that line to send the original bytes.",
                    )
                    .size(11.5)
                    .color(YELLOW),
                );
            });
        }
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if primary_button(ui, icon::SEND, "Forward", GREEN)
                .on_hover_text("Ctrl+Enter")
                .clicked()
            {
                action = Some(Decision::Forward(Some(pending.edited.clone())));
            }
            if primary_button(ui, icon::BAN, "Drop", RED).clicked() {
                action = Some(Decision::Drop);
            }
            ui.add_space(6.0);
            if ghost_button(ui, icon::ROTATE_CCW, "Reset edits").clicked() {
                pending.edited = ticket.raw.clone();
            }
            if ghost_button(ui, icon::PLAY, "Forward unchanged").clicked() {
                action = Some(Decision::Forward(None));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new("Ctrl+Enter to forward").size(11.5).color(TEXT_FAINT));
            });
        });
        ui.add_space(10.0);
        egui::Frame::new()
            .fill(CODE_BG)
            .stroke(Stroke::new(1.0, BORDER))
            .corner_radius(egui::CornerRadius::from(9u8))
            .inner_margin(Margin::same(4))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt(("ticket_editor", ticket.ticket_id))
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_sized(
                            ui.available_size(),
                            egui::TextEdit::multiline(&mut pending.edited)
                                .font(mono(12.5))
                                .code_editor()
                                .frame(egui::Frame::NONE)
                                .desired_width(f32::INFINITY)
                                .lock_focus(true),
                        );
                    });
            });
        if ctrl_enter && action.is_none() {
            action = Some(Decision::Forward(Some(pending.edited.clone())));
        }
    });
    if let Some(decision) = action {
        app.resolve_ticket(idx, decision);
    }
}
