use crate::app::FluxApp;
use crate::theme::*;
use eframe::egui::{self, RichText};
use fluxrs_core::LogLevel;

pub fn show(app: &mut FluxApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        section_title(ui, "Logs", "Engine diagnostics, TLS errors and warnings");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("🗑  Clear").clicked() {
                app.logs.clear();
            }
        });
    });
    card().show(ui, |ui| {
        ui.set_width(ui.available_width());
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                if app.logs.is_empty() {
                    ui.label(RichText::new("No log entries yet.").color(TEXT_FAINT));
                }
                for l in &app.logs {
                    let (tag, c) = match l.level {
                        LogLevel::Info => ("INFO ", BLUE),
                        LogLevel::Warn => ("WARN ", YELLOW),
                        LogLevel::Error => ("ERROR", RED),
                    };
                    let t = l
                        .time
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let clock =
                        format!("{:02}:{:02}:{:02}", (t / 3600) % 24, (t / 60) % 60, t % 60);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(clock).monospace().color(TEXT_FAINT));
                        ui.label(RichText::new(tag).monospace().color(c).strong());
                        ui.label(RichText::new(&l.text).monospace());
                    });
                }
            });
    });
}
