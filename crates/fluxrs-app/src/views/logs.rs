use crate::app::FluxApp;
use crate::theme::{icon, *};
use eframe::egui::{self, RichText};
use fluxrs_core::LogLevel;

pub fn show(app: &mut FluxApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        caption(ui, &format!("{} entries · times in UTC", app.logs.len()));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ghost_button(ui, icon::TRASH, "Clear").clicked() {
                app.logs.clear();
            }
        });
    });
    ui.add_space(8.0);
    card().show(ui, |ui| {
        ui.set_min_size(ui.available_size());
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                if app.logs.is_empty() {
                    ui.label(RichText::new("No log entries yet.").color(TEXT_FAINT));
                }
                for l in &app.logs {
                    let (tag, c) = match l.level {
                        LogLevel::Info => ("INFO", BLUE),
                        LogLevel::Warn => ("WARN", YELLOW),
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
                        ui.label(RichText::new(clock).font(mono(12.0)).color(TEXT_FAINT));
                        ui.add_sized(
                            [46.0, 18.0],
                            egui::Label::new(RichText::new(tag).font(mono(11.5)).color(c)),
                        );
                        ui.label(RichText::new(&l.text).font(mono(12.0)).color(TEXT));
                    });
                }
            });
    });
}
