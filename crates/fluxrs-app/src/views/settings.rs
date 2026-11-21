//! Settings: capture options and root certificate management.

use crate::app::FluxApp;
use crate::theme::*;
use eframe::egui::{self, RichText};
use fluxrs_core::{CaptureMode, CertificateAuthority, LogLevel};
use std::sync::Arc;

#[derive(Default)]
pub struct SettingsState {
    bypass_text: Option<String>,
    confirm_regenerate: bool,
}

pub fn show(app: &mut FluxApp, ui: &mut egui::Ui) {
    section_title(
        ui,
        "Settings",
        "Capture options apply the next time capture starts.",
    );
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            capture_card(app, ui);
            ui.add_space(12.0);
            certificate_card(app, ui);
            ui.add_space(12.0);
            about_card(ui);
        });
}

fn capture_card(app: &mut FluxApp, ui: &mut egui::Ui) {
    let running = app.is_running();
    let mut changed = false;
    card().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(RichText::new("Capture").size(15.0).strong());
        if running {
            ui.label(RichText::new("Stop capture to change these options.").size(11.5).color(YELLOW));
        }
        ui.add_space(8.0);
        ui.add_enabled_ui(!running, |ui| {
            let e = &mut app.settings.engine;
            egui::Grid::new("capture_grid")
                .num_columns(2)
                .spacing([24.0, 12.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Mode").color(TEXT_DIM));
                    ui.vertical(|ui| {
                        changed |= ui
                            .radio_value(&mut e.mode, CaptureMode::Proxyless, "Proxyless — capture all apps with WinDivert (Windows, admin)")
                            .changed();
                        changed |= ui
                            .radio_value(&mut e.mode, CaptureMode::Proxy, "Explicit proxy — point clients at the proxy address")
                            .changed();
                    });
                    ui.end_row();

                    ui.label(RichText::new("Proxy port").color(TEXT_DIM));
                    ui.horizontal(|ui| {
                        changed |= ui
                            .add(egui::DragValue::new(&mut e.port).range(1024..=65535))
                            .changed();
                        ui.label(RichText::new("Internal port in proxyless mode").size(11.5).color(TEXT_FAINT));
                    });
                    ui.end_row();

                    ui.label(RichText::new("Listen on LAN").color(TEXT_DIM));
                    ui.horizontal(|ui| {
                        changed |= toggle(ui, &mut e.listen_any).changed();
                        ui.label(RichText::new("Explicit proxy only: accept other devices (0.0.0.0)").size(11.5).color(TEXT_FAINT));
                    });
                    ui.end_row();

                    ui.label(RichText::new("Decrypt HTTPS").color(TEXT_DIM));
                    ui.horizontal(|ui| {
                        changed |= toggle(ui, &mut e.decrypt_tls).changed();
                        ui.label(RichText::new("Requires the FluxRS root CA to be trusted").size(11.5).color(TEXT_FAINT));
                    });
                    ui.end_row();

                    ui.label(RichText::new("Accept invalid upstream certs").color(TEXT_DIM));
                    ui.horizontal(|ui| {
                        changed |= toggle(ui, &mut e.insecure_upstream).changed();
                        ui.label(RichText::new("For local servers with self-signed certificates").size(11.5).color(TEXT_FAINT));
                    });
                    ui.end_row();

                    ui.label(RichText::new("Max captured body").color(TEXT_DIM));
                    let mut mb = (e.max_capture_body / (1024 * 1024)).max(1);
                    if ui
                        .add(egui::DragValue::new(&mut mb).range(1..=512).suffix(" MB"))
                        .changed()
                    {
                        e.max_capture_body = mb * 1024 * 1024;
                        changed = true;
                    }
                    ui.end_row();

                    ui.label(RichText::new("Never decrypt").color(TEXT_DIM));
                    ui.vertical(|ui| {
                        let text = app
                            .settings_ui
                            .bypass_text
                            .get_or_insert_with(|| e.bypass_hosts.join("\n"));
                        if ui
                            .add(
                                egui::TextEdit::multiline(text)
                                    .hint_text("*.apple.com\nlogin.example.com")
                                    .desired_rows(4)
                                    .desired_width(360.0)
                                    .font(egui::TextStyle::Monospace),
                            )
                            .changed()
                        {
                            e.bypass_hosts = text
                                .lines()
                                .map(|l| l.trim().to_string())
                                .filter(|l| !l.is_empty())
                                .collect();
                            changed = true;
                        }
                        ui.label(
                            RichText::new("One host per line, wildcards allowed. Use for certificate-pinned apps.")
                                .size(11.5)
                                .color(TEXT_FAINT),
                        );
                    });
                    ui.end_row();
                });
        });
    });
    if changed {
        app.save_settings();
    }
}

fn certificate_card(app: &mut FluxApp, ui: &mut egui::Ui) {
    let ctx = ui.ctx().clone();
    card().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(RichText::new("Root certificate").size(15.0).strong());
        ui.label(
            RichText::new("HTTPS decryption works by signing certificates with this local CA. Install it once; keep the key private.")
                .size(12.0)
                .color(TEXT_DIM),
        );
        ui.add_space(8.0);
        let Some(ca) = app.ca.clone() else {
            ui.label(RichText::new(format!("CA unavailable: {}", app.ca_error.clone().unwrap_or_default())).color(RED));
            return;
        };
        let path = ca.ca_cert_path();
        ui.horizontal(|ui| {
            ui.label(RichText::new("File").color(TEXT_DIM));
            ui.label(RichText::new(path.display().to_string()).monospace());
        });
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            if primary_button(ui, "🛡  Install in Windows trust store", ACCENT).clicked() {
                match ca.install_in_os_store() {
                    Ok(msg) => {
                        app.log(LogLevel::Info, msg.clone());
                        app.toast(&ctx, msg, GREEN);
                    }
                    Err(e) => {
                        app.log(LogLevel::Error, e.to_string());
                        app.toast(&ctx, e.to_string(), RED);
                    }
                }
            }
            if ui.button("📋 Copy PEM").clicked() {
                ctx.copy_text(ca.ca_pem().to_string());
                app.toast(&ctx, "Certificate copied", GREEN);
            }
            if ui.button("📂 Open folder").clicked() {
                open_folder(ca.dir());
            }
            if !app.settings_ui.confirm_regenerate {
                if ui.button("↻ Regenerate").clicked() {
                    app.settings_ui.confirm_regenerate = true;
                }
            } else {
                ui.label(RichText::new("Old certificate stops working. Sure?").color(YELLOW));
                if ui.button(RichText::new("Yes, regenerate").color(RED)).clicked() {
                    app.settings_ui.confirm_regenerate = false;
                    app.stop();
                    match CertificateAuthority::regenerate(ca.dir()) {
                        Ok(new) => {
                            app.ca = Some(Arc::new(new));
                            app.toast(&ctx, "New root CA generated — install it again", YELLOW);
                        }
                        Err(e) => app.toast(&ctx, format!("Regenerate failed: {e}"), RED),
                    }
                }
                if ui.button("Cancel").clicked() {
                    app.settings_ui.confirm_regenerate = false;
                }
            }
        });
        ui.add_space(6.0);
        ui.label(
            RichText::new("Firefox uses its own store: import the file in Settings › Certificates, or enable security.enterprise_roots.enabled.")
                .size(11.5)
                .color(TEXT_FAINT),
        );
        if let Some(e) = &app.engine {
            if app.settings.engine.mode == CaptureMode::Proxy {
                ui.label(
                    RichText::new(format!("Devices can also download it from http://{}/ca.crt through the proxy.", e.local_addr()))
                        .size(11.5)
                        .color(TEXT_FAINT),
                );
            }
        }
    });
}

fn about_card(ui: &mut egui::Ui) {
    card().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            logo(ui, 36.0);
            ui.vertical(|ui| {
                ui.label(RichText::new(format!("FluxRS {}", env!("CARGO_PKG_VERSION"))).size(15.0).strong());
                ui.label(
                    RichText::new("100% Rust HTTP debugger · engine inspired by fluxzy.core · proxyless capture via WinDivert")
                        .size(12.0)
                        .color(TEXT_DIM),
                );
            });
        });
        ui.add_space(6.0);
        ui.label(
            RichText::new("Proxyless notes: needs Administrator, WinDivert.dll + WinDivert64.sys next to fluxrs.exe. QUIC (UDP 443) is blocked during capture so browsers fall back to HTTPS over TCP; IPv6 connections on ports 80/443 fall back to IPv4.")
                .size(11.5)
                .color(TEXT_FAINT),
        );
    });
}

fn open_folder(path: &std::path::Path) {
    #[cfg(windows)]
    let cmd = "explorer";
    #[cfg(target_os = "macos")]
    let cmd = "open";
    #[cfg(all(unix, not(target_os = "macos")))]
    let cmd = "xdg-open";
    let _ = std::process::Command::new(cmd).arg(path).spawn();
}
