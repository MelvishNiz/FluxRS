//! Settings: HTTPS certificate, capture options, about.

use crate::app::FluxApp;
use crate::theme::{icon, *};
use eframe::egui::{self, Margin, RichText, Stroke};
use fluxrs_model::{CaptureMode, TrustStatus};

#[derive(Default)]
pub struct SettingsState {
    bypass_text: Option<String>,
    confirm_regenerate: bool,
}

pub fn show(app: &mut FluxApp, ui: &mut egui::Ui) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let width = ui.available_width().min(980.0);
            ui.set_max_width(width);
            certificate_card(app, ui);
            ui.add_space(14.0);
            capture_card(app, ui);
            ui.add_space(14.0);
            about_card(ui);
        });
}

fn card_title(ui: &mut egui::Ui, ic: &str, title: &str, subtitle: &str) {
    ui.horizontal(|ui| {
        egui::Frame::new()
            .fill(ACCENT_SOFT)
            .corner_radius(egui::CornerRadius::from(8u8))
            .inner_margin(Margin::same(7))
            .show(ui, |ui| {
                ui.label(ico(ic, 16.0, ACCENT_HI));
            });
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.label(strong(title, 15.0, TEXT));
            ui.label(RichText::new(subtitle).size(12.0).color(TEXT_DIM));
        });
    });
    ui.add_space(12.0);
}

/// One settings row: label + description on the left, control on the right.
fn row(ui: &mut egui::Ui, label: &str, help: &str, control: impl FnOnce(&mut egui::Ui)) {
    ui.separator();
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.set_width((ui.available_width() * 0.5).min(420.0));
            ui.spacing_mut().item_spacing.y = 1.0;
            ui.label(strong(label, 13.0, TEXT));
            if !help.is_empty() {
                ui.label(RichText::new(help).size(12.0).color(TEXT_FAINT));
            }
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), control);
    });
    ui.add_space(4.0);
}

fn certificate_card(app: &mut FluxApp, ui: &mut egui::Ui) {
    let ctx = ui.ctx().clone();
    card().show(ui, |ui| {
        ui.set_width(ui.available_width());
        card_title(
            ui,
            icon::KEY,
            "HTTPS decryption",
            "FluxRS signs a certificate for each site with a local root CA that only this PC knows.",
        );
        let Some(ca) = app.ca.clone() else {
            ui.label(
                RichText::new(format!(
                    "Root CA unavailable: {}",
                    app.ca_error.clone().unwrap_or_default()
                ))
                .color(RED),
            );
            return;
        };

        let trust = app.ca_trust();
        let (color, ic, title, text) = match trust {
            Some(TrustStatus::Trusted) => (
                GREEN,
                icon::SHIELD_CHECK,
                "Root certificate is trusted",
                "Browsers and apps accept the certificates FluxRS presents.",
            ),
            Some(TrustStatus::NotTrusted) => (
                YELLOW,
                icon::SHIELD_ALERT,
                "Root certificate is not trusted yet",
                "Install it once so HTTPS traffic can be decrypted.",
            ),
            Some(TrustStatus::Unknown) => (
                TEXT_DIM,
                icon::INFO,
                "Trust status unknown on this OS",
                "Import the certificate file into your system or browser store.",
            ),
            None => (
                TEXT_DIM,
                icon::CLOCK,
                "Checking the system certificate store…",
                "",
            ),
        };
        egui::Frame::new()
            .fill(color.gamma_multiply(0.07))
            .stroke(Stroke::new(1.0, color.gamma_multiply(0.3)))
            .corner_radius(egui::CornerRadius::from(10u8))
            .inner_margin(Margin::same(14))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(ico(ic, 26.0, color));
                    ui.add_space(4.0);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 1.0;
                        ui.label(strong(title, 14.0, TEXT));
                        ui.label(RichText::new(text).size(12.5).color(TEXT_DIM));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if trust != Some(TrustStatus::Trusted)
                            && primary_button(
                                ui,
                                icon::SHIELD_CHECK,
                                if app.is_local() {
                                    "Install certificate"
                                } else {
                                    "Install on host"
                                },
                                ACCENT,
                            )
                                .clicked()
                        {
                            app.install_ca(&ctx);
                        }
                        if icon_button(ui, icon::REFRESH, "Check again").clicked() {
                            app.refresh_ca_trust(&ctx);
                        }
                    });
                });
            });
        ui.add_space(12.0);

        ui.horizontal(|ui| {
            ui.label(RichText::new("File").color(TEXT_DIM));
            ui.add(
                egui::Label::new(
                    RichText::new(ca.path.clone())
                        .font(mono(12.0))
                        .color(TEXT),
                )
                .truncate(),
            );
        });
        ui.horizontal(|ui| {
            ui.label(RichText::new("Serial").color(TEXT_DIM));
            ui.label(RichText::new(ca.serial.clone()).font(mono(12.0)).color(TEXT_DIM));
        });
        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            if ghost_button(ui, icon::COPY, "Copy PEM").clicked() {
                ctx.copy_text(ca.pem.clone());
                app.toast(&ctx, "Certificate copied", GREEN);
            }
            #[cfg(not(target_arch = "wasm32"))]
            if app.is_local() && ghost_button(ui, icon::FOLDER_OPEN, "Open folder").clicked() {
                if let Some(dir) = std::path::Path::new(&ca.path).parent() {
                    open_folder(dir);
                }
            }
            #[cfg(target_arch = "wasm32")]
            ui.hyperlink_to(
                RichText::new("Download certificate").color(ACCENT_HI),
                "/ca.crt",
            );
            if !app.settings_ui.confirm_regenerate {
                if ghost_button(ui, icon::ROTATE_CCW, "Regenerate").clicked() {
                    app.settings_ui.confirm_regenerate = true;
                }
            } else {
                ui.label(RichText::new("The old certificate stops working. Continue?").color(YELLOW));
                if primary_button(ui, icon::ROTATE_CCW, "Regenerate", RED).clicked() {
                    app.settings_ui.confirm_regenerate = false;
                    app.regenerate_ca();
                }
                if ghost_button(ui, icon::X, "Cancel").clicked() {
                    app.settings_ui.confirm_regenerate = false;
                }
            }
        });
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(ico(icon::INFO, 12.0, TEXT_FAINT));
            ui.label(
                RichText::new(
                    "Firefox keeps its own store: import the file under Settings › Certificates, or set security.enterprise_roots.enabled to true.",
                )
                .size(11.5)
                .color(TEXT_FAINT),
            );
        });
        if let Some(addr) = app.local_addr().map(str::to_string) {
            if app.settings.engine.mode == CaptureMode::Proxy {
                ui.horizontal_wrapped(|ui| {
                    ui.label(ico(icon::INFO, 12.0, TEXT_FAINT));
                    ui.label(
                        RichText::new(format!(
                            "Other devices can download it from http://{addr}/ca.crt through the proxy."
                        ))
                        .size(11.5)
                        .color(TEXT_FAINT),
                    );
                });
            }
        }
    });
}

fn capture_card(app: &mut FluxApp, ui: &mut egui::Ui) {
    let running = app.is_running();
    let mut changed = false;
    card().show(ui, |ui| {
        ui.set_width(ui.available_width());
        card_title(
            ui,
            icon::NETWORK,
            "Capture",
            if running {
                "Stop capture to change these options."
            } else {
                "Applied the next time capture starts."
            },
        );
        ui.add_enabled_ui(!running, |ui| {
            let e = &mut app.settings.engine;
            row(
                ui,
                "Capture mode",
                "Proxyless captures every app (WinDivert on Windows, iptables on Linux; needs admin rights). Proxy needs client configuration.",
                |ui| {
                    changed |= segmented(
                        ui,
                        &mut e.mode,
                        &[
                            (CaptureMode::Proxy, Some(icon::GLOBE), "Proxy"),
                            (CaptureMode::Proxyless, Some(icon::ZAP), "Proxyless"),
                        ],
                    );
                },
            );
            row(
                ui,
                "Port",
                "Explicit proxy port, or the internal port in proxyless mode.",
                |ui| {
                    changed |= ui
                        .add(egui::DragValue::new(&mut e.port).range(1024..=65535))
                        .changed();
                },
            );
            row(
                ui,
                "Decrypt HTTPS",
                "Show HTTPS content. Requires the trusted root certificate.",
                |ui| {
                    changed |= toggle(ui, &mut e.decrypt_tls).changed();
                },
            );
            row(
                ui,
                "Accept invalid server certificates",
                "For local servers with self-signed certificates.",
                |ui| {
                    changed |= toggle(ui, &mut e.insecure_upstream).changed();
                },
            );
            row(
                ui,
                "Listen on the network",
                "Explicit proxy only: allow other devices (binds 0.0.0.0).",
                |ui| {
                    changed |= toggle(ui, &mut e.listen_any).changed();
                },
            );
            row(
                ui,
                "Max captured body",
                "Larger bodies are forwarded fully but stored truncated.",
                |ui| {
                    let mut mb = (e.max_capture_body / (1024 * 1024)).max(1);
                    if ui
                        .add(egui::DragValue::new(&mut mb).range(1..=512).suffix(" MB"))
                        .changed()
                    {
                        e.max_capture_body = mb * 1024 * 1024;
                        changed = true;
                    }
                },
            );
            ui.separator();
            ui.add_space(4.0);
            ui.label(strong("Never decrypt these hosts", 13.0, TEXT));
            ui.label(
                RichText::new("One per line, wildcards allowed. Use for certificate-pinned apps.")
                    .size(12.0)
                    .color(TEXT_FAINT),
            );
            ui.add_space(4.0);
            let text = app
                .settings_ui
                .bypass_text
                .get_or_insert_with(|| e.bypass_hosts.join("\n"));
            if ui
                .add(
                    egui::TextEdit::multiline(text)
                        .hint_text("*.apple.com\nlogin.example.com")
                        .desired_rows(4)
                        .desired_width(f32::INFINITY)
                        .font(mono(12.5)),
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
        });
    });
    if changed {
        app.save_settings();
    }
}

fn about_card(ui: &mut egui::Ui) {
    card().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            logo(ui, 40.0);
            ui.add_space(4.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                ui.horizontal(|ui| {
                    ui.label(strong("FluxRS", 15.0, TEXT));
                    pill(ui, format!("v{}", env!("CARGO_PKG_VERSION")), ACCENT_HI);
                });
                ui.label(
                    RichText::new(
                        "100% Rust HTTP debugger · engine modeled on fluxzy.core · proxyless capture via WinDivert / iptables",
                    )
                    .size(12.0)
                    .color(TEXT_DIM),
                );
            });
        });
        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(ico(icon::INFO, 12.0, TEXT_FAINT));
            ui.label(
                RichText::new(
                    "Proxyless on Windows needs Administrator and WinDivert.dll + WinDivert64.sys next to fluxrs.exe; on Linux it adds iptables rules through pkexec and removes them on stop. QUIC (UDP 443) is blocked while capturing so browsers use HTTPS over TCP; IPv6 connections to ports 80/443 fall back to IPv4.",
                )
                .size(11.5)
                .color(TEXT_FAINT),
            );
        });
    });
}

#[cfg(not(target_arch = "wasm32"))]
fn open_folder(path: &std::path::Path) {
    #[cfg(windows)]
    let cmd = "explorer";
    #[cfg(target_os = "macos")]
    let cmd = "open";
    #[cfg(all(unix, not(target_os = "macos")))]
    let cmd = "xdg-open";
    let _ = std::process::Command::new(cmd).arg(path).spawn();
}
