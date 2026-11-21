//! FluxRS - modern proxyless HTTP debugger (Windows), written in Rust.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod store;
mod theme;
mod views;

use eframe::egui;

fn main() -> eframe::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("FluxRS — HTTP Debugger")
            .with_inner_size([1440.0, 900.0])
            .with_min_inner_size([1024.0, 640.0])
            .with_icon(std::sync::Arc::new(theme::window_icon())),
        ..Default::default()
    };
    eframe::run_native(
        "FluxRS",
        options,
        Box::new(|cc| Ok(Box::new(app::FluxApp::new(cc)))),
    )
}
