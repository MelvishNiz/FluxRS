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

    #[cfg(target_os = "linux")]
    {
        // `fluxrs --cleanup` removes iptables rules left by a crashed session.
        if std::env::args().any(|a| a == "--cleanup") {
            match fluxrs_core::netfilter::cleanup_all() {
                Ok(()) => println!("FluxRS iptables rules removed."),
                Err(e) => eprintln!("cleanup failed: {e}"),
            }
            return Ok(());
        }
        // Never leave traffic redirected to a dead proxy after a panic.
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            fluxrs_core::netfilter::emergency_cleanup();
            default_hook(info);
        }));
        // Same on kill / Ctrl+C / logout.
        use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
        if let Ok(mut signals) = signal_hook::iterator::Signals::new([SIGTERM, SIGINT, SIGHUP]) {
            std::thread::spawn(move || {
                if let Some(sig) = signals.forever().next() {
                    fluxrs_core::netfilter::emergency_cleanup();
                    std::process::exit(128 + sig);
                }
            });
        }
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("FluxRS — HTTP Debugger")
            .with_app_id("fluxrs")
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
