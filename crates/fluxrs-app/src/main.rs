//! FluxRS - proxyless HTTP debugger written in Rust.
//!
//! Desktop app (Windows / Linux), headless web server (`--serve`) and the
//! same UI compiled to WebAssembly for the browser.

#![cfg_attr(
    all(not(debug_assertions), not(target_arch = "wasm32")),
    windows_subsystem = "windows"
)]

mod app;
mod backend;
#[cfg(not(target_arch = "wasm32"))]
mod host;
#[cfg(target_arch = "wasm32")]
mod remote;
#[cfg(not(target_arch = "wasm32"))]
mod server;
#[cfg(not(target_arch = "wasm32"))]
mod store;
mod theme;
mod views;

#[cfg(not(target_arch = "wasm32"))]
fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

#[cfg(not(target_arch = "wasm32"))]
fn main() -> eframe::Result<()> {
    use eframe::egui;

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();
    let args: Vec<String> = std::env::args().collect();

    #[cfg(target_os = "linux")]
    {
        // `fluxrs --cleanup` removes iptables rules left by a crashed session.
        if args.iter().any(|a| a == "--cleanup") {
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
    }

    if args.iter().any(|a| a == "--serve") {
        return serve(&args);
    }

    #[cfg(target_os = "linux")]
    {
        // Desktop: clean up on kill / Ctrl+C / logout too.
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
        Box::new(move |cc| {
            let backend = Box::new(backend::NativeBackend::new(&cc.egui_ctx));
            let mut app = app::FluxApp::new(cc, backend);
            app.apply_args(&args, &cc.egui_ctx);
            Ok(Box::new(app))
        }),
    )
}

/// `fluxrs --serve [--listen 127.0.0.1:8800] [--web-root DIR] [--token T]`
#[cfg(not(target_arch = "wasm32"))]
fn serve(args: &[String]) -> eframe::Result<()> {
    let listen = arg_value(args, "--listen").unwrap_or_else(|| "127.0.0.1:8800".into());
    let listen = match listen.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("invalid --listen address '{listen}': {e}");
            std::process::exit(2);
        }
    };
    let web_root = arg_value(args, "--web-root")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(default_web_root);
    let token = arg_value(args, "--token").unwrap_or_else(server::random_token);
    if let Err(e) = server::run(server::ServeOptions {
        listen,
        web_root,
        token,
    }) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
    Ok(())
}

/// `web/` next to the executable, else the Linux package location.
#[cfg(not(target_arch = "wasm32"))]
fn default_web_root() -> std::path::PathBuf {
    let beside_exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("web")));
    let candidates = [beside_exe, Some("/usr/share/fluxrs/web".into())];
    candidates
        .iter()
        .flatten()
        .find(|d| d.join("index.html").exists())
        .cloned()
        .unwrap_or_else(|| "web".into())
}

#[cfg(target_arch = "wasm32")]
fn main() {
    use eframe::wasm_bindgen::JsCast as _;

    wasm_bindgen_futures::spawn_local(async {
        let document = web_sys::window()
            .expect("window")
            .document()
            .expect("document");
        let canvas = document
            .get_element_by_id("fluxrs_canvas")
            .expect("canvas #fluxrs_canvas")
            .dyn_into::<web_sys::HtmlCanvasElement>()
            .expect("canvas element");
        let result = eframe::WebRunner::new()
            .start(
                canvas,
                eframe::WebOptions::default(),
                Box::new(|cc| {
                    let url = remote::default_url();
                    let backend = Box::new(remote::RemoteBackend::new(url, &cc.egui_ctx));
                    Ok(Box::new(app::FluxApp::new(cc, backend)))
                }),
            )
            .await;
        if let Some(loading) = document.get_element_by_id("loading") {
            match result {
                Ok(()) => loading.remove(),
                Err(e) => loading.set_inner_html(&format!("FluxRS failed to start: {e:?}")),
            }
        }
    });
}
