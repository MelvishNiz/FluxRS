//! Where the UI gets its data from: an in-process host (desktop) or a
//! remote host over WebSocket (browser).

use fluxrs_model::protocol::{ClientMsg, ServerMsg};

pub trait Backend {
    /// Messages received since the last call.
    fn poll(&mut self) -> Vec<ServerMsg>;
    fn send(&mut self, msg: ClientMsg);
    /// Desktop app with direct access to the host machine.
    fn is_local(&self) -> bool;
    /// Connection state for remote backends (`None` for local).
    fn connection(&self) -> Option<ConnectionState> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Only remote (browser) backends construct the non-connected states.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub enum ConnectionState {
    Connecting,
    Connected,
    Disconnected(String),
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::NativeBackend;

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use crate::host::Host;

    pub struct NativeBackend {
        host: Host,
        hello_sent: bool,
    }

    impl NativeBackend {
        pub fn new(ctx: &eframe::egui::Context) -> Self {
            let ctx = ctx.clone();
            NativeBackend {
                host: Host::new(std::sync::Arc::new(move || ctx.request_repaint())),
                hello_sent: false,
            }
        }
    }

    impl Backend for NativeBackend {
        fn poll(&mut self) -> Vec<ServerMsg> {
            let mut out = Vec::new();
            if !self.hello_sent {
                self.hello_sent = true;
                out.push(self.host.hello());
            }
            out.extend(self.host.poll());
            out
        }

        fn send(&mut self, msg: ClientMsg) {
            self.host.handle(msg);
        }

        fn is_local(&self) -> bool {
            true
        }
    }
}
