//! Where the UI gets its data from: the in-process host.

use fluxrs_model::protocol::{ClientMsg, ServerMsg};

pub trait Backend {
    /// Messages received since the last call.
    fn poll(&mut self) -> Vec<ServerMsg>;
    fn send(&mut self, msg: ClientMsg);
}

pub use native::NativeBackend;

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
    }
}
