//! FluxRS core: a Rust HTTP(S) debugging engine inspired by fluxzy.core.
//!
//! * MITM proxy with on-the-fly certificates (`cert`)
//! * Proxyless capture on Windows through WinDivert (`nat`, `divert`)
//! * Rewrite rules (`rules`) and breakpoints (`intercept`)

pub mod body;
pub mod cert;
#[cfg(windows)]
pub mod divert;
pub mod engine;
pub mod events;
#[cfg(windows)]
mod firewall;
pub mod intercept;
pub mod io;
pub mod model;
pub mod nat;
pub mod rawhttp;
pub mod rules;
pub mod tls;
pub mod tlsinfo;

pub use cert::{CertificateAuthority, TrustStatus};
pub use engine::{CaptureMode, Engine, EngineConfig, RulesHandle};
pub use events::{EventSink, LogLevel, ProxyEvent};
pub use intercept::{Decision, InterceptConfig, InterceptPhase, InterceptTicket, Interceptor};
pub use model::{
    CertSummary, Exchange, ExchangeId, ExchangeState, HeaderList, RequestData, ResponseData,
    TlsInfo,
};
pub use rules::{Action, Filter, FilterField, MatchOp, Rule};
