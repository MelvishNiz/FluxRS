//! Data model shared by the FluxRS engine, the desktop app and the web UI.
//!
//! Pure data + serde: compiles for native targets and `wasm32`.

pub mod codec;
pub mod config;
pub mod exchange;
pub mod intercept;
pub mod protocol;
pub mod rules;

pub use config::{CaptureMode, EngineConfig, Settings};
pub use exchange::*;
pub use intercept::{Decision, InterceptConfig, InterceptPhase, TicketInfo};
pub use rules::{Action, Filter, FilterField, MatchOp, Rule};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustStatus {
    Trusted,
    NotTrusted,
    /// Not checkable on this platform.
    Unknown,
}

/// Bytes <-> base64 string (compact JSON for bodies).
pub(crate) mod b64 {
    use base64::Engine as _;
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &Bytes, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Bytes, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map(Bytes::from)
            .map_err(serde::de::Error::custom)
    }
}
