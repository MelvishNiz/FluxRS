//! Capture engine and application settings.

use crate::intercept::InterceptConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureMode {
    /// Classic explicit HTTP proxy (configure clients to use 127.0.0.1:port).
    Proxy,
    /// Transparent capture with WinDivert, no proxy settings needed (Windows).
    Proxyless,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineConfig {
    pub mode: CaptureMode,
    pub port: u16,
    /// Explicit proxy mode: listen on all interfaces instead of loopback.
    pub listen_any: bool,
    pub decrypt_tls: bool,
    /// Hosts never decrypted (wildcards like `*.example.com`).
    pub bypass_hosts: Vec<String>,
    /// Accept invalid upstream certificates.
    pub insecure_upstream: bool,
    /// Max body bytes kept for display (streaming responses).
    pub max_capture_body: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            mode: if cfg!(windows) {
                CaptureMode::Proxyless
            } else {
                CaptureMode::Proxy
            },
            port: 44344,
            listen_any: false,
            decrypt_tls: true,
            bypass_hosts: vec![],
            insecure_upstream: false,
            max_capture_body: 8 * 1024 * 1024,
        }
    }
}

/// Persisted application settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Settings {
    pub engine: EngineConfig,
    pub intercept: InterceptConfig,
}
