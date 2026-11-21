//! Data model for captured HTTP exchanges.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::SystemTime;

pub type ExchangeId = u64;

/// Ordered list of header name/value pairs (keeps duplicates and order).
pub type HeaderList = Vec<(String, String)>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExchangeState {
    /// Request received, waiting for upstream.
    Pending,
    /// Paused by an intercept breakpoint.
    Intercepted,
    /// Response headers received, body still streaming.
    Receiving,
    /// Finished successfully.
    Completed,
    /// Failed (see `error`).
    Failed,
    /// Blocked or dropped by a rule or the user.
    Aborted,
}

#[derive(Debug, Clone)]
pub struct RequestData {
    pub method: String,
    /// "http" or "https"
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// Path including query string (origin-form).
    pub path: String,
    pub version: String,
    pub headers: HeaderList,
    pub body: Bytes,
    pub body_truncated: bool,
}

impl RequestData {
    pub fn url(&self) -> String {
        let default_port = matches!(
            (self.scheme.as_str(), self.port),
            ("http", 80) | ("https", 443)
        );
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if default_port {
            format!("{}://{}{}", self.scheme, host, self.path)
        } else {
            format!("{}://{}:{}{}", self.scheme, host, self.port, self.path)
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }
}

#[derive(Debug, Clone)]
pub struct ResponseData {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: HeaderList,
    pub body: Bytes,
    pub body_truncated: bool,
}

impl ResponseData {
    pub fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }
}

pub fn header_value<'a>(headers: &'a HeaderList, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[derive(Debug, Clone)]
pub struct Exchange {
    pub id: ExchangeId,
    pub client: Option<SocketAddr>,
    pub started: SystemTime,
    pub state: ExchangeState,
    pub request: RequestData,
    pub response: Option<ResponseData>,
    pub error: Option<String>,
    /// Total duration in milliseconds (set when finished).
    pub duration_ms: Option<u64>,
    /// Time to response headers in milliseconds.
    pub ttfb_ms: Option<u64>,
    /// Names of rewrite rules applied to this exchange.
    pub applied_rules: Vec<String>,
    /// Was this exchange paused/edited by the user.
    pub intercepted: bool,
    /// Connection was upgraded (e.g. WebSocket).
    pub upgraded: bool,
    /// HTTPS details (decrypted exchanges only).
    pub tls: Option<TlsInfo>,
}

/// Summary of an X.509 certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial: String,
    pub san: Vec<String>,
}

/// TLS parameters of both legs of a decrypted exchange.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsInfo {
    pub sni: Option<String>,
    /// Client <-> FluxRS
    pub client_version: Option<String>,
    pub client_cipher: Option<String>,
    pub client_alpn: Option<String>,
    /// FluxRS <-> server
    pub server_version: Option<String>,
    pub server_cipher: Option<String>,
    pub server_cert: Option<CertSummary>,
    pub server_chain_len: usize,
}

impl Exchange {
    pub fn content_type(&self) -> Option<&str> {
        self.response
            .as_ref()
            .and_then(|r| r.header("content-type"))
    }
}
