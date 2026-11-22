//! Messages between a FluxRS host (engine owner) and a user interface.
//!
//! The desktop app exchanges them in-process; the web UI sends them as JSON
//! over a WebSocket (`fluxrs --serve`).

use crate::{Decision, Exchange, LogLevel, Rule, Settings, TicketInfo, TrustStatus};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub const PROTOCOL_VERSION: u32 = 1;

/// Capture engine state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub running: bool,
    /// Listening address when running.
    pub addr: Option<String>,
    /// Last start error.
    pub error: Option<String>,
}

/// Root certificate details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaInfo {
    pub pem: String,
    /// File path on the host.
    pub path: String,
    pub serial: String,
}

/// Full host state, sent when an interface connects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub protocol: u32,
    pub version: String,
    /// Host operating system ("windows", "linux", ...).
    pub os: String,
    pub settings: Settings,
    pub rules: Vec<Rule>,
    pub rules_error: Option<String>,
    pub intercept_error: Option<String>,
    pub status: Status,
    pub ca: Option<CaInfo>,
    pub ca_error: Option<String>,
    pub trust: Option<TrustStatus>,
}

/// Host -> UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ServerMsg {
    /// Full state, sent first.
    Hello(Box<Hello>),
    Status(Status),
    /// New or updated exchange (replace by id).
    Exchange(Arc<Exchange>),
    /// Traffic list cleared.
    Cleared,
    Ticket(TicketInfo),
    /// Ticket resolved (by any client) or released.
    TicketClosed(u64),
    Log {
        level: LogLevel,
        text: String,
    },
    RulesError(Option<String>),
    InterceptError(Option<String>),
    Trust(Option<TrustStatus>),
    Ca {
        ca: Option<CaInfo>,
        error: Option<String>,
    },
    /// Short notification for the user.
    Toast {
        text: String,
        ok: bool,
    },
}

/// UI -> host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ClientMsg {
    Start,
    Stop,
    Clear,
    SetSettings(Settings),
    SetRules(Vec<Rule>),
    Resolve { ticket_id: u64, decision: Decision },
    InstallCa,
    RefreshTrust,
    RegenerateCa,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExchangeState, RequestData};

    #[test]
    fn exchange_roundtrip_with_base64_body() {
        let ex = Exchange {
            id: 7,
            client: Some("127.0.0.1:5000".parse().unwrap()),
            started: std::time::UNIX_EPOCH + std::time::Duration::from_secs(5),
            state: ExchangeState::Completed,
            request: RequestData {
                method: "POST".into(),
                scheme: "https".into(),
                host: "a.com".into(),
                port: 443,
                path: "/x".into(),
                version: "HTTP/1.1".into(),
                headers: vec![("a".into(), "b".into())],
                body: bytes::Bytes::from_static(&[0, 1, 2, 255]),
                body_truncated: false,
            },
            response: None,
            error: None,
            duration_ms: Some(3),
            ttfb_ms: None,
            applied_rules: vec!["r".into()],
            intercepted: false,
            upgraded: false,
            tls: None,
        };
        let json = serde_json::to_string(&ServerMsg::Exchange(Arc::new(ex))).unwrap();
        assert!(json.contains("\"AAEC/w==\""), "{json}");
        let back: ServerMsg = serde_json::from_str(&json).unwrap();
        match back {
            ServerMsg::Exchange(e) => {
                assert_eq!(e.id, 7);
                assert_eq!(&e.request.body[..], &[0, 1, 2, 255]);
                assert_eq!(e.request.url(), "https://a.com/x");
            }
            _ => panic!(),
        }
        let c: ClientMsg = serde_json::from_str(
            r#"{"type":"Resolve","data":{"ticket_id":3,"decision":{"Forward":"GET / HTTP/1.1"}}}"#,
        )
        .unwrap();
        assert!(matches!(c, ClientMsg::Resolve { ticket_id: 3, .. }));
    }
}
