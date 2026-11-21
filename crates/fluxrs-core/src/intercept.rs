//! Breakpoint based interception: pause a request or response, let the
//! user edit it as raw HTTP text, then forward or drop it.

use crate::model::{ExchangeId, RequestData};
use crate::rules::{CompiledFilterPub, Filter, RuleError};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::oneshot;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InterceptConfig {
    pub enabled: bool,
    pub requests: bool,
    pub responses: bool,
    /// Only exchanges matching this filter are paused. Empty value = all.
    pub filter: Filter,
}

impl Default for InterceptConfig {
    fn default() -> Self {
        InterceptConfig {
            enabled: false,
            requests: true,
            responses: false,
            filter: Filter::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptPhase {
    Request,
    Response,
}

#[derive(Debug)]
pub enum Decision {
    /// Forward. `Some(raw)` replaces the message with the edited raw text.
    Forward(Option<String>),
    /// Abort the exchange.
    Drop,
}

/// A paused exchange waiting for a decision. Dropping the ticket
/// without resolving it forwards the message unchanged.
pub struct InterceptTicket {
    pub ticket_id: u64,
    pub exchange_id: ExchangeId,
    pub phase: InterceptPhase,
    /// Short description, e.g. "GET https://host/path".
    pub title: String,
    /// Editable raw HTTP message.
    pub raw: String,
    /// Body is binary and shown as a placeholder (kept as-is unless replaced).
    pub binary_body: bool,
    responder: Option<oneshot::Sender<Decision>>,
}

impl std::fmt::Debug for InterceptTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterceptTicket")
            .field("ticket_id", &self.ticket_id)
            .field("exchange_id", &self.exchange_id)
            .field("phase", &self.phase)
            .field("title", &self.title)
            .finish()
    }
}

impl InterceptTicket {
    pub fn resolve(mut self, decision: Decision) {
        if let Some(tx) = self.responder.take() {
            let _ = tx.send(decision);
        }
    }
}

struct State {
    config: InterceptConfig,
    filter: Option<CompiledFilterPub>,
}

#[derive(Clone)]
pub struct Interceptor {
    state: Arc<RwLock<State>>,
    next_ticket: Arc<AtomicU64>,
}

impl Default for Interceptor {
    fn default() -> Self {
        Interceptor {
            state: Arc::new(RwLock::new(State {
                config: InterceptConfig::default(),
                filter: None,
            })),
            next_ticket: Arc::new(AtomicU64::new(1)),
        }
    }
}

impl Interceptor {
    pub fn set_config(&self, config: InterceptConfig) -> Result<(), RuleError> {
        let filter = if config.filter.value.is_empty() {
            None
        } else {
            Some(CompiledFilterPub::compile(&config.filter)?)
        };
        let mut s = self.state.write();
        s.config = config;
        s.filter = filter;
        Ok(())
    }

    pub fn config(&self) -> InterceptConfig {
        self.state.read().config.clone()
    }

    pub fn should_intercept(&self, phase: InterceptPhase, req: &RequestData) -> bool {
        let s = self.state.read();
        if !s.config.enabled {
            return false;
        }
        let phase_on = match phase {
            InterceptPhase::Request => s.config.requests,
            InterceptPhase::Response => s.config.responses,
        };
        phase_on && s.filter.as_ref().is_none_or(|f| f.matches(req))
    }

    pub(crate) fn ticket(
        &self,
        exchange_id: ExchangeId,
        phase: InterceptPhase,
        title: String,
        raw: String,
        binary_body: bool,
    ) -> (InterceptTicket, oneshot::Receiver<Decision>) {
        let (tx, rx) = oneshot::channel();
        let t = InterceptTicket {
            ticket_id: self.next_ticket.fetch_add(1, Ordering::Relaxed),
            exchange_id,
            phase,
            title,
            raw,
            binary_body,
            responder: Some(tx),
        };
        (t, rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{FilterField, MatchOp};

    fn req(host: &str) -> RequestData {
        RequestData {
            method: "GET".into(),
            scheme: "http".into(),
            host: host.into(),
            port: 80,
            path: "/".into(),
            version: "HTTP/1.1".into(),
            headers: vec![],
            body: Default::default(),
            body_truncated: false,
        }
    }

    #[test]
    fn intercept_respects_config_and_filter() {
        let i = Interceptor::default();
        assert!(!i.should_intercept(InterceptPhase::Request, &req("a.com")));
        i.set_config(InterceptConfig {
            enabled: true,
            requests: true,
            responses: false,
            filter: Filter {
                field: FilterField::Host,
                op: MatchOp::EndsWith,
                value: "a.com".into(),
                ..Default::default()
            },
        })
        .unwrap();
        assert!(i.should_intercept(InterceptPhase::Request, &req("x.a.com")));
        assert!(!i.should_intercept(InterceptPhase::Request, &req("b.com")));
        assert!(!i.should_intercept(InterceptPhase::Response, &req("x.a.com")));
    }

    #[tokio::test]
    async fn ticket_resolution_and_drop() {
        let i = Interceptor::default();
        let (t, rx) = i.ticket(1, InterceptPhase::Request, "t".into(), "raw".into(), false);
        t.resolve(Decision::Drop);
        assert!(matches!(rx.await, Ok(Decision::Drop)));
        let (t, rx) = i.ticket(2, InterceptPhase::Request, "t".into(), "raw".into(), false);
        drop(t);
        assert!(rx.await.is_err());
    }
}
