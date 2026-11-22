//! Breakpoint configuration and decisions.

use crate::rules::Filter;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterceptPhase {
    Request,
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Forward. `Some(raw)` replaces the message with the edited raw text.
    Forward(Option<String>),
    /// Abort the exchange.
    Drop,
}

/// A paused message as shown to a user interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketInfo {
    pub ticket_id: u64,
    pub exchange_id: u64,
    pub phase: InterceptPhase,
    pub title: String,
    pub raw: String,
    pub binary_body: bool,
}
