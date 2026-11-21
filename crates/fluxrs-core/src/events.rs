//! Events emitted by the engine to the UI (or any other consumer).

use crate::intercept::InterceptTicket;
use crate::model::Exchange;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

#[derive(Debug)]
pub enum ProxyEvent {
    /// New or updated exchange snapshot (replace by id).
    Exchange(Arc<Exchange>),
    /// An exchange hit a breakpoint and waits for a user decision.
    Intercepted(InterceptTicket),
    /// Diagnostic message.
    Log(LogLevel, String),
    /// Engine stopped (with optional error).
    Stopped(Option<String>),
}

/// Callback receiving engine events. Must be cheap and non-blocking.
pub type EventSink = Arc<dyn Fn(ProxyEvent) + Send + Sync>;

pub(crate) fn log(sink: &EventSink, level: LogLevel, msg: impl Into<String>) {
    let msg = msg.into();
    match level {
        LogLevel::Info => tracing::info!("{msg}"),
        LogLevel::Warn => tracing::warn!("{msg}"),
        LogLevel::Error => tracing::error!("{msg}"),
    }
    sink(ProxyEvent::Log(level, msg));
}
