//! Windows firewall rule so redirected (reflected) connections reach the proxy.

#![cfg(windows)]

use crate::events::{log, EventSink, LogLevel};
use std::os::windows::process::CommandExt;

const RULE_NAME: &str = "FluxRS-Proxyless-Capture";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn netsh(args: &[String]) -> std::io::Result<std::process::Output> {
    std::process::Command::new("netsh")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
}

/// Best effort: (re)create an inbound allow rule for the proxy port.
pub fn ensure_rule(port: u16, sink: &EventSink) {
    let name = format!("name={RULE_NAME}");
    let _ = netsh(&[
        "advfirewall".into(),
        "firewall".into(),
        "delete".into(),
        "rule".into(),
        name.clone(),
    ]);
    let res = netsh(&[
        "advfirewall".into(),
        "firewall".into(),
        "add".into(),
        "rule".into(),
        name,
        "dir=in".into(),
        "action=allow".into(),
        "protocol=TCP".into(),
        format!("localport={port}"),
        "enable=yes".into(),
    ]);
    match res {
        Ok(o) if o.status.success() => {}
        Ok(o) => log(
            sink,
            LogLevel::Warn,
            format!(
                "Could not add firewall rule: {}",
                String::from_utf8_lossy(&o.stdout).trim()
            ),
        ),
        Err(e) => log(sink, LogLevel::Warn, format!("netsh failed: {e}")),
    }
}
