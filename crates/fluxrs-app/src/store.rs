//! Persistence of settings and rules (JSON files in the data directory).

use fluxrs_core::{EngineConfig, InterceptConfig, Rule};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Settings {
    pub engine: EngineConfig,
    pub intercept: InterceptConfig,
}

pub fn data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("FluxRS")
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    // Write atomically to avoid corrupt files on crash.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

pub fn load_settings(dir: &Path) -> Settings {
    let mut s: Settings = read_json(&dir.join("settings.json")).unwrap_or_default();
    // Breakpoints always start disabled so traffic is never stuck at launch.
    s.intercept.enabled = false;
    s
}

pub fn save_settings(dir: &Path, s: &Settings) -> Result<(), String> {
    write_json(&dir.join("settings.json"), s)
}

pub fn load_rules(dir: &Path) -> Vec<Rule> {
    read_json(&dir.join("rules.json")).unwrap_or_else(default_rules)
}

pub fn save_rules(dir: &Path, rules: &[Rule]) -> Result<(), String> {
    write_json(&dir.join("rules.json"), &rules)
}

/// Example rules (disabled) shown on first launch.
fn default_rules() -> Vec<Rule> {
    use fluxrs_core::{Action, Filter, FilterField, MatchOp};
    vec![
        Rule {
            name: "Example: allow CORS for an API".into(),
            enabled: false,
            filters: vec![Filter {
                field: FilterField::Host,
                op: MatchOp::EndsWith,
                value: "api.example.com".into(),
                ..Default::default()
            }],
            actions: vec![Action::SetResponseHeader {
                name: "Access-Control-Allow-Origin".into(),
                value: "*".into(),
            }],
        },
        Rule {
            name: "Example: mock an endpoint".into(),
            enabled: false,
            filters: vec![Filter {
                field: FilterField::Path,
                op: MatchOp::StartsWith,
                value: "/api/feature-flags".into(),
                ..Default::default()
            }],
            actions: vec![Action::MockResponse {
                status: 200,
                content_type: "application/json".into(),
                body: "{\"newCheckout\": true}".into(),
            }],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_and_rules_roundtrip() {
        let dir = std::env::temp_dir().join(format!("fluxrs-test-{}", std::process::id()));
        let mut s = Settings::default();
        s.engine.port = 50123;
        s.intercept.enabled = true;
        save_settings(&dir, &s).unwrap();
        let back = load_settings(&dir);
        assert_eq!(back.engine.port, 50123);
        assert!(!back.intercept.enabled, "intercept must start disabled");

        let rules = default_rules();
        save_rules(&dir, &rules).unwrap();
        assert_eq!(load_rules(&dir), rules);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
