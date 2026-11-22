//! Rewrite rule engine: filters select exchanges, actions alter them.
//!
//! Inspired by fluxzy's rule/filter/action model, simplified.

use crate::model::{HeaderList, RequestData};
pub use fluxrs_model::rules::*;
use regex::Regex;

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("rule '{rule}': invalid regex '{pattern}': {err}")]
    Regex {
        rule: String,
        pattern: String,
        err: regex::Error,
    },
}

#[derive(Debug)]
struct CompiledFilter {
    filter: Filter,
    regex: Option<Regex>,
    value_lower: String,
}

impl CompiledFilter {
    fn matches(&self, req: &RequestData) -> bool {
        let url;
        let subject: Option<&str> = match self.filter.field {
            FilterField::Url => {
                url = req.url();
                Some(url.as_str())
            }
            FilterField::Host => Some(req.host.as_str()),
            FilterField::Path => Some(req.path.as_str()),
            FilterField::Method => Some(req.method.as_str()),
            FilterField::RequestHeader => req.header(&self.filter.header_name),
        };
        let hit = match subject {
            None => false,
            Some(s) => self.matches_str(s),
        };
        hit != self.filter.negate
    }

    fn matches_str(&self, s: &str) -> bool {
        if let Some(re) = &self.regex {
            return re.is_match(s);
        }
        let ci = self.filter.case_insensitive;
        let owned;
        let s = if ci {
            owned = s.to_lowercase();
            owned.as_str()
        } else {
            s
        };
        let v = if ci {
            self.value_lower.as_str()
        } else {
            self.filter.value.as_str()
        };
        match self.filter.op {
            MatchOp::Contains => s.contains(v),
            MatchOp::Equals => s == v,
            MatchOp::StartsWith => s.starts_with(v),
            MatchOp::EndsWith => s.ends_with(v),
            MatchOp::Regex => unreachable!("regex handled above"),
        }
    }
}

#[derive(Debug)]
pub(crate) enum CompiledAction {
    Plain(Action),
    RewritePath {
        re: Regex,
        replace: String,
    },
    BodyReplace {
        response: bool,
        re: Regex,
        replace: String,
    },
}

#[derive(Debug)]
pub(crate) struct CompiledRule {
    pub name: String,
    filters: Vec<CompiledFilter>,
    pub actions: Vec<CompiledAction>,
}

impl CompiledRule {
    pub fn matches(&self, req: &RequestData) -> bool {
        self.filters.iter().all(|f| f.matches(req))
    }
}

/// Compiled, ready to evaluate rule set.
#[derive(Debug, Default)]
pub struct RuleSet {
    pub(crate) rules: Vec<CompiledRule>,
}

pub(crate) fn compile_filter(
    filter: &Filter,
    rule_name: &str,
) -> Result<CompiledFilterPub, RuleError> {
    let regex = if filter.op == MatchOp::Regex {
        let pat = if filter.case_insensitive {
            format!("(?i){}", filter.value)
        } else {
            filter.value.clone()
        };
        Some(Regex::new(&pat).map_err(|err| RuleError::Regex {
            rule: rule_name.to_string(),
            pattern: filter.value.clone(),
            err,
        })?)
    } else {
        None
    };
    Ok(CompiledFilterPub(CompiledFilter {
        filter: filter.clone(),
        regex,
        value_lower: filter.value.to_lowercase(),
    }))
}

/// A compiled filter usable outside the rule engine (e.g. intercept filter).
#[derive(Debug)]
pub struct CompiledFilterPub(CompiledFilter);

impl CompiledFilterPub {
    pub fn compile(filter: &Filter) -> Result<Self, RuleError> {
        compile_filter(filter, "filter")
    }
    pub fn matches(&self, req: &RequestData) -> bool {
        self.0.matches(req)
    }
}

fn literal_or_regex(find: &str, regex: bool, rule: &str) -> Result<Regex, RuleError> {
    let pat = if regex {
        find.to_string()
    } else {
        regex::escape(find)
    };
    Regex::new(&pat).map_err(|err| RuleError::Regex {
        rule: rule.to_string(),
        pattern: find.to_string(),
        err,
    })
}

impl RuleSet {
    pub fn compile(rules: &[Rule]) -> Result<RuleSet, RuleError> {
        let mut out = Vec::new();
        for rule in rules.iter().filter(|r| r.enabled) {
            let filters = rule
                .filters
                .iter()
                .map(|f| compile_filter(f, &rule.name).map(|c| c.0))
                .collect::<Result<Vec<_>, _>>()?;
            let mut actions = Vec::new();
            for a in &rule.actions {
                let ca = match a {
                    Action::RewritePath { find, replace } => CompiledAction::RewritePath {
                        re: literal_or_regex(find, true, &rule.name)?,
                        replace: replace.clone(),
                    },
                    Action::RequestBodyReplace {
                        find,
                        replace,
                        regex,
                    } => {
                        if find.is_empty() {
                            continue;
                        }
                        CompiledAction::BodyReplace {
                            response: false,
                            re: literal_or_regex(find, *regex, &rule.name)?,
                            replace: replace.clone(),
                        }
                    }
                    Action::ResponseBodyReplace {
                        find,
                        replace,
                        regex,
                    } => {
                        if find.is_empty() {
                            continue;
                        }
                        CompiledAction::BodyReplace {
                            response: true,
                            re: literal_or_regex(find, *regex, &rule.name)?,
                            replace: replace.clone(),
                        }
                    }
                    other => CompiledAction::Plain(other.clone()),
                };
                actions.push(ca);
            }
            out.push(CompiledRule {
                name: rule.name.clone(),
                filters,
                actions,
            });
        }
        Ok(RuleSet { rules: out })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Rules matching the given request, in order.
    pub(crate) fn matching<'a>(&'a self, req: &RequestData) -> Vec<&'a CompiledRule> {
        self.rules.iter().filter(|r| r.matches(req)).collect()
    }
}

/// Result of applying request-phase actions.
#[derive(Debug, Default)]
pub(crate) struct RequestOutcome {
    pub mock: Option<(u16, String, String)>,
    pub block: bool,
    pub delay_ms: u64,
    /// New upstream target requested (host, port, https).
    pub redirect: Option<(String, Option<u16>, Option<bool>)>,
}

pub(crate) fn set_header(headers: &mut HeaderList, name: &str, value: &str) {
    remove_header(headers, name);
    headers.push((name.to_string(), value.to_string()));
}

pub(crate) fn remove_header(headers: &mut HeaderList, name: &str) {
    headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
}

fn replace_text_body(body: &[u8], re: &Regex, replace: &str) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(body).ok()?;
    let replaced = re.replace_all(text, replace);
    Some(replaced.into_owned().into_bytes())
}

/// Apply request-phase actions. `body` must already be decoded (no content-encoding)
/// if any body action is present; caller handles that.
pub(crate) fn apply_request_actions(
    rules: &[&CompiledRule],
    req: &mut RequestData,
) -> RequestOutcome {
    let mut out = RequestOutcome::default();
    for rule in rules {
        for action in &rule.actions {
            match action {
                CompiledAction::Plain(a) => match a {
                    Action::SetRequestHeader { name, value } if !name.is_empty() => {
                        set_header(&mut req.headers, name, value)
                    }
                    Action::RemoveRequestHeader { name } => remove_header(&mut req.headers, name),
                    Action::SetMethod { method } if !method.trim().is_empty() => {
                        req.method = method.trim().to_uppercase()
                    }
                    Action::RedirectHost { host, port, https } if !host.trim().is_empty() => {
                        out.redirect = Some((host.trim().to_string(), *port, *https));
                    }
                    Action::ReplaceRequestBody { body } => {
                        req.body = bytes::Bytes::from(body.clone().into_bytes());
                    }
                    Action::MockResponse {
                        status,
                        content_type,
                        body,
                    } => {
                        if out.mock.is_none() {
                            out.mock = Some((*status, content_type.clone(), body.clone()));
                        }
                    }
                    Action::Block => out.block = true,
                    Action::Delay { ms } => out.delay_ms = out.delay_ms.saturating_add(*ms),
                    _ => {}
                },
                CompiledAction::RewritePath { re, replace } => {
                    let new = re.replace_all(&req.path, replace.as_str()).into_owned();
                    req.path = if new.starts_with('/') {
                        new
                    } else {
                        format!("/{new}")
                    };
                }
                CompiledAction::BodyReplace {
                    response: false,
                    re,
                    replace,
                } => {
                    if let Some(b) = replace_text_body(&req.body, re, replace) {
                        req.body = b.into();
                    }
                }
                CompiledAction::BodyReplace { response: true, .. } => {}
            }
        }
    }
    out
}

pub(crate) fn rules_need_request_body(rules: &[&CompiledRule]) -> bool {
    rules.iter().any(|r| {
        r.actions.iter().any(|a| {
            matches!(
                a,
                CompiledAction::BodyReplace {
                    response: false,
                    ..
                } | CompiledAction::Plain(Action::ReplaceRequestBody { .. })
            )
        })
    })
}

pub(crate) fn rules_need_response_body(rules: &[&CompiledRule]) -> bool {
    rules.iter().any(|r| {
        r.actions.iter().any(|a| match a {
            CompiledAction::BodyReplace { response, .. } => *response,
            CompiledAction::Plain(a) => a.touches_response_body(),
            _ => false,
        })
    })
}

/// Apply response header/status actions (no body).
pub(crate) fn apply_response_head_actions(
    rules: &[&CompiledRule],
    status: &mut u16,
    headers: &mut HeaderList,
) {
    for rule in rules {
        for action in &rule.actions {
            if let CompiledAction::Plain(a) = action {
                match a {
                    Action::SetResponseHeader { name, value } if !name.is_empty() => {
                        set_header(headers, name, value)
                    }
                    Action::RemoveResponseHeader { name } => remove_header(headers, name),
                    Action::SetResponseStatus { status: s } if (100..=999).contains(s) => {
                        *status = *s
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Apply response body actions on an already decoded body.
pub(crate) fn apply_response_body_actions(rules: &[&CompiledRule], body: &mut bytes::Bytes) {
    for rule in rules {
        for action in &rule.actions {
            match action {
                CompiledAction::Plain(Action::ReplaceResponseBody { body: b }) => {
                    *body = bytes::Bytes::from(b.clone().into_bytes());
                }
                CompiledAction::BodyReplace {
                    response: true,
                    re,
                    replace,
                } => {
                    if let Some(b) = replace_text_body(body, re, replace) {
                        *body = b.into();
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> RequestData {
        RequestData {
            method: "GET".into(),
            scheme: "https".into(),
            host: "api.example.com".into(),
            port: 443,
            path: "/api/v1/users?id=1".into(),
            version: "HTTP/1.1".into(),
            headers: vec![("Host".into(), "api.example.com".into())],
            body: bytes::Bytes::from_static(b"hello world"),
            body_truncated: false,
        }
    }

    fn rule(filters: Vec<Filter>, actions: Vec<Action>) -> Rule {
        Rule {
            name: "t".into(),
            enabled: true,
            filters,
            actions,
        }
    }

    #[test]
    fn filters_match() {
        let r = req();
        let f = |field, op, value: &str| Filter {
            field,
            op,
            value: value.into(),
            ..Default::default()
        };
        let cases = [
            (
                f(FilterField::Host, MatchOp::Equals, "API.example.com"),
                true,
            ),
            (f(FilterField::Host, MatchOp::EndsWith, ".com"), true),
            (f(FilterField::Path, MatchOp::StartsWith, "/api"), true),
            (f(FilterField::Url, MatchOp::Contains, "https://api"), true),
            (f(FilterField::Url, MatchOp::Regex, r"v\d/users"), true),
            (f(FilterField::Method, MatchOp::Equals, "post"), false),
        ];
        for (filter, expected) in cases {
            let c = CompiledFilterPub::compile(&filter).unwrap();
            assert_eq!(c.matches(&r), expected, "{filter:?}");
        }
        let mut neg = f(FilterField::Method, MatchOp::Equals, "post");
        neg.negate = true;
        assert!(CompiledFilterPub::compile(&neg).unwrap().matches(&r));
        let hdr = Filter {
            field: FilterField::RequestHeader,
            header_name: "host".into(),
            op: MatchOp::Contains,
            value: "example".into(),
            ..Default::default()
        };
        assert!(CompiledFilterPub::compile(&hdr).unwrap().matches(&r));
    }

    #[test]
    fn invalid_regex_reports_error() {
        let r = rule(
            vec![Filter {
                op: MatchOp::Regex,
                value: "(".into(),
                ..Default::default()
            }],
            vec![],
        );
        assert!(RuleSet::compile(&[r]).is_err());
    }

    #[test]
    fn request_actions_apply() {
        let rs = RuleSet::compile(&[rule(
            vec![],
            vec![
                Action::SetRequestHeader {
                    name: "X-A".into(),
                    value: "1".into(),
                },
                Action::RemoveRequestHeader {
                    name: "host".into(),
                },
                Action::SetMethod {
                    method: "post".into(),
                },
                Action::RewritePath {
                    find: "^/api/v1/".into(),
                    replace: "/api/v2/".into(),
                },
                Action::RequestBodyReplace {
                    find: "world".into(),
                    replace: "rust".into(),
                    regex: false,
                },
                Action::RedirectHost {
                    host: "localhost".into(),
                    port: Some(8080),
                    https: Some(false),
                },
            ],
        )])
        .unwrap();
        let mut r = req();
        let m = rs.matching(&r);
        assert_eq!(m.len(), 1);
        let out = apply_request_actions(&m, &mut r);
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/api/v2/users?id=1");
        assert_eq!(&r.body[..], b"hello rust");
        assert_eq!(r.header("x-a"), Some("1"));
        assert_eq!(r.header("host"), None);
        assert_eq!(
            out.redirect,
            Some(("localhost".into(), Some(8080), Some(false)))
        );
        assert!(!out.block);
    }

    #[test]
    fn response_actions_apply() {
        let rs = RuleSet::compile(&[rule(
            vec![],
            vec![
                Action::SetResponseStatus { status: 418 },
                Action::SetResponseHeader {
                    name: "X-B".into(),
                    value: "2".into(),
                },
                Action::ResponseBodyReplace {
                    find: r"\d+".into(),
                    replace: "N".into(),
                    regex: true,
                },
            ],
        )])
        .unwrap();
        let r = req();
        let m = rs.matching(&r);
        assert!(rules_need_response_body(&m));
        assert!(!rules_need_request_body(&m));
        let mut status = 200;
        let mut headers = vec![];
        apply_response_head_actions(&m, &mut status, &mut headers);
        assert_eq!(status, 418);
        assert_eq!(headers, vec![("X-B".to_string(), "2".to_string())]);
        let mut body = bytes::Bytes::from_static(b"a1b22c333");
        apply_response_body_actions(&m, &mut body);
        assert_eq!(&body[..], b"aNbNcN");
    }

    #[test]
    fn disabled_rules_are_skipped_and_serde_roundtrip() {
        let mut r = rule(vec![], vec![Action::Block]);
        r.enabled = false;
        let rs = RuleSet::compile(&[r.clone()]).unwrap();
        assert!(rs.is_empty());
        let json = serde_json::to_string(&vec![r.clone()]).unwrap();
        let back: Vec<Rule> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, vec![r]);
    }
}
