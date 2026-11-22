//! Rewrite rule definitions (filters + actions). Evaluation lives in fluxrs-core.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FilterField {
    #[default]
    Url,
    Host,
    Path,
    Method,
    /// Value of a request header (`header_name` must be set).
    RequestHeader,
}

impl FilterField {
    pub const ALL: [FilterField; 5] = [
        FilterField::Url,
        FilterField::Host,
        FilterField::Path,
        FilterField::Method,
        FilterField::RequestHeader,
    ];

    pub fn label(self) -> &'static str {
        match self {
            FilterField::Url => "URL",
            FilterField::Host => "Host",
            FilterField::Path => "Path",
            FilterField::Method => "Method",
            FilterField::RequestHeader => "Request header",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum MatchOp {
    #[default]
    Contains,
    Equals,
    StartsWith,
    EndsWith,
    Regex,
}

impl MatchOp {
    pub const ALL: [MatchOp; 5] = [
        MatchOp::Contains,
        MatchOp::Equals,
        MatchOp::StartsWith,
        MatchOp::EndsWith,
        MatchOp::Regex,
    ];

    pub fn label(self) -> &'static str {
        match self {
            MatchOp::Contains => "contains",
            MatchOp::Equals => "equals",
            MatchOp::StartsWith => "starts with",
            MatchOp::EndsWith => "ends with",
            MatchOp::Regex => "matches regex",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filter {
    pub field: FilterField,
    pub op: MatchOp,
    pub value: String,
    #[serde(default)]
    pub header_name: String,
    #[serde(default)]
    pub negate: bool,
    #[serde(default = "default_true")]
    pub case_insensitive: bool,
}

pub(crate) fn default_true() -> bool {
    true
}

impl Default for Filter {
    fn default() -> Self {
        Filter {
            field: FilterField::default(),
            op: MatchOp::default(),
            value: String::new(),
            header_name: String::new(),
            negate: false,
            case_insensitive: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Action {
    SetRequestHeader {
        name: String,
        value: String,
    },
    RemoveRequestHeader {
        name: String,
    },
    SetResponseHeader {
        name: String,
        value: String,
    },
    RemoveResponseHeader {
        name: String,
    },
    /// Change the HTTP method.
    SetMethod {
        method: String,
    },
    /// Regex replace on path + query.
    RewritePath {
        find: String,
        replace: String,
    },
    /// Forward the request to another host (and optionally port / scheme).
    RedirectHost {
        host: String,
        port: Option<u16>,
        /// None keeps the original scheme.
        https: Option<bool>,
    },
    ReplaceRequestBody {
        body: String,
    },
    RequestBodyReplace {
        find: String,
        replace: String,
        regex: bool,
    },
    SetResponseStatus {
        status: u16,
    },
    ReplaceResponseBody {
        body: String,
    },
    ResponseBodyReplace {
        find: String,
        replace: String,
        regex: bool,
    },
    /// Answer directly without contacting the server.
    MockResponse {
        status: u16,
        content_type: String,
        body: String,
    },
    /// Abort the request (connection is closed).
    Block,
    /// Delay before forwarding (milliseconds).
    Delay {
        ms: u64,
    },
}

impl Action {
    pub fn kind_label(&self) -> &'static str {
        match self {
            Action::SetRequestHeader { .. } => "Set request header",
            Action::RemoveRequestHeader { .. } => "Remove request header",
            Action::SetResponseHeader { .. } => "Set response header",
            Action::RemoveResponseHeader { .. } => "Remove response header",
            Action::SetMethod { .. } => "Set method",
            Action::RewritePath { .. } => "Rewrite path",
            Action::RedirectHost { .. } => "Redirect host",
            Action::ReplaceRequestBody { .. } => "Replace request body",
            Action::RequestBodyReplace { .. } => "Find/replace request body",
            Action::SetResponseStatus { .. } => "Set response status",
            Action::ReplaceResponseBody { .. } => "Replace response body",
            Action::ResponseBodyReplace { .. } => "Find/replace response body",
            Action::MockResponse { .. } => "Mock response",
            Action::Block => "Block",
            Action::Delay { .. } => "Delay",
        }
    }

    /// One default instance of each action kind (used by UIs).
    pub fn templates() -> Vec<Action> {
        vec![
            Action::SetRequestHeader {
                name: "X-Debug".into(),
                value: "1".into(),
            },
            Action::RemoveRequestHeader {
                name: "Cookie".into(),
            },
            Action::SetResponseHeader {
                name: "Access-Control-Allow-Origin".into(),
                value: "*".into(),
            },
            Action::RemoveResponseHeader {
                name: "Content-Security-Policy".into(),
            },
            Action::SetMethod {
                method: "POST".into(),
            },
            Action::RewritePath {
                find: "^/api/v1/".into(),
                replace: "/api/v2/".into(),
            },
            Action::RedirectHost {
                host: "localhost".into(),
                port: Some(8080),
                https: Some(false),
            },
            Action::ReplaceRequestBody {
                body: String::new(),
            },
            Action::RequestBodyReplace {
                find: String::new(),
                replace: String::new(),
                regex: false,
            },
            Action::SetResponseStatus { status: 200 },
            Action::ReplaceResponseBody {
                body: String::new(),
            },
            Action::ResponseBodyReplace {
                find: String::new(),
                replace: String::new(),
                regex: false,
            },
            Action::MockResponse {
                status: 200,
                content_type: "application/json".into(),
                body: "{\"mocked\": true}".into(),
            },
            Action::Block,
            Action::Delay { ms: 1000 },
        ]
    }

    pub fn touches_response_body(&self) -> bool {
        matches!(
            self,
            Action::ReplaceResponseBody { .. } | Action::ResponseBodyReplace { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// All filters must match (AND). Empty = match everything.
    #[serde(default)]
    pub filters: Vec<Filter>,
    #[serde(default)]
    pub actions: Vec<Action>,
}

impl Default for Rule {
    fn default() -> Self {
        Rule {
            name: "New rule".into(),
            enabled: true,
            filters: vec![Filter::default()],
            actions: vec![],
        }
    }
}
