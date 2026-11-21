//! Formatting/parsing of HTTP messages as editable raw text.

use crate::model::HeaderList;
use bytes::Bytes;

pub const BINARY_PLACEHOLDER_PREFIX: &str = "<<binary body:";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RawParseError {
    #[error("empty message")]
    Empty,
    #[error("invalid start line: {0}")]
    StartLine(String),
    #[error("invalid header line: {0}")]
    Header(String),
    #[error("invalid status code: {0}")]
    Status(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HeaderList,
    pub body: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResponse {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: HeaderList,
    pub body: Bytes,
}

fn body_text(body: &[u8]) -> (String, bool) {
    match std::str::from_utf8(body) {
        Ok(s) if !s.contains('\0') => (s.to_string(), false),
        _ => (
            format!(
                "{BINARY_PLACEHOLDER_PREFIX} {} bytes, kept unchanged>>",
                body.len()
            ),
            true,
        ),
    }
}

fn write_headers(out: &mut String, headers: &HeaderList) {
    for (n, v) in headers {
        out.push_str(n);
        out.push_str(": ");
        out.push_str(v);
        out.push('\n');
    }
}

/// Returns raw text and whether the body is binary (placeholder).
pub fn format_request(
    method: &str,
    path: &str,
    version: &str,
    headers: &HeaderList,
    body: &[u8],
) -> (String, bool) {
    let mut out = format!("{method} {path} {version}\n");
    write_headers(&mut out, headers);
    out.push('\n');
    let (b, binary) = body_text(body);
    out.push_str(&b);
    (out, binary)
}

pub fn format_response(
    version: &str,
    status: u16,
    reason: &str,
    headers: &HeaderList,
    body: &[u8],
) -> (String, bool) {
    let mut out = format!("{version} {status} {reason}\n");
    write_headers(&mut out, headers);
    out.push('\n');
    let (b, binary) = body_text(body);
    out.push_str(&b);
    (out, binary)
}

/// Splits raw text into (head lines, body).
fn split(raw: &str) -> (Vec<&str>, &str) {
    let crlf = raw.find("\r\n\r\n").map(|i| (i, 4));
    let lf = raw.find("\n\n").map(|i| (i, 2));
    let sep = match (crlf, lf) {
        (Some(a), Some(b)) => Some(if a.0 < b.0 { a } else { b }),
        (a, b) => a.or(b),
    };
    let (head, body) = match sep {
        Some((i, len)) => (&raw[..i], &raw[i + len..]),
        None => (raw, ""),
    };
    let lines = head
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .collect();
    (lines, body)
}

fn parse_headers(lines: &[&str]) -> Result<HeaderList, RawParseError> {
    let mut headers = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let (n, v) = line
            .split_once(':')
            .ok_or_else(|| RawParseError::Header(line.to_string()))?;
        let n = n.trim();
        if n.is_empty() || n.contains(char::is_whitespace) || !n.is_ascii() {
            return Err(RawParseError::Header(line.to_string()));
        }
        headers.push((n.to_string(), v.trim().to_string()));
    }
    Ok(headers)
}

fn resolve_body(body: &str, binary: bool, original: &Bytes) -> Bytes {
    if binary && body.trim_start().starts_with(BINARY_PLACEHOLDER_PREFIX) {
        original.clone()
    } else {
        Bytes::from(body.to_string().into_bytes())
    }
}

pub fn parse_request(
    raw: &str,
    binary: bool,
    original_body: &Bytes,
) -> Result<RawRequest, RawParseError> {
    let raw = raw.trim_start_matches(['\r', '\n']);
    if raw.trim().is_empty() {
        return Err(RawParseError::Empty);
    }
    let (lines, body) = split(raw);
    let start = lines[0];
    let mut parts = start.split_whitespace();
    let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
        return Err(RawParseError::StartLine(start.to_string()));
    };
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();
    if parts.next().is_some() || !method.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(RawParseError::StartLine(start.to_string()));
    }
    let path = if path.starts_with('/') || path == "*" {
        path.to_string()
    } else if let Some(rest) = path
        .strip_prefix("http://")
        .or_else(|| path.strip_prefix("https://"))
    {
        // Absolute URL typed by the user: keep only the origin-form part.
        match rest.find('/') {
            Some(i) => rest[i..].to_string(),
            None => "/".to_string(),
        }
    } else {
        return Err(RawParseError::StartLine(start.to_string()));
    };
    Ok(RawRequest {
        method: method.to_ascii_uppercase(),
        path,
        version,
        headers: parse_headers(&lines[1..])?,
        body: resolve_body(body, binary, original_body),
    })
}

pub fn parse_response(
    raw: &str,
    binary: bool,
    original_body: &Bytes,
) -> Result<RawResponse, RawParseError> {
    let raw = raw.trim_start_matches(['\r', '\n']);
    if raw.trim().is_empty() {
        return Err(RawParseError::Empty);
    }
    let (lines, body) = split(raw);
    let start = lines[0].trim();
    let mut parts = start.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(RawParseError::StartLine(start.to_string()));
    }
    let code = parts.next().unwrap_or_default();
    let status: u16 = code
        .parse()
        .ok()
        .filter(|c| (100..=999).contains(c))
        .ok_or_else(|| RawParseError::Status(code.to_string()))?;
    let reason = parts.next().unwrap_or("").trim().to_string();
    Ok(RawResponse {
        status,
        reason,
        version: version.to_string(),
        headers: parse_headers(&lines[1..])?,
        body: resolve_body(body, binary, original_body),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("X-Test".to_string(), "a: b".to_string()),
        ];
        let (raw, bin) = format_request("POST", "/a?b=1", "HTTP/1.1", &headers, b"{\"x\":1}");
        assert!(!bin);
        let parsed = parse_request(&raw, bin, &Bytes::new()).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/a?b=1");
        assert_eq!(parsed.headers, headers);
        assert_eq!(&parsed.body[..], b"{\"x\":1}");
    }

    #[test]
    fn crlf_and_absolute_url() {
        let raw = "get https://example.com/x/y HTTP/1.1\r\nHost: example.com\r\n\r\nbody\r\n";
        let p = parse_request(raw, false, &Bytes::new()).unwrap();
        assert_eq!(p.method, "GET");
        assert_eq!(p.path, "/x/y");
        assert_eq!(&p.body[..], b"body\r\n");
    }

    #[test]
    fn binary_placeholder_keeps_original() {
        let original = Bytes::from_static(&[0, 159, 146, 150]);
        let (raw, bin) = format_response("HTTP/1.1", 200, "OK", &vec![], &original);
        assert!(bin);
        let p = parse_response(&raw, bin, &original).unwrap();
        assert_eq!(p.body, original);
        assert_eq!(p.status, 200);
        assert_eq!(p.reason, "OK");
    }

    #[test]
    fn response_edit_and_errors() {
        let p =
            parse_response("HTTP/1.1 404 Not Found\nA: 1\n\nnope", false, &Bytes::new()).unwrap();
        assert_eq!(p.status, 404);
        assert_eq!(p.reason, "Not Found");
        assert_eq!(&p.body[..], b"nope");
        assert!(parse_response("HTTP/1.1 abc\n\n", false, &Bytes::new()).is_err());
        assert!(parse_response("", false, &Bytes::new()).is_err());
        assert!(parse_request("GET /\nBad Header\n\n", false, &Bytes::new()).is_err());
        assert!(parse_request("GET relative HTTP/1.1\n\n", false, &Bytes::new()).is_err());
    }
}
