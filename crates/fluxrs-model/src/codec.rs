//! Content-Encoding decoding (gzip, deflate, br). Pure Rust, works in wasm.

use crate::exchange::{header_value, HeaderList};
use bytes::Bytes;
use std::io::Read;

/// Decode a body according to `Content-Encoding` (gzip, deflate, br).
/// Returns `None` when the encoding is unknown or decoding fails.
pub fn decode_body(headers: &HeaderList, body: &[u8]) -> Option<Bytes> {
    let enc = header_value(headers, "content-encoding")
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    decode_with(&enc, body)
}

pub fn decode_with(encoding: &str, body: &[u8]) -> Option<Bytes> {
    // Multiple encodings are applied in order; decode in reverse.
    let encs: Vec<&str> = encoding
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && *s != "identity")
        .collect();
    let mut data = body.to_vec();
    for enc in encs.iter().rev() {
        let mut out = Vec::new();
        match *enc {
            "gzip" | "x-gzip" => {
                flate2::read::MultiGzDecoder::new(&data[..])
                    .read_to_end(&mut out)
                    .ok()?;
            }
            "deflate" => {
                // Spec says zlib-wrapped, but raw deflate is common too.
                if flate2::read::ZlibDecoder::new(&data[..])
                    .read_to_end(&mut out)
                    .is_err()
                {
                    out.clear();
                    flate2::read::DeflateDecoder::new(&data[..])
                        .read_to_end(&mut out)
                        .ok()?;
                }
            }
            "br" => {
                brotli::Decompressor::new(&data[..], 4096)
                    .read_to_end(&mut out)
                    .ok()?;
            }
            _ => return None,
        }
        data = out;
    }
    Some(Bytes::from(data))
}

/// True when the body is encoded with something other than identity.
pub fn is_encoded(headers: &HeaderList) -> bool {
    header_value(headers, "content-encoding")
        .map(|v| {
            v.split(',')
                .any(|e| !e.trim().is_empty() && !e.trim().eq_ignore_ascii_case("identity"))
        })
        .unwrap_or(false)
}
