//! Body helpers: content decoding, header normalization, streaming tee.

use crate::model::HeaderList;
use bytes::{Bytes, BytesMut};
use http_body::{Body, Frame, SizeHint};
use std::io::Read;
use std::pin::Pin;
use std::task::{Context, Poll};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Decode a body according to `Content-Encoding` (gzip, deflate, br).
/// Returns `None` when the encoding is unknown or decoding fails.
pub fn decode_body(headers: &HeaderList, body: &[u8]) -> Option<Bytes> {
    let enc = crate::model::header_value(headers, "content-encoding")
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
    crate::model::header_value(headers, "content-encoding")
        .map(|v| {
            v.split(',')
                .any(|e| !e.trim().is_empty() && !e.trim().eq_ignore_ascii_case("identity"))
        })
        .unwrap_or(false)
}

/// Fix framing headers for a fully buffered body.
pub fn set_fixed_length(headers: &mut HeaderList, len: usize) {
    crate::rules::remove_header(headers, "transfer-encoding");
    crate::rules::set_header(headers, "Content-Length", &len.to_string());
}

/// Hop-by-hop headers that must not be forwarded.
pub fn strip_hop_by_hop(headers: &mut HeaderList, keep_upgrade: bool) {
    // Headers listed in `Connection` are hop-by-hop as well.
    let listed: Vec<String> = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(',').map(|s| s.trim().to_ascii_lowercase()))
        .filter(|s| !s.is_empty())
        .collect();
    headers.retain(|(n, _)| {
        let l = n.to_ascii_lowercase();
        let base = matches!(
            l.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-connection"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
        );
        if keep_upgrade && (l == "connection" || l == "upgrade") {
            return true;
        }
        !base && !(listed.contains(&l) && !(keep_upgrade && l == "upgrade"))
    });
}

type DoneFn = Box<dyn FnOnce(Bytes, bool, Option<String>) + Send + Sync>;

/// Body wrapper forwarding frames while keeping a (capped) copy.
/// `on_done(body, truncated, error)` runs once at end, on error or on drop.
pub struct TeeBody<B: Body> {
    inner: B,
    buf: BytesMut,
    cap: usize,
    truncated: bool,
    on_done: Option<DoneFn>,
}

impl<B: Body> TeeBody<B> {
    pub fn new(
        inner: B,
        cap: usize,
        on_done: impl FnOnce(Bytes, bool, Option<String>) + Send + Sync + 'static,
    ) -> Self {
        TeeBody {
            inner,
            buf: BytesMut::new(),
            cap,
            truncated: false,
            on_done: Some(Box::new(on_done)),
        }
    }

    fn finish(&mut self, err: Option<String>) {
        if let Some(f) = self.on_done.take() {
            let body = std::mem::take(&mut self.buf).freeze();
            f(body, self.truncated, err);
        }
    }
}

impl<B: Body> Drop for TeeBody<B> {
    fn drop(&mut self) {
        if self.on_done.is_some() {
            if self.inner.is_end_stream() {
                self.finish(None);
            } else {
                self.finish(Some("body transfer aborted".into()));
            }
        }
    }
}

impl<B: Body> TeeBody<B> {
    /// Hyper may stop polling once the size hint is satisfied, so the
    /// end is detected after every frame too.
    fn check_end(&mut self) {
        if self.on_done.is_some() && self.inner.is_end_stream() {
            self.finish(None);
        }
    }
}

impl<B> Body for TeeBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let room = this.cap.saturating_sub(this.buf.len());
                    if data.len() > room {
                        this.truncated = true;
                    }
                    this.buf.extend_from_slice(&data[..data.len().min(room)]);
                }
                this.check_end();
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.finish(Some(e.to_string()));
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.finish(None);
                Poll::Ready(None)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn decodes_gzip_deflate_brotli() {
        let plain = b"hello hello hello fluxrs";
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(plain).unwrap();
        let gz = gz.finish().unwrap();
        let h = vec![("Content-Encoding".to_string(), "gzip".to_string())];
        assert_eq!(&decode_body(&h, &gz).unwrap()[..], plain);
        assert!(is_encoded(&h));

        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(plain).unwrap();
        assert_eq!(
            &decode_with("deflate", &z.finish().unwrap()).unwrap()[..],
            plain
        );

        let mut raw =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(plain).unwrap();
        assert_eq!(
            &decode_with("deflate", &raw.finish().unwrap()).unwrap()[..],
            plain
        );

        let mut br = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut br, 4096, 5, 22);
            w.write_all(plain).unwrap();
        }
        assert_eq!(&decode_with("br", &br).unwrap()[..], plain);
        assert_eq!(&decode_with("", plain).unwrap()[..], plain);
        assert!(decode_with("zstd", plain).is_none());
    }

    #[test]
    fn hop_by_hop_removed() {
        let mut h: HeaderList = vec![
            ("Connection".into(), "keep-alive, X-Foo".into()),
            ("X-Foo".into(), "1".into()),
            ("Keep-Alive".into(), "timeout=5".into()),
            ("Transfer-Encoding".into(), "chunked".into()),
            ("Content-Type".into(), "text/plain".into()),
        ];
        strip_hop_by_hop(&mut h, false);
        assert_eq!(
            h,
            vec![("Content-Type".to_string(), "text/plain".to_string())]
        );

        let mut h: HeaderList = vec![
            ("Connection".into(), "Upgrade".into()),
            ("Upgrade".into(), "websocket".into()),
        ];
        strip_hop_by_hop(&mut h, true);
        assert_eq!(h.len(), 2);
    }

    #[tokio::test]
    async fn tee_body_captures_with_cap() {
        use http_body_util::{BodyExt, Full};
        let (tx, rx) = std::sync::mpsc::channel();
        let body = TeeBody::new(
            Full::new(Bytes::from_static(b"0123456789")),
            4,
            move |b, t, e| {
                tx.send((b, t, e)).unwrap();
            },
        );
        let collected = body.collect().await.unwrap().to_bytes();
        assert_eq!(&collected[..], b"0123456789");
        let (b, truncated, err) = rx.recv().unwrap();
        assert_eq!(&b[..], b"0123");
        assert!(truncated);
        assert!(err.is_none());
    }
}
