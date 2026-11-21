//! TLS helpers: ClientHello SNI sniffing, upstream client configs.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sniff {
    /// Not enough bytes yet.
    NeedMore,
    /// The stream does not start with a TLS handshake record.
    NotTls,
    /// TLS ClientHello; SNI if present and parsable.
    Tls(Option<String>),
}

const MAX_RECORD: usize = 16384 + 2048;

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|b| ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize)
    }
}

/// Inspect the first bytes of a client stream.
pub fn sniff_client_hello(buf: &[u8]) -> Sniff {
    if buf.is_empty() {
        return Sniff::NeedMore;
    }
    if buf[0] != 0x16 {
        return Sniff::NotTls;
    }
    if buf.len() < 5 {
        return Sniff::NeedMore;
    }
    if buf[1] != 0x03 {
        return Sniff::NotTls;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if rec_len > MAX_RECORD {
        return Sniff::NotTls;
    }
    if buf.len() < 5 + rec_len {
        return Sniff::NeedMore;
    }
    Sniff::Tls(parse_sni(&buf[5..5 + rec_len]))
}

fn parse_sni(hs: &[u8]) -> Option<String> {
    let mut c = Cursor { buf: hs, pos: 0 };
    if c.u8()? != 1 {
        return None; // not ClientHello
    }
    let _len = c.u24()?;
    c.take(2 + 32)?; // version + random
    let sid = c.u8()? as usize;
    c.take(sid)?;
    let cs = c.u16()? as usize;
    c.take(cs)?;
    let comp = c.u8()? as usize;
    c.take(comp)?;
    let ext_len = c.u16()? as usize;
    let exts = c.take(ext_len.min(hs.len().saturating_sub(c.pos)))?;
    let mut e = Cursor { buf: exts, pos: 0 };
    while let (Some(ty), Some(len)) = (e.u16(), e.u16()) {
        let data = e.take(len as usize)?;
        if ty == 0 {
            let mut s = Cursor { buf: data, pos: 0 };
            let _list = s.u16()?;
            while let Some(kind) = s.u8() {
                let n = s.u16()? as usize;
                let name = s.take(n)?;
                if kind == 0 {
                    let name = std::str::from_utf8(name).ok()?;
                    if name.is_empty() {
                        return None;
                    }
                    return Some(name.to_ascii_lowercase());
                }
            }
            return None;
        }
    }
    None
}

pub fn client_config(provider: Arc<CryptoProvider>, insecure: bool) -> Arc<ClientConfig> {
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring provider supports default protocol versions");
    let mut cfg = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

pub fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    ServerName::try_from(h.to_string()).map_err(|e| format!("invalid server name '{host}': {e}"))
}

/// Accepts any upstream certificate (for local/self-signed test servers).
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Simple wildcard host match: `*.example.com`, `example.com`, `*`.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if p.is_empty() {
        return false;
    }
    if p == "*" {
        return true;
    }
    if let Some(suffix) = p.strip_prefix("*.") {
        return h == suffix || h.ends_with(&format!(".{suffix}"));
    }
    h == p
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a real ClientHello with rustls and check SNI extraction.
    #[test]
    fn sniff_real_client_hello() {
        let cfg = client_config(crate::cert::crypto_provider(), false);
        let mut conn =
            rustls::ClientConnection::new(cfg, server_name("www.Example.com").unwrap()).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        assert_eq!(
            sniff_client_hello(&out),
            Sniff::Tls(Some("www.example.com".into()))
        );
        assert_eq!(sniff_client_hello(&out[..3]), Sniff::NeedMore);
        assert_eq!(sniff_client_hello(&out[..out.len() - 1]), Sniff::NeedMore);
        assert_eq!(sniff_client_hello(b"GET / HTTP/1.1\r\n"), Sniff::NotTls);
        assert_eq!(sniff_client_hello(b""), Sniff::NeedMore);
    }

    #[test]
    fn ip_client_hello_has_no_sni() {
        let cfg = client_config(crate::cert::crypto_provider(), true);
        let mut conn =
            rustls::ClientConnection::new(cfg, server_name("10.0.0.1").unwrap()).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        assert_eq!(sniff_client_hello(&out), Sniff::Tls(None));
    }

    #[test]
    fn wildcard_hosts() {
        assert!(host_matches("*.example.com", "a.b.example.com"));
        assert!(host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "badexample.com"));
        assert!(host_matches("Example.com", "example.com."));
        assert!(host_matches("*", "x"));
        assert!(!host_matches("", "x"));
    }
}
