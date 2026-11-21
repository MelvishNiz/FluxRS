//! HTTPS session details shown in the inspector.

use crate::model::{CertSummary, TlsInfo};
use x509_parser::prelude::*;

/// Summary of a DER certificate (subject, issuer, validity, SANs).
pub fn summarize_cert(der: &[u8]) -> Option<CertSummary> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let mut san = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(d) => san.push((*d).to_string()),
                GeneralName::IPAddress(ip) => san.push(format_ip(ip)),
                _ => {}
            }
        }
    }
    Some(CertSummary {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
        serial: cert.raw_serial_as_string(),
        san,
    })
}

fn format_ip(raw: &[u8]) -> String {
    match raw.len() {
        4 => std::net::Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]).to_string(),
        16 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(raw);
            std::net::Ipv6Addr::from(b).to_string()
        }
        _ => format!("{raw:02x?}"),
    }
}

pub(crate) fn version_name(v: rustls::ProtocolVersion) -> String {
    match v {
        rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".into(),
        rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".into(),
        other => format!("{other:?}"),
    }
}

/// Client side (browser <-> FluxRS) negotiated parameters.
pub(crate) fn from_server_conn(conn: &rustls::ServerConnection, sni: Option<String>) -> TlsInfo {
    TlsInfo {
        sni: sni.or_else(|| conn.server_name().map(|s| s.to_string())),
        client_version: conn.protocol_version().map(version_name),
        client_cipher: conn
            .negotiated_cipher_suite()
            .map(|c| format!("{:?}", c.suite())),
        client_alpn: conn
            .alpn_protocol()
            .map(|a| String::from_utf8_lossy(a).into_owned()),
        ..Default::default()
    }
}

/// Upstream (FluxRS <-> server) parameters and certificate.
#[derive(Debug, Clone, Default)]
pub(crate) struct UpstreamTls {
    pub version: Option<String>,
    pub cipher: Option<String>,
    pub cert: Option<CertSummary>,
    pub chain_len: usize,
}

pub(crate) fn from_client_conn(conn: &rustls::ClientConnection) -> UpstreamTls {
    let certs = conn.peer_certificates().unwrap_or(&[]);
    UpstreamTls {
        version: conn.protocol_version().map(version_name),
        cipher: conn
            .negotiated_cipher_suite()
            .map(|c| format!("{:?}", c.suite())),
        cert: certs.first().and_then(|c| summarize_cert(c)),
        chain_len: certs.len(),
    }
}

pub(crate) fn merge(client: Option<&TlsInfo>, up: Option<&UpstreamTls>) -> Option<TlsInfo> {
    if client.is_none() && up.is_none() {
        return None;
    }
    let mut info = client.cloned().unwrap_or_default();
    if let Some(u) = up {
        info.server_version = u.version.clone();
        info.server_cipher = u.cipher.clone();
        info.server_cert = u.cert.clone();
        info.server_chain_len = u.chain_len;
    }
    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_generated_cert() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params =
            rcgen::CertificateParams::new(vec!["example.com".into(), "10.0.0.1".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let s = summarize_cert(cert.der()).unwrap();
        assert_eq!(
            s.san,
            vec!["example.com".to_string(), "10.0.0.1".to_string()]
        );
        assert!(!s.not_after.is_empty());
        assert!(summarize_cert(b"garbage").is_none());
    }
}
