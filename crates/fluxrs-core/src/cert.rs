//! Root CA management and on-the-fly leaf certificate generation.

use parking_lot::Mutex;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

pub const CA_CERT_FILE: &str = "fluxrs-root-ca.crt";
pub const CA_KEY_FILE: &str = "fluxrs-root-ca.key";
pub const CA_COMMON_NAME: &str = "FluxRS Root CA";

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

pub fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

static SERIAL_COUNTER: AtomicU64 = AtomicU64::new(1);

fn random_serial() -> SerialNumber {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let counter = SERIAL_COUNTER.fetch_add(1, Ordering::Relaxed) as u128;
    let pid = std::process::id() as u128;
    let mut v =
        nanos ^ (counter << 64) ^ (pid << 96) ^ (counter.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    if v == 0 {
        v = 1;
    }
    let mut bytes = v.to_be_bytes();
    bytes[0] &= 0x7f; // keep it positive
    bytes[0] |= 0x01; // and non-zero leading byte
    SerialNumber::from_slice(&bytes)
}

pub struct CertificateAuthority {
    dir: PathBuf,
    ca_pem: String,
    ca_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    leaf_key: KeyPair,
    provider: Arc<CryptoProvider>,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateAuthority")
            .field("dir", &self.dir)
            .finish()
    }
}

fn pem_to_der(pem: &str) -> Result<CertificateDer<'static>, CertError> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| CertError::Other(format!("invalid CA PEM: {e:?}")))
}

impl CertificateAuthority {
    /// Load the root CA from `dir`, creating a new one when missing.
    pub fn load_or_create(dir: &Path) -> Result<Self, CertError> {
        std::fs::create_dir_all(dir)?;
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);
        let (ca_pem, key_pem) = if cert_path.exists() && key_path.exists() {
            (
                std::fs::read_to_string(&cert_path)?,
                std::fs::read_to_string(&key_path)?,
            )
        } else {
            let (c, k) = Self::generate_ca()?;
            std::fs::write(&key_path, &k)?;
            std::fs::write(&cert_path, &c)?;
            (c, k)
        };
        Self::from_pem(dir, ca_pem, &key_pem)
    }

    /// Delete and regenerate the root CA in `dir`.
    pub fn regenerate(dir: &Path) -> Result<Self, CertError> {
        let _ = std::fs::remove_file(dir.join(CA_CERT_FILE));
        let _ = std::fs::remove_file(dir.join(CA_KEY_FILE));
        Self::load_or_create(dir)
    }

    fn from_pem(dir: &Path, ca_pem: String, key_pem: &str) -> Result<Self, CertError> {
        let ca_key = KeyPair::from_pem(key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key)?;
        let ca_der = pem_to_der(&ca_pem)?;
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        Ok(CertificateAuthority {
            dir: dir.to_path_buf(),
            ca_pem,
            ca_der,
            issuer,
            leaf_key,
            provider: crypto_provider(),
            cache: Mutex::new(HashMap::new()),
        })
    }

    fn generate_ca() -> Result<(String, String), CertError> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, CA_COMMON_NAME);
        dn.push(DnType::OrganizationName, "FluxRS HTTP Debugger");
        dn.push(
            DnType::OrganizationalUnitName,
            "Local debugging CA - do not share",
        );
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(2);
        params.not_after = now + Duration::days(3650);
        params.serial_number = Some(random_serial());
        let cert = params.self_signed(&key)?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn ca_cert_path(&self) -> PathBuf {
        self.dir.join(CA_CERT_FILE)
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn ca_der(&self) -> &CertificateDer<'static> {
        &self.ca_der
    }

    pub fn provider(&self) -> Arc<CryptoProvider> {
        self.provider.clone()
    }

    /// Leaf certificate for `host` (DNS name or IP), cached.
    pub fn leaf_for(&self, host: &str) -> Result<Arc<CertifiedKey>, CertError> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return Err(CertError::Other("empty host name".into()));
        }
        if let Some(c) = self.cache.lock().get(&host) {
            return Ok(c.clone());
        }
        let ck = Arc::new(self.generate_leaf(&host)?);
        let mut cache = self.cache.lock();
        if cache.len() > 4096 {
            cache.clear();
        }
        cache.insert(host, ck.clone());
        Ok(ck)
    }

    fn generate_leaf(&self, host: &str) -> Result<CertifiedKey, CertError> {
        let mut params = CertificateParams::default();
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let san = match bare.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(host.to_string().try_into()?),
        };
        params.subject_alt_names = vec![san];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, bare);
        dn.push(DnType::OrganizationName, "FluxRS HTTP Debugger");
        params.distinguished_name = dn;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(365);
        params.serial_number = Some(random_serial());
        let cert = params.signed_by(&self.leaf_key, &self.issuer)?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let signing_key = self.provider.key_provider.load_private_key(key_der)?;
        Ok(CertifiedKey::new(
            vec![cert.der().clone(), self.ca_der.clone()],
            signing_key,
        ))
    }

    /// TLS server config presenting a forged certificate for `host`.
    pub fn server_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>, CertError> {
        let ck = self.leaf_for(host)?;
        let mut cfg = rustls::ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(FixedCert(ck)));
        // Only HTTP/1.1 is offered so clients never negotiate h2.
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(cfg))
    }

    /// Serial number of the root CA as plain hex (no separators).
    pub fn serial_hex(&self) -> String {
        crate::tlsinfo::summarize_cert(self.ca_der.as_ref())
            .map(|c| c.serial.replace(':', ""))
            .unwrap_or_default()
    }

    /// Is the root CA present in the OS trust store? (blocking, runs certutil)
    pub fn os_trust_status(&self) -> TrustStatus {
        os_trust_status(&self.serial_hex())
    }

    /// Install the root CA into the Windows trusted root store.
    pub fn install_in_os_store(&self) -> Result<String, CertError> {
        install_root_ca(&self.ca_cert_path())
    }
}

#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStatus {
    Trusted,
    NotTrusted,
    /// Not checkable on this platform.
    Unknown,
}

#[cfg(windows)]
fn os_trust_status(serial: &str) -> TrustStatus {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    if serial.is_empty() {
        return TrustStatus::Unknown;
    }
    let found = |user: bool| {
        let mut cmd = std::process::Command::new("certutil");
        if user {
            cmd.arg("-user");
        }
        cmd.args(["-store", "Root", serial])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    if found(false) || found(true) {
        TrustStatus::Trusted
    } else {
        TrustStatus::NotTrusted
    }
}

#[cfg(not(windows))]
fn os_trust_status(_serial: &str) -> TrustStatus {
    TrustStatus::Unknown
}

#[cfg(windows)]
fn install_root_ca(path: &Path) -> Result<String, CertError> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let run = |args: &[&str]| {
        std::process::Command::new("certutil")
            .args(args)
            .arg(path)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
    };
    // Machine store first (needs admin, no prompt), then the user store.
    let out = run(&["-addstore", "-f", "Root"])?;
    if out.status.success() {
        return Ok("Root CA installed in the local machine trust store.".into());
    }
    let out2 = run(&["-addstore", "-user", "-f", "Root"])?;
    if out2.status.success() {
        return Ok("Root CA installed in the current user trust store.".into());
    }
    Err(CertError::Other(format!(
        "certutil failed: {}",
        String::from_utf8_lossy(&out2.stdout).trim()
    )))
}

#[cfg(not(windows))]
fn install_root_ca(path: &Path) -> Result<String, CertError> {
    Err(CertError::Other(format!(
        "Automatic install is only supported on Windows. Import {} manually.",
        path.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_reload_and_issue() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CertificateAuthority::load_or_create(dir.path()).unwrap();
        assert!(ca.ca_pem().contains("BEGIN CERTIFICATE"));
        let pem1 = ca.ca_pem().to_string();
        let ca2 = CertificateAuthority::load_or_create(dir.path()).unwrap();
        assert_eq!(pem1, ca2.ca_pem());
        let leaf = ca2.leaf_for("example.com").unwrap();
        assert_eq!(leaf.cert.len(), 2);
        let again = ca2.leaf_for("EXAMPLE.com").unwrap();
        assert!(Arc::ptr_eq(&leaf, &again));
        ca2.leaf_for("127.0.0.1").unwrap();
        assert!(ca2.serial_hex().len() >= 2);
        assert!(!ca2.serial_hex().contains(':'));
        ca2.server_config("example.com").unwrap();
        let ca3 = CertificateAuthority::regenerate(dir.path()).unwrap();
        assert_ne!(pem1, ca3.ca_pem());
    }
}
