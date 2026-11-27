//! Ephemeral per-VM ECDSA P-256 MITM Certificate Authority and dynamic SNI leaf signer.
//!
//! Each VM running in `network.mode = "egress"` mints its own in-memory ECDSA P-256 Root CA
//! whose PEM certificate is injected into the guest trust store at boot (`Port 1002`).
//! Incoming TLS handshakes (Pingora HTTP/1.1 & HTTP/2 and Postgres `SSLRequest`) dynamically
//! mint and cache leaf certificates per SNI hostname via [`rustls::server::ResolvesServerCert`].

use crate::error::{ProxyError, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig};
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

/// Ephemeral per-VM ECDSA P-256 Root CA that signs SNI leaf certificates on demand.
pub struct EphemeralCa {
    sandbox_id: String,
    issuer: Issuer<'static, KeyPair>,
    ca_cert_pem: String,
    ca_cert_der: CertificateDer<'static>,
    leaf_cache: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    default_sni: String,
}

impl fmt::Debug for EphemeralCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralCa")
            .field("sandbox_id", &self.sandbox_id)
            .field("default_sni", &self.default_sni)
            .field(
                "cached_leaves",
                &self.leaf_cache.read().map(|g| g.len()).unwrap_or(0),
            )
            .finish()
    }
}

fn build_ca_params(sandbox_id: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Blackwall Sandbox Ephemeral CA");
    params
        .distinguished_name
        .push(DnType::CommonName, format!("blackwall-vm-ca-{sandbox_id}"));
    params
}

fn decode_cert_pem(cert_pem: &str) -> Result<CertificateDer<'static>> {
    let mut in_block = false;
    let mut b64 = String::new();
    for line in cert_pem.lines() {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN CERTIFICATE-----" {
            in_block = true;
            continue;
        }
        if trimmed == "-----END CERTIFICATE-----" {
            break;
        }
        if in_block {
            b64.push_str(trimmed);
        }
    }
    if !in_block || b64.is_empty() {
        return Err(ProxyError::Tls(
            "invalid PEM certificate: missing BEGIN/END CERTIFICATE block".into(),
        ));
    }
    let der = BASE64
        .decode(b64.as_bytes())
        .map_err(|e| ProxyError::Tls(format!("invalid base64 in CA certificate PEM: {e}")))?;
    Ok(CertificateDer::from(der))
}

impl EphemeralCa {
    /// Generate a fresh ephemeral ECDSA P-256 Root CA for `sandbox_id`.
    pub fn generate(sandbox_id: impl Into<String>) -> Result<Self> {
        let sandbox_id = sandbox_id.into();
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| ProxyError::Tls(format!("failed to generate ECDSA P-256 CA key: {e}")))?;

        let params = build_ca_params(&sandbox_id);
        let cert = params
            .self_signed(&ca_key)
            .map_err(|e| ProxyError::Tls(format!("failed to self-sign ephemeral CA: {e}")))?;

        let ca_cert_pem = cert.pem();
        let ca_cert_der = cert.der().clone();
        let issuer = Issuer::new(params, ca_key);

        Ok(Self {
            sandbox_id,
            issuer,
            ca_cert_pem,
            ca_cert_der,
            leaf_cache: RwLock::new(HashMap::new()),
            default_sni: "localhost".to_string(),
        })
    }

    /// Reconstruct an [`EphemeralCa`] in-memory from a PEM certificate + PKCS#8 private key pair
    /// (handed to a jailed child `blackwall-proxy` over an anonymous memory pipe — NEVER disk).
    pub fn from_pem_pair(
        sandbox_id: impl Into<String>,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<Self> {
        let sandbox_id = sandbox_id.into();
        let ca_cert_der = decode_cert_pem(cert_pem)?;
        let ca_key = KeyPair::from_pem(key_pem)
            .map_err(|e| ProxyError::Tls(format!("failed to parse CA private key PEM: {e}")))?;
        let params = build_ca_params(&sandbox_id);
        let issuer = Issuer::new(params, ca_key);

        Ok(Self {
            sandbox_id,
            issuer,
            ca_cert_pem: cert_pem.to_string(),
            ca_cert_der,
            leaf_cache: RwLock::new(HashMap::new()),
            default_sni: "localhost".to_string(),
        })
    }

    /// Override the fallback hostname used when a client omits TLS SNI.
    pub fn with_default_sni(mut self, host: impl Into<String>) -> Self {
        self.default_sni = normalize_sni(&host.into());
        self
    }

    /// PEM-encoded Root CA certificate for injection into the guest trust store.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// PEM-encoded Root CA PKCS#8 private key (wrapped in [`Zeroizing`] so callers wipe it
    /// immediately after writing to the child proxy's memory pipe).
    pub fn ca_key_pem(&self) -> Zeroizing<String> {
        Zeroizing::new(self.issuer.key().serialize_pem())
    }

    /// DER-encoded Root CA certificate.
    pub fn ca_cert_der(&self) -> CertificateDer<'static> {
        self.ca_cert_der.clone()
    }

    /// Build a `rustls::RootCertStore` trusting only this ephemeral CA.
    pub fn root_cert_store(&self) -> Result<RootCertStore> {
        let mut store = RootCertStore::empty();
        store
            .add(self.ca_cert_der.clone())
            .map_err(|e| ProxyError::Tls(format!("failed to add CA to RootCertStore: {e}")))?;
        Ok(store)
    }

    /// Return the number of leaf certificates currently cached.
    pub fn cached_leaf_count(&self) -> usize {
        self.leaf_cache.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Mint (or retrieve from cache) an ECDSA P-256 leaf `CertifiedKey` for `host`.
    pub fn leaf_for_host(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        let normalized = normalize_sni(host);
        if normalized.is_empty() {
            return Err(ProxyError::Tls("empty SNI hostname".into()));
        }

        if let Ok(cache) = self.leaf_cache.read() {
            if let Some(existing) = cache.get(&normalized) {
                return Ok(Arc::clone(existing));
            }
        }

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| ProxyError::Tls(format!("failed to generate leaf P-256 key: {e}")))?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params
            .distinguished_name
            .push(DnType::CommonName, normalized.clone());

        if let Ok(ip) = normalized.parse::<IpAddr>() {
            params.subject_alt_names.push(SanType::IpAddress(ip));
        } else {
            let ia5 = normalized
                .clone()
                .try_into()
                .map_err(|e| ProxyError::Tls(format!("invalid DNS SAN '{normalized}': {e}")))?;
            params.subject_alt_names.push(SanType::DnsName(ia5));
        }

        let leaf_cert = params
            .signed_by(&leaf_key, &self.issuer)
            .map_err(|e| ProxyError::Tls(format!("failed to sign leaf cert for '{normalized}': {e}")))?;

        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let signing_key = ring::sign::any_ecdsa_type(&key_der)
            .map_err(|e| ProxyError::Tls(format!("failed to load leaf signing key: {e}")))?;

        let certified = Arc::new(CertifiedKey::new(
            vec![leaf_cert.der().clone(), self.ca_cert_der.clone()],
            signing_key,
        ));

        if let Ok(mut cache) = self.leaf_cache.write() {
            let entry = cache
                .entry(normalized)
                .or_insert_with(|| Arc::clone(&certified));
            return Ok(Arc::clone(entry));
        }

        Ok(certified)
    }

    /// Build a `rustls::ServerConfig` backed by this dynamic SNI resolver.
    pub fn server_config(self: &Arc<Self>, alpn_protocols: Vec<Vec<u8>>) -> Result<Arc<ServerConfig>> {
        let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| ProxyError::Tls(format!("failed to configure TLS versions: {e}")))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(self) as Arc<dyn ResolvesServerCert>);
        config.alpn_protocols = alpn_protocols;
        Ok(Arc::new(config))
    }
}

impl ResolvesServerCert for EphemeralCa {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello
            .server_name()
            .unwrap_or(&self.default_sni);
        self.leaf_for_host(sni).ok()
    }
}

fn normalize_sni(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use rustls::ClientConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[tokio::test]
    async fn ephemeral_ca_mints_and_verifies_dynamic_sni_leaves() {
        let ca = Arc::new(EphemeralCa::generate("sb-ca-test").unwrap());
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(ca.ca_cert_pem().contains("END CERTIFICATE"));

        // Mint and verify caching
        let cert1 = ca.leaf_for_host("api.github.com").unwrap();
        let cert2 = ca.leaf_for_host("API.GITHUB.COM.").unwrap();
        assert!(Arc::ptr_eq(&cert1, &cert2));
        assert_eq!(ca.cached_leaf_count(), 1);

        let cert3 = ca.leaf_for_host("db.internal").unwrap();
        assert!(!Arc::ptr_eq(&cert1, &cert3));
        assert_eq!(ca.cached_leaf_count(), 2);

        // Perform a real TLS 1.3 handshake verifying the dynamic SNI leaf against the ephemeral CA
        let server_cfg = ca.server_config(vec![b"http/1.1".to_vec()]).unwrap();
        let acceptor = TlsAcceptor::from(server_cfg);

        let client_cfg = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(ca.root_cert_store().unwrap())
                .with_no_client_auth(),
        );
        let connector = TlsConnector::from(client_cfg);

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);

        let server_task = tokio::spawn(async move {
            let mut tls = acceptor.accept(server_io).await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            tls.write_all(b"world").await.unwrap();
            tls.shutdown().await.unwrap();
        });

        let sni = ServerName::try_from("api.anthropic.com".to_string()).unwrap();
        let mut client_tls = connector.connect(sni, client_io).await.unwrap();
        client_tls.write_all(b"hello").await.unwrap();
        let mut resp = [0u8; 5];
        client_tls.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"world");
        server_task.await.unwrap();

        // New SNI hostname was dynamically minted and cached
        assert_eq!(ca.cached_leaf_count(), 3);
    }

    #[tokio::test]
    async fn client_rejects_untrusted_other_vm_ca() {
        let ca_vm1 = Arc::new(EphemeralCa::generate("vm-1").unwrap());
        let ca_vm2 = Arc::new(EphemeralCa::generate("vm-2").unwrap());

        let acceptor = TlsAcceptor::from(ca_vm1.server_config(vec![]).unwrap());
        let client_cfg = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(ca_vm2.root_cert_store().unwrap())
                .with_no_client_auth(),
        );
        let connector = TlsConnector::from(client_cfg);

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let _ = acceptor.accept(server_io).await;
        });

        let sni = ServerName::try_from("api.github.com".to_string()).unwrap();
        let err = connector.connect(sni, client_io).await;
        assert!(err.is_err(), "VM2 trust store must reject VM1 ephemeral CA");
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn from_pem_pair_reconstructs_ca_and_signs_trusted_leaves() {
        let orig = Arc::new(EphemeralCa::generate("vm-rehydrate").unwrap());
        let cert_pem = orig.ca_cert_pem().to_string();
        let key_pem = orig.ca_key_pem();
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));

        let restored = Arc::new(
            EphemeralCa::from_pem_pair("vm-rehydrate", &cert_pem, &key_pem)
                .expect("from_pem_pair must succeed"),
        );

        let acceptor = TlsAcceptor::from(restored.server_config(vec![b"http/1.1".to_vec()]).unwrap());
        let client_cfg = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(orig.root_cert_store().unwrap())
                .with_no_client_auth(),
        );
        let connector = TlsConnector::from(client_cfg);

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let mut tls = acceptor.accept(server_io).await.unwrap();
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            tls.write_all(b"pong").await.unwrap();
            tls.shutdown().await.unwrap();
        });

        let sni = ServerName::try_from("api.example.test".to_string()).unwrap();
        let mut client_tls = connector.connect(sni, client_io).await.unwrap();
        client_tls.write_all(b"ping").await.unwrap();
        let mut resp = [0u8; 4];
        client_tls.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"pong");
        server_task.await.unwrap();
    }
}
