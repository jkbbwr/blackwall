//! Bridge between `blackwall_secrets::VmSecretTable` (`memfd_secret`-backed
//! [`blackwall_secrets::SecretBytes`]) and `blackwall_proxy::SecretResolver`.

use blackwall_proxy::SecretResolver;
use blackwall_secrets::{current_unix_sec, VmSecretTable};
use std::collections::BTreeMap;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Wraps an `Arc<VmSecretTable>` and implements [`blackwall_proxy::SecretResolver`].
///
/// - Placeholder checks delegate to `VmSecretTable::verify_placeholder` (constant-time).
/// - Secret reads fetch directly from `memfd_secret`-backed `SecretBytes` (checking any
///   authenticated `SealBinding` expiration before returning a `Zeroizing<String>`).
#[derive(Clone, Debug)]
pub struct VmSecretTableBridge {
    table: Arc<VmSecretTable>,
}

impl VmSecretTableBridge {
    /// Wrap a shared [`VmSecretTable`].
    pub fn new(table: Arc<VmSecretTable>) -> Self {
        Self { table }
    }

    /// Wrap an owned [`VmSecretTable`].
    pub fn from_table(table: VmSecretTable) -> Self {
        Self {
            table: Arc::new(table),
        }
    }

    /// Access the underlying `Arc<VmSecretTable>`.
    pub fn inner(&self) -> &Arc<VmSecretTable> {
        &self.table
    }

    /// Snapshot all minted guest placeholders (`secret_name -> placeholder`).
    pub fn guest_placeholders(&self) -> BTreeMap<String, String> {
        self.table.guest_placeholders()
    }
}

impl From<Arc<VmSecretTable>> for VmSecretTableBridge {
    fn from(table: Arc<VmSecretTable>) -> Self {
        Self::new(table)
    }
}

impl From<VmSecretTable> for VmSecretTableBridge {
    fn from(table: VmSecretTable) -> Self {
        Self::from_table(table)
    }
}

impl SecretResolver for VmSecretTableBridge {
    fn verify_placeholder(&self, secret_name: &str, presented: &str) -> bool {
        self.table.verify_placeholder(secret_name, presented)
    }

    fn resolve_secret(&self, secret_name: &str) -> Option<Zeroizing<String>> {
        if let Some(binding) = self.table.binding(secret_name) {
            if binding.check_expiration(current_unix_sec()).is_err() {
                return None;
            }
        }
        let placeholder = self.table.get_placeholder(secret_name)?;
        let secret_bytes = self.table.verify_and_get(secret_name, placeholder).ok()?;
        let secret_str = secret_bytes.as_str().ok()?;
        Some(Zeroizing::new(secret_str.to_owned()))
    }

    fn placeholder_for(&self, secret_name: &str) -> Option<String> {
        self.table
            .get_placeholder(secret_name)
            .map(ToOwned::to_owned)
    }

    fn all_placeholders(&self) -> Vec<(String, String)> {
        self.table.guest_placeholders().into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_policy::{AuthSpec, HttpRule, NetworkMode, SandboxSpec, SecretSpec};
    use blackwall_secrets::{seal_secret, HostKeyPair, SealBinding};

    #[test]
    fn bridge_verifies_placeholders_in_constant_time_and_reads_memfd_secret() {
        let kp = HostKeyPair::generate();
        let binding = SealBinding {
            allow_hosts: vec!["api.github.com".into()],
            allow_path_templates: vec!["/repos/org/repo/".into()],
            policy_tag: "test-agent".into(),
            exp_unix_sec: Some(current_unix_sec() + 3600),
        };
        let sealed_gh =
            seal_secret(kp.public_key(), b"ghp_REAL_MEMFD_SECRET_VALUE", &binding).unwrap();

        let mut spec = SandboxSpec::base();
        spec.network.mode = NetworkMode::Egress;
        spec.network.http.push(HttpRule {
            host: "api.github.com".into(),
            port: 443,
            methods: vec!["GET".into(), "POST".into()],
            path_prefixes: vec!["/repos/org/repo/".into()],
            max_request_bytes: None,
            auth: Some(AuthSpec::Bearer {
                secret: "GITHUB_TOKEN".into(),
            }),
        });
        spec.secrets.insert(
            "GITHUB_TOKEN".into(),
            SecretSpec {
                placeholder_prefix: "ghp_bw00_".into(),
                sealed: Some(sealed_gh),
                ephemeral: None,
            },
        );
        spec.secrets.insert(
            "EPHEMERAL_API_KEY".into(),
            SecretSpec {
                placeholder_prefix: "sk_bw00_".into(),
                sealed: None,
                ephemeral: Some("sk_REAL_EPHEMERAL_VALUE".into()),
            },
        );

        let (table, placeholders) = VmSecretTable::from_sandbox_spec(
            &mut spec,
            Some(&kp),
            Some("test-agent"),
            current_unix_sec(),
        )
        .unwrap();
        let bridge = VmSecretTableBridge::new(Arc::new(table));
        let resolver: &dyn SecretResolver = &bridge;

        let gh_ph = &placeholders["GITHUB_TOKEN"];
        let eph_ph = &placeholders["EPHEMERAL_API_KEY"];

        // Valid placeholders succeed and resolve real memfd_secret values.
        assert!(resolver.verify_placeholder("GITHUB_TOKEN", gh_ph));
        assert!(resolver.verify_placeholder("EPHEMERAL_API_KEY", eph_ph));
        assert_eq!(resolver.placeholder_for("GITHUB_TOKEN").as_deref(), Some(gh_ph.as_str()));
        assert_eq!(
            resolver.resolve_secret("GITHUB_TOKEN").unwrap().as_str(),
            "ghp_REAL_MEMFD_SECRET_VALUE"
        );
        assert_eq!(
            resolver.resolve_secret("EPHEMERAL_API_KEY").unwrap().as_str(),
            "sk_REAL_EPHEMERAL_VALUE"
        );

        // Attacker / BYO / real-value-as-placeholder attempts are rejected.
        assert!(!resolver.verify_placeholder("GITHUB_TOKEN", "ghp_ATTACKER_TOKEN"));
        assert!(!resolver.verify_placeholder("GITHUB_TOKEN", "ghp_REAL_MEMFD_SECRET_VALUE"));
        assert!(!resolver.verify_placeholder("GITHUB_TOKEN", eph_ph));
        assert!(!resolver.verify_placeholder("NON_EXISTENT", gh_ph));
        assert!(resolver.resolve_secret("NON_EXISTENT").is_none());

        // Debug representation never leaks real secret values.
        let dbg = format!("{bridge:?}");
        assert!(!dbg.contains("ghp_REAL_MEMFD_SECRET_VALUE"));
        assert!(!dbg.contains("sk_REAL_EPHEMERAL_VALUE"));
    }
}
