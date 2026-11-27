//! Ephemeral secret intake, 256-bit random SDK-shaped placeholder minting,
//! and per-VM [`VmSecretTable`] for `blackwall-proxy`.

use crate::error::{Result, SecretError};
use crate::hpke_seal::{open_sealed, HostKeyPair, SealBinding};
use crate::mem::SecretBytes;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use blackwall_policy::{SandboxSpec, SecretSpec};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::BTreeMap;
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Number of cryptographically random bytes in every minted placeholder (256 bits).
pub const PLACEHOLDER_ENTROPY_BYTES: usize = 32;

/// Mint a 256-bit cryptographically random SDK-shaped placeholder carrying
/// zero mathematical relationship to any real secret.
///
/// Format: `<prefix><base64url_nopad(32 random bytes)>`.
pub fn mint_placeholder(prefix: &str) -> String {
    let mut entropy = [0u8; PLACEHOLDER_ENTROPY_BYTES];
    OsRng.fill_bytes(&mut entropy);
    let encoded = URL_SAFE_NO_PAD.encode(entropy);
    entropy.zeroize();
    format!("{prefix}{encoded}")
}

/// Constant-time byte-slice equality comparison (backed by `subtle::ConstantTimeEq`).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

struct VmSecretEntry {
    placeholder: String,
    secret: SecretBytes,
    binding: Option<SealBinding>,
}

impl fmt::Debug for VmSecretEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmSecretEntry")
            .field("placeholder", &self.placeholder)
            .field("secret", &self.secret)
            .field("binding", &self.binding)
            .finish()
    }
}

/// Per-VM secret table held exclusively inside that VM's jailed `blackwall-proxy`.
///
/// Maps secret logical names (e.g. `"GITHUB_TOKEN"`, `"PGPASSWORD"`) to their
/// minted guest placeholder, protected [`SecretBytes`], and optional authenticated
/// [`SealBinding`].
pub struct VmSecretTable {
    entries: BTreeMap<String, VmSecretEntry>,
}

impl Default for VmSecretTable {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for VmSecretTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmSecretTable")
            .field("entries", &self.entries)
            .finish()
    }
}

impl VmSecretTable {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Open all [`SecretSpec`] entries from a resolved [`SandboxSpec`]:
    /// - `sealed = "seal1_..."`: decrypted with `host_key`, expiration-checked
    ///   against `now_unix_sec`, and validated against all `[[network.http]]`
    ///   and `[[network.postgres]]` rules in `spec` that reference the secret
    ///   (plus optional `expected_policy_tag`).
    /// - `ephemeral = "..."`: copied into [`SecretBytes`] (`memfd_secret` /
    ///   `mlock`) and immediately zeroized & cleared from `spec.secrets`.
    ///
    /// Returns `(VmSecretTable, guest_placeholders)` where `guest_placeholders`
    /// maps secret names to freshly minted 256-bit random placeholders safe to
    /// inject into the guest environment.
    pub fn from_sandbox_spec(
        spec: &mut SandboxSpec,
        host_key: Option<&HostKeyPair>,
        expected_policy_tag: Option<&str>,
        now_unix_sec: u64,
    ) -> Result<(Self, BTreeMap<String, String>)> {
        let mut table = Self::new();
        let mut guest_placeholders = BTreeMap::new();

        // Collect per-secret referenced hosts and HTTP path prefixes up front.
        let mut secret_hosts: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut secret_paths: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for rule in &spec.network.http {
            if let Some(auth) = &rule.auth {
                let sname = auth.secret_name().to_string();
                secret_hosts
                    .entry(sname.clone())
                    .or_default()
                    .push(rule.host.clone());
                secret_paths
                    .entry(sname)
                    .or_default()
                    .extend(rule.path_prefixes.iter().cloned());
            }
        }
        for rule in &spec.network.postgres {
            secret_hosts
                .entry(rule.secret.clone())
                .or_default()
                .push(rule.host.clone());
        }

        for (name, secret_spec) in spec.secrets.iter_mut() {
            let (secret_bytes, binding) = open_secret_spec(
                name,
                secret_spec,
                host_key,
                secret_hosts.get(name).map(Vec::as_slice).unwrap_or(&[]),
                secret_paths.get(name).map(Vec::as_slice).unwrap_or(&[]),
                expected_policy_tag,
                now_unix_sec,
            )?;

            let placeholder = mint_placeholder(&secret_spec.placeholder_prefix);
            guest_placeholders.insert(name.clone(), placeholder.clone());
            table.entries.insert(
                name.clone(),
                VmSecretEntry {
                    placeholder,
                    secret: secret_bytes,
                    binding,
                },
            );
        }

        Ok((table, guest_placeholders))
    }

    /// Open a standalone map of [`SecretSpec`]s against explicit allowed hosts,
    /// path prefixes, and optional policy tag.
    ///
    /// Ephemeral plaintext inputs in `specs` are copied into [`SecretBytes`]
    /// and immediately zeroized & cleared.
    pub fn from_secret_specs(
        specs: &mut BTreeMap<String, SecretSpec>,
        host_key: Option<&HostKeyPair>,
        allowed_hosts: &[String],
        allowed_path_prefixes: &[String],
        expected_policy_tag: Option<&str>,
        now_unix_sec: u64,
    ) -> Result<(Self, BTreeMap<String, String>)> {
        let mut table = Self::new();
        let mut guest_placeholders = BTreeMap::new();

        for (name, secret_spec) in specs.iter_mut() {
            let (secret_bytes, binding) = open_secret_spec(
                name,
                secret_spec,
                host_key,
                allowed_hosts,
                allowed_path_prefixes,
                expected_policy_tag,
                now_unix_sec,
            )?;

            let placeholder = mint_placeholder(&secret_spec.placeholder_prefix);
            guest_placeholders.insert(name.clone(), placeholder.clone());
            table.entries.insert(
                name.clone(),
                VmSecretEntry {
                    placeholder,
                    secret: secret_bytes,
                    binding,
                },
            );
        }

        Ok((table, guest_placeholders))
    }

    /// Insert a single ephemeral secret directly, zeroizing `secret` immediately
    /// after copying into [`SecretBytes`], and return its minted placeholder.
    pub fn insert_ephemeral(
        &mut self,
        name: impl Into<String>,
        placeholder_prefix: &str,
        secret: String,
    ) -> String {
        let placeholder = mint_placeholder(placeholder_prefix);
        let secret_bytes = SecretBytes::from_string(secret);
        self.entries.insert(
            name.into(),
            VmSecretEntry {
                placeholder: placeholder.clone(),
                secret: secret_bytes,
                binding: None,
            },
        );
        placeholder
    }

    /// Verify a guest-supplied placeholder for `secret_name` in constant time.
    pub fn verify_placeholder(&self, secret_name: &str, presented_placeholder: &str) -> bool {
        match self.entries.get(secret_name) {
            Some(entry) => {
                constant_time_eq(entry.placeholder.as_bytes(), presented_placeholder.as_bytes())
            }
            None => false,
        }
    }

    /// Constant-time verify `presented_placeholder` for `secret_name` and return
    /// a borrow of the real [`SecretBytes`] for upstream auth injection.
    pub fn verify_and_get(
        &self,
        secret_name: &str,
        presented_placeholder: &str,
    ) -> Result<&SecretBytes> {
        let entry = self
            .entries
            .get(secret_name)
            .ok_or_else(|| SecretError::SecretNotFound(secret_name.to_string()))?;

        if !constant_time_eq(entry.placeholder.as_bytes(), presented_placeholder.as_bytes()) {
            return Err(SecretError::PlaceholderMismatch(secret_name.to_string()));
        }

        Ok(&entry.secret)
    }

    /// Verify the guest placeholder in constant time AND re-enforce any
    /// [`SealBinding`] host, path, and expiration constraints at request time.
    pub fn verify_and_get_for_target(
        &self,
        secret_name: &str,
        presented_placeholder: &str,
        host: &str,
        path: Option<&str>,
        now_unix_sec: u64,
    ) -> Result<&SecretBytes> {
        let entry = self
            .entries
            .get(secret_name)
            .ok_or_else(|| SecretError::SecretNotFound(secret_name.to_string()))?;

        if !constant_time_eq(entry.placeholder.as_bytes(), presented_placeholder.as_bytes()) {
            return Err(SecretError::PlaceholderMismatch(secret_name.to_string()));
        }

        if let Some(binding) = &entry.binding {
            let paths: Vec<&str> = path.into_iter().collect();
            binding.validate_usage(&[host], &paths, None, now_unix_sec)?;
        }

        Ok(&entry.secret)
    }

    /// Look up the minted guest placeholder for `secret_name`.
    pub fn get_placeholder(&self, secret_name: &str) -> Option<&str> {
        self.entries.get(secret_name).map(|e| e.placeholder.as_str())
    }

    /// Snapshot all guest placeholders (`name -> placeholder`).
    pub fn guest_placeholders(&self) -> BTreeMap<String, String> {
        self.entries
            .iter()
            .map(|(k, v)| (k.clone(), v.placeholder.clone()))
            .collect()
    }

    /// Inspect the authenticated [`SealBinding`] for `secret_name` if it was opened
    /// from a `seal1_` token.
    pub fn binding(&self, secret_name: &str) -> Option<&SealBinding> {
        self.entries
            .get(secret_name)
            .and_then(|e| e.binding.as_ref())
    }

    pub fn contains(&self, secret_name: &str) -> bool {
        self.entries.contains_key(secret_name)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn open_secret_spec(
    name: &str,
    spec: &mut SecretSpec,
    host_key: Option<&HostKeyPair>,
    hosts: &[String],
    path_prefixes: &[String],
    expected_policy_tag: Option<&str>,
    now_unix_sec: u64,
) -> Result<(SecretBytes, Option<SealBinding>)> {
    match (spec.sealed.as_deref(), spec.ephemeral.is_some()) {
        (Some(sealed), false) => {
            let keypair =
                host_key.ok_or_else(|| SecretError::MissingHostKey(name.to_string()))?;
            let opened = open_sealed(keypair, sealed, now_unix_sec)?;
            let host_refs: Vec<&str> = hosts.iter().map(String::as_str).collect();
            let path_refs: Vec<&str> = path_prefixes.iter().map(String::as_str).collect();
            opened.binding.validate_usage(
                &host_refs,
                &path_refs,
                expected_policy_tag,
                now_unix_sec,
            )?;
            Ok((opened.secret, Some(opened.binding)))
        }
        (None, true) => {
            let plain = spec
                .ephemeral
                .take()
                .expect("ephemeral was checked as Some");
            // `SecretBytes::from_string` copies into protected memory and zeroizes `plain`.
            Ok((SecretBytes::from_string(plain), None))
        }
        _ => Err(SecretError::InvalidSecretSource(name.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpke_seal::seal_secret;
    use blackwall_policy::{AuthSpec, HttpRule, NetworkMode, PostgresRule};
    use std::collections::HashSet;

    fn sample_egress_spec(sealed_gh: String, ephemeral_pg: String) -> SandboxSpec {
        let mut spec = SandboxSpec::base();
        spec.network.mode = NetworkMode::Egress;
        spec.network.http.push(HttpRule {
            host: "api.github.com".into(),
            port: 443,
            methods: vec!["GET".into(), "POST".into()],
            path_prefixes: vec!["/repos/my-org/my-repo/".into()],
            max_request_bytes: Some(4_194_304),
            auth: Some(AuthSpec::Bearer {
                secret: "GITHUB_TOKEN".into(),
            }),
        });
        spec.network.postgres.push(PostgresRule {
            host: "db.internal".into(),
            port: 5432,
            secret: "PGPASSWORD".into(),
            require_upstream_tls: true,
        });
        spec.secrets.insert(
            "GITHUB_TOKEN".into(),
            SecretSpec {
                placeholder_prefix: "ghp_bw00".into(),
                sealed: Some(sealed_gh),
                ephemeral: None,
            },
        );
        spec.secrets.insert(
            "PGPASSWORD".into(),
            SecretSpec {
                placeholder_prefix: "bwpg_".into(),
                sealed: None,
                ephemeral: Some(ephemeral_pg),
            },
        );
        spec
    }

    #[test]
    fn vm_secret_table_opens_sealed_and_ephemeral_and_verifies_placeholders() {
        let kp = HostKeyPair::generate();
        let binding = SealBinding {
            allow_hosts: vec!["api.github.com".into()],
            allow_path_templates: vec!["/repos/my-org/my-repo/".into()],
            policy_tag: "repo-agent".into(),
            exp_unix_sec: Some(2_000_000_000),
        };
        let sealed_gh = seal_secret(kp.public_key(), b"ghp_REAL_GITHUB_SECRET", &binding).unwrap();

        let mut spec = sample_egress_spec(sealed_gh, "pg_REAL_DB_PASSWORD".into());
        let (table, placeholders) =
            VmSecretTable::from_sandbox_spec(&mut spec, Some(&kp), Some("repo-agent"), 1_700_000_000)
                .unwrap();

        // Ephemeral input in spec was cleared after zeroization
        assert!(spec.secrets["PGPASSWORD"].ephemeral.is_none());

        assert_eq!(table.len(), 2);
        let gh_ph = &placeholders["GITHUB_TOKEN"];
        let pg_ph = &placeholders["PGPASSWORD"];
        assert!(gh_ph.starts_with("ghp_bw00"));
        assert!(pg_ph.starts_with("bwpg_"));
        assert_eq!(gh_ph.len(), "ghp_bw00".len() + 43);
        assert_eq!(pg_ph.len(), "bwpg_".len() + 43);
        assert!(!gh_ph.contains("REAL"));
        assert!(!pg_ph.contains("REAL"));

        // Valid placeholder succeeds
        assert!(table.verify_placeholder("GITHUB_TOKEN", gh_ph));
        let real_gh = table.verify_and_get("GITHUB_TOKEN", gh_ph).unwrap();
        assert_eq!(real_gh.as_str().unwrap(), "ghp_REAL_GITHUB_SECRET");

        let real_pg = table.verify_and_get("PGPASSWORD", pg_ph).unwrap();
        assert_eq!(real_pg.as_str().unwrap(), "pg_REAL_DB_PASSWORD");

        // Attacker / BYO token fails constant-time verification
        assert!(!table.verify_placeholder("GITHUB_TOKEN", "ghp_ATTACKER_TOKEN"));
        assert!(!table.verify_placeholder("GITHUB_TOKEN", "ghp_REAL_GITHUB_SECRET"));
        assert!(matches!(
            table.verify_and_get("GITHUB_TOKEN", "ghp_ATTACKER_TOKEN"),
            Err(SecretError::PlaceholderMismatch(_))
        ));
        assert!(matches!(
            table.verify_and_get("UNKNOWN_SECRET", gh_ph),
            Err(SecretError::SecretNotFound(_))
        ));

        // Request-time target validation enforces binding host, path, and expiry
        assert!(table
            .verify_and_get_for_target(
                "GITHUB_TOKEN",
                gh_ph,
                "api.github.com",
                Some("/repos/my-org/my-repo/issues"),
                1_700_000_000
            )
            .is_ok());
        assert!(matches!(
            table.verify_and_get_for_target(
                "GITHUB_TOKEN",
                gh_ph,
                "evil.example.com",
                Some("/repos/my-org/my-repo/issues"),
                1_700_000_000
            ),
            Err(SecretError::BindingMismatch(_))
        ));
        assert!(matches!(
            table.verify_and_get_for_target(
                "GITHUB_TOKEN",
                gh_ph,
                "api.github.com",
                Some("/repos/other-org/other-repo/issues"),
                1_700_000_000
            ),
            Err(SecretError::BindingMismatch(_))
        ));
        assert!(matches!(
            table.verify_and_get_for_target(
                "GITHUB_TOKEN",
                gh_ph,
                "api.github.com",
                Some("/repos/my-org/my-repo/issues"),
                2_000_000_000
            ),
            Err(SecretError::Expired { .. })
        ));

        // Debug output on VmSecretTable must never leak real secret values
        let dbg = format!("{table:?}");
        assert!(!dbg.contains("ghp_REAL_GITHUB_SECRET"));
        assert!(!dbg.contains("pg_REAL_DB_PASSWORD"));
        assert!(dbg.contains("SecretBytes(<redacted>)"));
    }

    #[test]
    fn vm_secret_table_rejects_binding_mismatch_against_sandbox_rules() {
        let kp = HostKeyPair::generate();

        // Sealed for a different host
        let wrong_host_binding = SealBinding {
            allow_hosts: vec!["api.openai.com".into()],
            allow_path_templates: vec!["/repos/my-org/my-repo/".into()],
            policy_tag: "repo-agent".into(),
            exp_unix_sec: None,
        };
        let sealed = seal_secret(kp.public_key(), b"secret", &wrong_host_binding).unwrap();
        let mut spec = sample_egress_spec(sealed, "pg".into());
        assert!(matches!(
            VmSecretTable::from_sandbox_spec(&mut spec, Some(&kp), Some("repo-agent"), 1_700_000_000),
            Err(SecretError::BindingMismatch(_))
        ));

        // Sealed for a narrower path than the sandbox HTTP rule requests
        let wrong_path_binding = SealBinding {
            allow_hosts: vec!["api.github.com".into()],
            allow_path_templates: vec!["/repos/other-org/other-repo/".into()],
            policy_tag: "repo-agent".into(),
            exp_unix_sec: None,
        };
        let sealed = seal_secret(kp.public_key(), b"secret", &wrong_path_binding).unwrap();
        let mut spec = sample_egress_spec(sealed, "pg".into());
        assert!(matches!(
            VmSecretTable::from_sandbox_spec(&mut spec, Some(&kp), Some("repo-agent"), 1_700_000_000),
            Err(SecretError::BindingMismatch(_))
        ));

        // Wrong policy_tag
        let good_binding = SealBinding {
            allow_hosts: vec!["api.github.com".into()],
            allow_path_templates: vec!["/repos/my-org/my-repo/".into()],
            policy_tag: "dev".into(),
            exp_unix_sec: None,
        };
        let sealed = seal_secret(kp.public_key(), b"secret", &good_binding).unwrap();
        let mut spec = sample_egress_spec(sealed, "pg".into());
        assert!(matches!(
            VmSecretTable::from_sandbox_spec(&mut spec, Some(&kp), Some("prod"), 1_700_000_000),
            Err(SecretError::BindingMismatch(_))
        ));
    }

    #[test]
    fn minted_placeholders_are_unique_and_256_bit_random() {
        let count = 256;
        let mut seen = HashSet::with_capacity(count);
        for _ in 0..count {
            let ph = mint_placeholder("sk-bw00_");
            assert!(ph.starts_with("sk-bw00_"));
            let suffix = &ph["sk-bw00_".len()..];
            let decoded = URL_SAFE_NO_PAD.decode(suffix).unwrap();
            assert_eq!(decoded.len(), PLACEHOLDER_ENTROPY_BYTES);
            assert!(seen.insert(ph), "duplicate placeholder minted");
        }
        assert_eq!(seen.len(), count);
    }

    #[test]
    fn vm_secret_table_handles_missing_host_key_and_direct_ephemeral_intake() {
        let kp = HostKeyPair::generate();
        let binding = SealBinding {
            allow_hosts: vec!["api.github.com".into()],
            allow_path_templates: vec!["/repos/my-org/my-repo/".into()],
            policy_tag: "repo-agent".into(),
            exp_unix_sec: None,
        };
        let sealed = seal_secret(kp.public_key(), b"ghp_real", &binding).unwrap();
        let mut spec = sample_egress_spec(sealed, "pg_pass".into());

        // Missing host key fails when a sealed secret is present
        assert!(matches!(
            VmSecretTable::from_sandbox_spec(&mut spec, None, None, 1_700_000_000),
            Err(SecretError::MissingHostKey(ref name)) if name == "GITHUB_TOKEN"
        ));

        // Direct ephemeral insertion & standalone specs map
        let mut table = VmSecretTable::new();
        let ph = table.insert_ephemeral("ANTHROPIC_API_KEY", "sk-ant-bw00_", "sk-ant-REAL".into());
        assert!(ph.starts_with("sk-ant-bw00_"));
        assert_eq!(
            table
                .verify_and_get("ANTHROPIC_API_KEY", &ph)
                .unwrap()
                .as_str()
                .unwrap(),
            "sk-ant-REAL"
        );
        assert!(matches!(
            table.verify_and_get("ANTHROPIC_API_KEY", "sk-ant-attacker"),
            Err(SecretError::PlaceholderMismatch(_))
        ));

        let mut specs = BTreeMap::new();
        specs.insert(
            "PGPASSWORD".into(),
            SecretSpec {
                placeholder_prefix: "bwpg_".into(),
                sealed: Some(
                    seal_secret(
                        kp.public_key(),
                        b"real-pg-secret",
                        &SealBinding {
                            allow_hosts: vec!["db.internal".into()],
                            allow_path_templates: vec![],
                            policy_tag: "db".into(),
                            exp_unix_sec: None,
                        },
                    )
                    .unwrap(),
                ),
                ephemeral: None,
            },
        );
        let (db_table, db_ph) = VmSecretTable::from_secret_specs(
            &mut specs,
            Some(&kp),
            &["db.internal".into()],
            &[],
            Some("db"),
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(
            db_table
                .verify_and_get_for_target("PGPASSWORD", &db_ph["PGPASSWORD"], "db.internal", None, 1_700_000_000)
                .unwrap()
                .as_str()
                .unwrap(),
            "real-pg-secret"
        );
    }
}
