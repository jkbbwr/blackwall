//! Local secret-resolution trait and in-memory implementation for `blackwall-proxy`.
//!
//! Decouples `blackwall-proxy` from `blackwall-secrets` storage internals (`memfd_secret`,
//! HPKE `seal1_` unsealing) so `blackwall-core` can bridge `VmSecretTable` into
//! `SecretResolver` cleanly while keeping `blackwall-proxy` independently testable.

use std::collections::BTreeMap;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Constant-time string comparison (prevents timing side-channels on placeholder verification).
pub fn constant_time_str_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    bool::from(a_bytes.ct_eq(b_bytes))
}

/// Trait implemented by per-VM secret stores to verify guest placeholders and retrieve
/// real brokered credentials for upstream injection.
pub trait SecretResolver: Send + Sync {
    /// Constant-time verification that `presented` matches the per-VM random placeholder
    /// assigned to `secret_name`.
    fn verify_placeholder(&self, secret_name: &str, presented: &str) -> bool;

    /// Retrieve the real upstream secret material (wrapped in `Zeroizing` so memory is
    /// wiped immediately on drop).
    fn resolve_secret(&self, secret_name: &str) -> Option<Zeroizing<String>>;

    /// Return the guest-visible placeholder for `secret_name`, if registered.
    fn placeholder_for(&self, secret_name: &str) -> Option<String>;

    /// Return all registered `(secret_name, guest_placeholder)` pairs for outbound
    /// placeholder exfiltration detection across headers, query strings, and bodies.
    fn all_placeholders(&self) -> Vec<(String, String)>;
}

struct SecretRecord {
    placeholder: String,
    real_value: Zeroizing<String>,
}

/// Thread-safe in-memory [`SecretResolver`] backed by `Zeroizing` buffers.
#[derive(Default)]
pub struct InMemorySecretResolver {
    entries: BTreeMap<String, SecretRecord>,
}

impl InMemorySecretResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a `(secret_name, guest_placeholder, real_secret)` mapping.
    pub fn insert(
        &mut self,
        secret_name: impl Into<String>,
        placeholder: impl Into<String>,
        real_value: impl Into<String>,
    ) {
        self.entries.insert(
            secret_name.into(),
            SecretRecord {
                placeholder: placeholder.into(),
                real_value: Zeroizing::new(real_value.into()),
            },
        );
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl SecretResolver for InMemorySecretResolver {
    fn verify_placeholder(&self, secret_name: &str, presented: &str) -> bool {
        match self.entries.get(secret_name) {
            Some(rec) => constant_time_str_eq(&rec.placeholder, presented),
            None => false,
        }
    }

    fn resolve_secret(&self, secret_name: &str) -> Option<Zeroizing<String>> {
        self.entries
            .get(secret_name)
            .map(|rec| Zeroizing::new((*rec.real_value).clone()))
    }

    fn placeholder_for(&self, secret_name: &str) -> Option<String> {
        self.entries
            .get(secret_name)
            .map(|rec| rec.placeholder.clone())
    }

    fn all_placeholders(&self) -> Vec<(String, String)> {
        self.entries
            .iter()
            .map(|(name, rec)| (name.clone(), rec.placeholder.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_validation_and_secret_lookup() {
        let mut resolver = InMemorySecretResolver::new();
        resolver.insert("GITHUB_TOKEN", "ghp_bw00abc123", "ghp_REAL_SECRET_XYZ");

        assert!(resolver.verify_placeholder("GITHUB_TOKEN", "ghp_bw00abc123"));
        assert!(!resolver.verify_placeholder("GITHUB_TOKEN", "ghp_ATTACKER"));
        assert!(!resolver.verify_placeholder("GITHUB_TOKEN", "ghp_bw00abc124"));
        assert!(!resolver.verify_placeholder("UNKNOWN", "ghp_bw00abc123"));

        let resolved = resolver.resolve_secret("GITHUB_TOKEN").unwrap();
        assert_eq!(resolved.as_str(), "ghp_REAL_SECRET_XYZ");
        assert_eq!(
            resolver.placeholder_for("GITHUB_TOKEN").as_deref(),
            Some("ghp_bw00abc123")
        );
    }
}
