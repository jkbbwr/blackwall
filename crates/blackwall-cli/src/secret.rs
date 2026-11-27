//! Offline HPKE X25519 `seal1_` secret sealing for `blackwall secret seal`.
//!
//! Plaintext is read exclusively from a named environment variable (`--value-env`)
//! or from stdin — never from a CLI flag that would leak into `ps` / `/proc/pid/cmdline`.

use crate::cli::SecretSealArgs;
use crate::error::{CliError, Result};
use blackwall_core::CoreConfig;
use blackwall_secrets::{current_unix_sec, HostKeyPair, SealBinding};
use serde::Serialize;
use std::io::Read;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Output metadata produced by `blackwall secret seal`.
#[derive(Debug, Clone, Serialize)]
pub struct SealedSecretOutput {
    pub name: String,
    pub placeholder_prefix: String,
    pub sealed: String,
    pub host_public_key: String,
    pub key_path: PathBuf,
    pub binding: SealBinding,
}

impl SealedSecretOutput {
    /// Format a ready-to-paste TOML snippet for a Blackwall profile file.
    pub fn to_toml_snippet(&self) -> String {
        format!(
            "[secrets.{}]\nplaceholder_prefix = {:?}\nsealed = {:?}\n",
            self.name, self.placeholder_prefix, self.sealed
        )
    }
}

/// Seal a secret using options from [`SecretSealArgs`], reading plaintext from
/// `--value-env` or the provided `stdin_reader`.
pub fn seal_secret_from_args<R: Read>(
    args: &SecretSealArgs,
    stdin_reader: R,
) -> Result<SealedSecretOutput> {
    validate_secret_name(&args.name)?;

    let plaintext = read_secret_plaintext(args.value_env.as_deref(), stdin_reader)?;
    let key_path = args
        .key_path
        .clone()
        .unwrap_or_else(|| CoreConfig::default().host_key_path);

    let keypair = HostKeyPair::load_or_generate(&key_path)?;

    let allow_hosts: Vec<String> = args
        .hosts
        .iter()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .collect();

    let allow_path_templates: Vec<String> = if args.paths.is_empty() {
        vec!["/*".to_string()]
    } else {
        args.paths
            .iter()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    };

    let exp_unix_sec = args
        .exp_sec
        .map(|ttl| current_unix_sec().saturating_add(ttl));

    let binding = SealBinding {
        allow_hosts,
        allow_path_templates,
        policy_tag: args.policy_tag.clone(),
        exp_unix_sec,
    }
    .normalized();

    let sealed = keypair.seal(plaintext.as_bytes(), &binding)?;
    let placeholder_prefix = args
        .placeholder_prefix
        .clone()
        .unwrap_or_else(|| default_placeholder_prefix(&args.name));

    Ok(SealedSecretOutput {
        name: args.name.clone(),
        placeholder_prefix,
        sealed,
        host_public_key: keypair.public_key().to_base64(),
        key_path,
        binding,
    })
}

fn validate_secret_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(CliError::InvalidArgument(format!(
            "secret --name '{name}' must be non-empty and contain only ASCII letters, digits, and '_'"
        )));
    }
    Ok(())
}

fn read_secret_plaintext<R: Read>(
    value_env: Option<&str>,
    mut stdin_reader: R,
) -> Result<Zeroizing<String>> {
    let raw = if let Some(env_var) = value_env {
        let val = std::env::var(env_var).map_err(|_| {
            CliError::InvalidArgument(format!(
                "environment variable '{env_var}' specified by --value-env is not set"
            ))
        })?;
        Zeroizing::new(val)
    } else {
        let mut buf = Zeroizing::new(String::new());
        stdin_reader.read_to_string(&mut buf)?;
        let trimmed = buf.trim_end_matches(['\r', '\n']).to_string();
        Zeroizing::new(trimmed)
    };

    if raw.is_empty() {
        return Err(CliError::InvalidArgument(
            "secret plaintext is empty (provide secret via --value-env or stdin)".into(),
        ));
    }

    Ok(raw)
}

fn default_placeholder_prefix(name: &str) -> String {
    let upper = name.to_ascii_uppercase();
    if upper.contains("GITHUB") {
        "ghp_bw00_".to_string()
    } else if upper.contains("PG") || upper.contains("POSTGRES") {
        "bwpg_".to_string()
    } else {
        "bw_".to_string()
    }
}
