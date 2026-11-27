//! Composable `SandboxSpec` policy engine for Blackwall.
//!
//! Features:
//! - Built-in fail-closed `base` defaults (`debian:bookworm-slim`, 2 GiB workspace,
//!   `network.mode = "loopback"`, default `deny_touch_globs`, sensible default `env`).
//! - Left-to-right `extends = [...]` profile inheritance with cycle & conflict detection.
//! - Auto-derived DNS allowlists from declared `[[network.http]]` + `[[network.postgres]]`.
//! - `[policy] locked = true` narrow-only ceiling enforcement on runtime overrides.
//! - Dual secret sources: `sealed = "seal1_..."` (required for on-disk TOML) and
//!   `ephemeral = "..."` (permitted exclusively on programmatic `0600` UDS API calls).

use blackwall_proto::GuestNetMode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use thiserror::Error;

pub const BASE_PROFILE_NAME: &str = "base";
pub const DEFAULT_BASE_IMAGE: &str = "debian:bookworm-slim";

pub const DEFAULT_DENY_TOUCH_GLOBS: &[&str] = &[
    ".git/**",
    ".gitmodules",
    ".gitconfig",
    ".jj/**",
    ".github/**",
    ".gitlab-ci.yml",
    ".circleci/**",
    "Jenkinsfile",
    ".envrc",
    ".env*",
    ".bashrc",
    ".zshrc",
    ".profile",
    ".vscode/**",
    ".idea/**",
    ".cursor/**",
    ".zed/**",
    ".claude/**",
    ".gemini/**",
    ".cargo/config.toml",
    "rust-toolchain.toml",
    "Makefile",
    "justfile",
    "flake.nix",
];

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unknown profile '{0}' referenced in extends")]
    UnknownProfile(String),
    #[error("profile inheritance cycle detected involving '{0}'")]
    CycleDetected(String),
    #[error("conflicting HTTP rule for host '{host}' prefix '{prefix}'")]
    HttpRuleConflict { host: String, prefix: String },
    #[error("conflicting Postgres rule for '{host}:{port}'")]
    PostgresRuleConflict { host: String, port: u16 },
    #[error("conflicting secret definition for '{0}'")]
    SecretConflict(String),
    #[error("ephemeral plaintext secret '{0}' is forbidden in on-disk TOML profiles; use seal1_...")]
    EphemeralSecretInFile(String),
    #[error("secret '{0}' must specify exactly one of `sealed` or `ephemeral`")]
    InvalidSecretSource(String),
    #[error("sealed secret '{0}' must start with 'seal1_'")]
    InvalidSealedPrefix(String),
    #[error("rule references undefined secret '{0}'")]
    UndefinedSecret(String),
    #[error("network rules declared while network.mode is '{0:?}'; set network.mode = \"egress\"")]
    RulesRequireEgressMode(NetworkMode),
    #[error("locked policy violation: {0}")]
    LockedPolicyViolation(String),
    #[error("invalid policy value: {0}")]
    InvalidValue(String),
}

pub type Result<T> = std::result::Result<T, PolicyError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    None,
    Loopback,
    Egress,
}

impl From<NetworkMode> for GuestNetMode {
    fn from(mode: NetworkMode) -> Self {
        match mode {
            NetworkMode::None => GuestNetMode::None,
            NetworkMode::Loopback => GuestNetMode::Loopback,
            NetworkMode::Egress => GuestNetMode::Egress,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageSpec {
    #[serde(rename = "ref", default)]
    pub image_ref: Option<String>,
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub run: Vec<String>,
}

impl Default for ImageSpec {
    fn default() -> Self {
        Self {
            image_ref: None,
            base: Some(DEFAULT_BASE_IMAGE.to_string()),
            packages: Vec::new(),
            run: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeSpec {
    pub vcpus: u32,
    pub memory_mib: u32,
    pub workspace_mib: u32,
    pub idle_timeout_sec: u64,
    pub max_wall_time_sec: u64,
}

impl Default for ComputeSpec {
    fn default() -> Self {
        Self {
            vcpus: 2,
            memory_mib: 2048,
            workspace_mib: 2048,
            idle_timeout_sec: 600,
            max_wall_time_sec: 3600,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AuthSpec {
    Bearer {
        secret: String,
    },
    Header {
        secret: String,
        name: String,
        #[serde(default)]
        prefix: Option<String>,
    },
    Basic {
        secret: String,
        username: String,
    },
}

impl AuthSpec {
    pub fn secret_name(&self) -> &str {
        match self {
            Self::Bearer { secret }
            | Self::Header { secret, .. }
            | Self::Basic { secret, .. } => secret,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRule {
    pub host: String,
    #[serde(default = "default_http_port")]
    pub port: u16,
    pub methods: Vec<String>,
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub max_request_bytes: Option<u64>,
    #[serde(default)]
    pub auth: Option<AuthSpec>,
}

fn default_http_port() -> u16 {
    443
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgresRule {
    pub host: String,
    #[serde(default = "default_pg_port")]
    pub port: u16,
    pub secret: String,
    #[serde(default = "default_true")]
    pub require_upstream_tls: bool,
}

fn default_pg_port() -> u16 {
    5432
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSpec {
    pub mode: NetworkMode,
    #[serde(default)]
    pub http: Vec<HttpRule>,
    #[serde(default)]
    pub postgres: Vec<PostgresRule>,
}

impl Default for NetworkSpec {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Loopback,
            http: Vec::new(),
            postgres: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressSpec {
    #[serde(default)]
    pub allow_ports: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostServiceSpec {
    pub name: String,
    pub guest_port: u16,
    /// Must be either `unix:///abs/path.sock` or a loopback TCP addr (`127.0.0.1:<port>` / `[::1]:<port>`).
    pub target: String,
}

/// Validate a single host service bridge specification.
///
/// Enforces:
/// - `name`: non-empty, `<= 64` chars, `[a-zA-Z0-9._-]+`.
/// - `guest_port`: `>= 1`.
/// - `target`: either `unix:///abs/path` (absolute path, no `..` components, no NUL bytes)
///   or a loopback `SocketAddr` (`127.0.0.0/8` or `::1`) with `port >= 1`.
pub fn validate_host_service(svc: &HostServiceSpec) -> Result<()> {
    let name_bytes = svc.name.as_bytes();
    if name_bytes.is_empty()
        || name_bytes.len() > 64
        || !name_bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return Err(PolicyError::InvalidValue(format!(
            "invalid host_services name '{}': must be 1..=64 chars matching [a-zA-Z0-9._-]+",
            svc.name
        )));
    }

    if svc.guest_port == 0 {
        return Err(PolicyError::InvalidValue(format!(
            "host_services '{}' guest_port must be >= 1",
            svc.name
        )));
    }

    if let Some(socket_path) = svc.target.strip_prefix("unix://") {
        if !socket_path.starts_with('/') || socket_path.trim_end_matches('/').is_empty() {
            return Err(PolicyError::InvalidValue(format!(
                "host_services '{}' unix target '{}' must be an absolute socket path",
                svc.name, svc.target
            )));
        }
        if socket_path.contains('\0') {
            return Err(PolicyError::InvalidValue(format!(
                "host_services '{}' unix target contains NUL byte",
                svc.name
            )));
        }
        if Path::new(socket_path)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
            || socket_path.split('/').any(|seg| seg == "..")
        {
            return Err(PolicyError::InvalidValue(format!(
                "host_services '{}' unix target '{}' must not contain '..' path components",
                svc.name, svc.target
            )));
        }
        return Ok(());
    }

    let addr: std::net::SocketAddr = svc.target.parse().map_err(|_| {
        PolicyError::InvalidValue(format!(
            "host_services '{}' target '{}' must be unix:///abs/path or loopback SocketAddr (127.0.0.1:<port> / [::1]:<port>)",
            svc.name, svc.target
        ))
    })?;
    if !addr.ip().is_loopback() {
        return Err(PolicyError::InvalidValue(format!(
            "host_services '{}' target '{}' must be a loopback address",
            svc.name, svc.target
        )));
    }
    if addr.port() == 0 {
        return Err(PolicyError::InvalidValue(format!(
            "host_services '{}' target '{}' port must be >= 1",
            svc.name, svc.target
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretSpec {
    pub placeholder_prefix: String,
    #[serde(default)]
    pub sealed: Option<String>,
    #[serde(default)]
    pub ephemeral: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSpec {
    pub max_bytes: u64,
    pub max_files: u64,
    pub deny_touch_globs: Vec<String>,
}

impl Default for ExportSpec {
    fn default() -> Self {
        Self {
            max_bytes: 52_428_800,
            max_files: 10_000,
            deny_touch_globs: DEFAULT_DENY_TOUCH_GLOBS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyGovernance {
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub max_vcpus: Option<u32>,
    #[serde(default)]
    pub max_memory_mib: Option<u32>,
    #[serde(default)]
    pub max_workspace_mib: Option<u32>,
    #[serde(default)]
    pub max_idle_timeout_sec: Option<u64>,
    #[serde(default)]
    pub max_wall_time_sec: Option<u64>,
    #[serde(default)]
    pub max_export_bytes: Option<u64>,
    #[serde(default)]
    pub max_export_files: Option<u64>,
}

/// Operator-enforced hard upper-bound ceiling applied to resolved [`SandboxSpec`]s
/// (and profile/image operations) regardless of profile contents.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCeiling {
    #[serde(default)]
    pub max_network_mode: Option<NetworkMode>,
    #[serde(default)]
    pub allowed_egress_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub allow_host_services: Option<bool>,
    #[serde(default)]
    pub allow_image_build: Option<bool>,
    #[serde(default)]
    pub max_vcpus: Option<u32>,
    #[serde(default)]
    pub max_memory_mib: Option<u32>,
    #[serde(default)]
    pub max_workspace_mib: Option<u32>,
    #[serde(default)]
    pub max_idle_timeout_sec: Option<u64>,
    #[serde(default)]
    pub max_wall_time_sec: Option<u64>,
}

impl PolicyCeiling {
    /// Parse a [`PolicyCeiling`] from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self> {
        Ok(toml::from_str(s)?)
    }

    /// Load and parse a [`PolicyCeiling`] from a TOML file on disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(path.as_ref())?;
        Self::from_toml_str(&raw)
    }

    /// Enforce this operator ceiling against a resolved [`SandboxSpec`].
    ///
    /// Any violation returns [`PolicyError::LockedPolicyViolation`].
    pub fn enforce(&self, spec: &SandboxSpec) -> Result<()> {
        if let Some(max_mode) = self.max_network_mode {
            if spec.network.mode > max_mode {
                return Err(PolicyError::LockedPolicyViolation(format!(
                    "network.mode ({:?}) exceeds policy ceiling ({max_mode:?})",
                    spec.network.mode
                )));
            }
        }

        if let Some(ref allowed) = self.allowed_egress_hosts {
            let allowed_set: BTreeSet<String> =
                allowed.iter().map(|h| h.to_ascii_lowercase()).collect();
            for rule in &spec.network.http {
                if !allowed_set.contains(&rule.host.to_ascii_lowercase()) {
                    return Err(PolicyError::LockedPolicyViolation(format!(
                        "egress HTTP host '{}' is not permitted by policy ceiling",
                        rule.host
                    )));
                }
            }
            for rule in &spec.network.postgres {
                if !allowed_set.contains(&rule.host.to_ascii_lowercase()) {
                    return Err(PolicyError::LockedPolicyViolation(format!(
                        "egress Postgres host '{}' is not permitted by policy ceiling",
                        rule.host
                    )));
                }
            }
        }

        if self.allow_host_services == Some(false) && !spec.host_services.is_empty() {
            return Err(PolicyError::LockedPolicyViolation(
                "host_services are disabled by policy ceiling".into(),
            ));
        }

        check_ceiling_u32("vcpus", spec.compute.vcpus, self.max_vcpus)?;
        check_ceiling_u32("memory_mib", spec.compute.memory_mib, self.max_memory_mib)?;
        check_ceiling_u32(
            "workspace_mib",
            spec.compute.workspace_mib,
            self.max_workspace_mib,
        )?;
        check_ceiling_u64(
            "idle_timeout_sec",
            spec.compute.idle_timeout_sec,
            self.max_idle_timeout_sec,
        )?;
        check_ceiling_u64(
            "max_wall_time_sec",
            spec.compute.max_wall_time_sec,
            self.max_wall_time_sec,
        )?;

        Ok(())
    }
}

/// Fully resolved, validated sandbox specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxSpec {
    pub version: u32,
    pub name: String,
    #[serde(default)]
    pub host_services: Vec<HostServiceSpec>,
    pub image: ImageSpec,
    pub compute: ComputeSpec,
    pub network: NetworkSpec,
    #[serde(default)]
    pub ingress: IngressSpec,
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretSpec>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub export: ExportSpec,
    #[serde(default)]
    pub policy: PolicyGovernance,
}

/// Validate a user-defined profile name (`^[a-z0-9][a-z0-9_-]{0,63}$` and not `"base"`).
pub fn validate_profile_name(name: &str) -> Result<()> {
    if name == BASE_PROFILE_NAME {
        return Err(PolicyError::InvalidValue(
            "profile name 'base' is reserved".into(),
        ));
    }
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return Err(PolicyError::InvalidValue(format!(
            "invalid profile name '{name}': must match ^[a-z0-9][a-z0-9_-]{{0,63}}$"
        )));
    }
    let first_ok = bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit();
    let rest_ok = bytes
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if !first_ok || !rest_ok {
        return Err(PolicyError::InvalidValue(format!(
            "invalid profile name '{name}': must match ^[a-z0-9][a-z0-9_-]{{0,63}}$"
        )));
    }
    Ok(())
}

/// Default environment variables populated in the built-in `base` profile
/// (overridable by child profiles and runtime drafts).
pub const DEFAULT_BASE_ENV: &[(&str, &str)] = &[
    ("HOME", "/home/sandbox"),
    (
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    ),
    ("TERM", "xterm-256color"),
    ("LANG", "C.UTF-8"),
    ("LC_ALL", "C.UTF-8"),
    ("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt"),
    ("NODE_EXTRA_CA_CERTS", "/run/blackwall/mitm-ca.crt"),
];

impl SandboxSpec {
    pub fn base() -> Self {
        let env = DEFAULT_BASE_ENV
            .iter()
            .map(|&(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Self {
            version: 1,
            name: BASE_PROFILE_NAME.to_string(),
            host_services: Vec::new(),
            image: ImageSpec::default(),
            compute: ComputeSpec::default(),
            network: NetworkSpec::default(),
            ingress: IngressSpec::default(),
            secrets: BTreeMap::new(),
            env,
            export: ExportSpec::default(),
            policy: PolicyGovernance::default(),
        }
    }

    /// Derive the complete set of allowlisted DNS FQDNs automatically from
    /// declared `[[network.http]]` and `[[network.postgres]]` rules.
    pub fn derived_dns_allow(&self) -> BTreeSet<String> {
        let mut hosts = BTreeSet::new();
        if self.network.mode == NetworkMode::Egress {
            for r in &self.network.http {
                hosts.insert(r.host.to_ascii_lowercase());
            }
            for r in &self.network.postgres {
                hosts.insert(r.host.to_ascii_lowercase());
            }
        }
        hosts
    }

    /// Validate all invariants (fail-closed network mode, valid secret references,
    /// positive compute/export limits, ceilings).
    pub fn validate(&self, allow_ephemeral_secrets: bool) -> Result<()> {
        if self.version != 1 {
            return Err(PolicyError::InvalidValue(format!(
                "unsupported spec version {}",
                self.version
            )));
        }
        if self.compute.vcpus == 0 || self.compute.memory_mib < 64 || self.compute.workspace_mib < 16 {
            return Err(PolicyError::InvalidValue(
                "compute vcpus/memory_mib/workspace_mib must be positive (min 64 MiB RAM, 16 MiB workspace)".into(),
            ));
        }
        if self.compute.idle_timeout_sec == 0 || self.compute.max_wall_time_sec == 0 {
            return Err(PolicyError::InvalidValue(
                "idle_timeout_sec and max_wall_time_sec must be > 0".into(),
            ));
        }
        if self.compute.idle_timeout_sec > self.compute.max_wall_time_sec {
            return Err(PolicyError::InvalidValue(
                "idle_timeout_sec cannot exceed max_wall_time_sec".into(),
            ));
        }
        if self.image.image_ref.is_none() && self.image.base.is_none() {
            return Err(PolicyError::InvalidValue(
                "image must specify either `ref` or `base`".into(),
            ));
        }

        if self.network.mode != NetworkMode::Egress
            && (!self.network.http.is_empty() || !self.network.postgres.is_empty())
        {
            return Err(PolicyError::RulesRequireEgressMode(self.network.mode));
        }

        for (name, secret) in &self.secrets {
            match (&secret.sealed, &secret.ephemeral) {
                (Some(sealed), None) => {
                    if !sealed.starts_with("seal1_") {
                        return Err(PolicyError::InvalidSealedPrefix(name.clone()));
                    }
                }
                (None, Some(_)) => {
                    if !allow_ephemeral_secrets {
                        return Err(PolicyError::EphemeralSecretInFile(name.clone()));
                    }
                }
                _ => return Err(PolicyError::InvalidSecretSource(name.clone())),
            }
        }

        for rule in &self.network.http {
            if rule.host.trim().is_empty() || rule.methods.is_empty() || rule.path_prefixes.is_empty() {
                return Err(PolicyError::InvalidValue(format!(
                    "HTTP rule for '{}' must specify non-empty host, methods, and path_prefixes",
                    rule.host
                )));
            }
            if let Some(auth) = &rule.auth {
                let sname = auth.secret_name();
                if !self.secrets.contains_key(sname) {
                    return Err(PolicyError::UndefinedSecret(sname.to_string()));
                }
            }
        }

        for rule in &self.network.postgres {
            if rule.host.trim().is_empty() {
                return Err(PolicyError::InvalidValue(
                    "Postgres rule must specify non-empty host".into(),
                ));
            }
            if !self.secrets.contains_key(&rule.secret) {
                return Err(PolicyError::UndefinedSecret(rule.secret.clone()));
            }
        }

        for &port in &self.ingress.allow_ports {
            if port == 0 {
                return Err(PolicyError::InvalidValue(
                    "ingress.allow_ports entries must be > 0".into(),
                ));
            }
        }

        if !self.host_services.is_empty() && self.network.mode == NetworkMode::None {
            return Err(PolicyError::InvalidValue(
                "host_services cannot be used when network.mode is 'none'".into(),
            ));
        }
        let mut seen_host_service_ports = BTreeSet::new();
        for svc in &self.host_services {
            validate_host_service(svc)?;
            if !seen_host_service_ports.insert(svc.guest_port) {
                return Err(PolicyError::InvalidValue(format!(
                    "duplicate host_services guest_port {}",
                    svc.guest_port
                )));
            }
        }

        // Enforce explicit ceilings if set on the spec itself
        check_ceiling_u32("vcpus", self.compute.vcpus, self.policy.max_vcpus)?;
        check_ceiling_u32("memory_mib", self.compute.memory_mib, self.policy.max_memory_mib)?;
        check_ceiling_u32(
            "workspace_mib",
            self.compute.workspace_mib,
            self.policy.max_workspace_mib,
        )?;
        check_ceiling_u64(
            "idle_timeout_sec",
            self.compute.idle_timeout_sec,
            self.policy.max_idle_timeout_sec,
        )?;
        check_ceiling_u64(
            "max_wall_time_sec",
            self.compute.max_wall_time_sec,
            self.policy.max_wall_time_sec,
        )?;
        check_ceiling_u64("export.max_bytes", self.export.max_bytes, self.policy.max_export_bytes)?;
        check_ceiling_u64("export.max_files", self.export.max_files, self.policy.max_export_files)?;

        Ok(())
    }

    /// Return a copy with secret payloads redacted for safe API inspection.
    pub fn redacted(&self) -> Self {
        let mut copy = self.clone();
        for secret in copy.secrets.values_mut() {
            if secret.sealed.is_some() {
                secret.sealed = Some("seal1_<redacted>".to_string());
            }
            if secret.ephemeral.is_some() {
                secret.ephemeral = Some("<redacted>".to_string());
            }
        }
        copy
    }
}

fn check_ceiling_u32(field: &str, val: u32, max: Option<u32>) -> Result<()> {
    if let Some(limit) = max {
        if val > limit {
            return Err(PolicyError::LockedPolicyViolation(format!(
                "{field} ({val}) exceeds policy ceiling ({limit})"
            )));
        }
    }
    Ok(())
}

fn check_ceiling_u64(field: &str, val: u64, max: Option<u64>) -> Result<()> {
    if let Some(limit) = max {
        if val > limit {
            return Err(PolicyError::LockedPolicyViolation(format!(
                "{field} ({val}) exceeds policy ceiling ({limit})"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Partial Profile Draft for TOML / JSON composition
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImagePatch {
    #[serde(rename = "ref", default)]
    pub image_ref: Option<String>,
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub run: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputePatch {
    #[serde(default)]
    pub vcpus: Option<u32>,
    #[serde(default)]
    pub memory_mib: Option<u32>,
    #[serde(default)]
    pub workspace_mib: Option<u32>,
    #[serde(default)]
    pub idle_timeout_sec: Option<u64>,
    #[serde(default)]
    pub max_wall_time_sec: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPatch {
    #[serde(default)]
    pub mode: Option<NetworkMode>,
    /// Optional narrow-only filter for runtime overrides: keep only these hosts.
    #[serde(default)]
    pub restrict_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub http: Vec<HttpRule>,
    #[serde(default)]
    pub postgres: Vec<PostgresRule>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressPatch {
    #[serde(default)]
    pub allow_ports: Vec<u16>,
    /// Optional narrow-only filter for runtime overrides: keep only these ingress ports.
    #[serde(default)]
    pub restrict_ports: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportPatch {
    #[serde(default)]
    pub max_bytes: Option<u64>,
    #[serde(default)]
    pub max_files: Option<u64>,
    #[serde(default)]
    pub deny_touch_globs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileDraft {
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub extends: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_services: Option<Vec<HostServiceSpec>>,
    #[serde(default)]
    pub image: Option<ImagePatch>,
    #[serde(default)]
    pub compute: Option<ComputePatch>,
    #[serde(default)]
    pub network: Option<NetworkPatch>,
    #[serde(default)]
    pub ingress: Option<IngressPatch>,
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretSpec>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub export: Option<ExportPatch>,
    #[serde(default)]
    pub policy: Option<PolicyGovernance>,
}

impl ProfileDraft {
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let draft: Self = toml::from_str(s)?;
        for (name, secret) in &draft.secrets {
            if secret.ephemeral.is_some() {
                return Err(PolicyError::EphemeralSecretInFile(name.clone()));
            }
        }
        Ok(draft)
    }

    pub fn from_json_str(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }

    /// Serialize this draft to a valid on-disk TOML document, rejecting any
    /// plaintext `ephemeral` secrets.
    pub fn to_toml_string(&self) -> Result<String> {
        for (name, secret) in &self.secrets {
            if secret.ephemeral.is_some() {
                return Err(PolicyError::EphemeralSecretInFile(name.clone()));
            }
        }
        toml::to_string_pretty(self).map_err(|e| {
            PolicyError::InvalidValue(format!("failed to serialize profile TOML: {e}"))
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProfileRegistry {
    profiles: BTreeMap<String, ProfileDraft>,
}

impl ProfileRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: impl Into<String>, draft: ProfileDraft) {
        self.profiles.insert(name.into(), draft);
    }

    /// Load all `*.toml` profile files from a directory.
    pub fn load_dir(dir: impl AsRef<Path>) -> Result<Self> {
        let mut reg = Self::new();
        let dir = dir.as_ref();
        if !dir.exists() {
            return Ok(reg);
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                let raw = fs::read_to_string(&path)?;
                let mut draft = ProfileDraft::from_toml_str(&raw)?;
                let name = draft.name.clone().unwrap_or_else(|| {
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unnamed")
                        .to_string()
                });
                if draft.name.is_none() {
                    draft.name = Some(name.clone());
                }
                reg.insert(name, draft);
            }
        }
        Ok(reg)
    }

    pub fn names(&self) -> Vec<String> {
        let mut out = vec![BASE_PROFILE_NAME.to_string()];
        for k in self.profiles.keys() {
            if k != BASE_PROFILE_NAME {
                out.push(k.clone());
            }
        }
        out
    }

    /// Resolve a named profile from the registry.
    pub fn resolve_named(&self, name: &str) -> Result<SandboxSpec> {
        if name == BASE_PROFILE_NAME {
            let spec = SandboxSpec::base();
            spec.validate(false)?;
            return Ok(spec);
        }
        let draft = self
            .profiles
            .get(name)
            .ok_or_else(|| PolicyError::UnknownProfile(name.to_string()))?;
        let mut visiting = BTreeSet::new();
        visiting.insert(name.to_string());
        let spec = self.resolve_draft_inner(draft, &mut visiting, false)?;
        spec.validate(false)?;
        Ok(spec)
    }

    /// Resolve an API-supplied `ProfileDraft` (which may `extends` registered profiles
    /// and may contain `ephemeral` secrets over the `0600` Unix socket).
    pub fn resolve_api_request(&self, draft: &ProfileDraft) -> Result<SandboxSpec> {
        self.resolve_api_request_with_options(draft, false)
    }

    /// Resolve an API-supplied `ProfileDraft` with optional operator enforcement requiring
    /// the draft to extend a registered `policy.locked = true` profile.
    pub fn resolve_api_request_with_options(
        &self,
        draft: &ProfileDraft,
        require_locked_parent: bool,
    ) -> Result<SandboxSpec> {
        let mut visiting = BTreeSet::new();
        if require_locked_parent {
            let has_non_base_parent = draft.extends.iter().any(|p| p != BASE_PROFILE_NAME);
            if !has_non_base_parent {
                return Err(PolicyError::LockedPolicyViolation(
                    "must extend a locked profile (--require-locked-profiles)".into(),
                ));
            }
            let parent_spec = self.resolve_parents(&draft.extends, &mut visiting)?;
            if !parent_spec.policy.locked {
                return Err(PolicyError::LockedPolicyViolation(
                    "extended profile must have policy.locked = true".into(),
                ));
            }
            let spec = apply_draft(parent_spec, draft, true)?;
            spec.validate(true)?;
            return Ok(spec);
        }

        let spec = self.resolve_draft_inner(draft, &mut visiting, true)?;
        spec.validate(true)?;
        Ok(spec)
    }

    fn resolve_parents(
        &self,
        extends: &[String],
        visiting: &mut BTreeSet<String>,
    ) -> Result<SandboxSpec> {
        let mut acc = SandboxSpec::base();
        let parents: Vec<&str> = if extends.is_empty() {
            vec![BASE_PROFILE_NAME]
        } else {
            extends.iter().map(String::as_str).collect()
        };

        for parent_name in parents {
            if parent_name == BASE_PROFILE_NAME {
                continue;
            }
            if !visiting.insert(parent_name.to_string()) {
                return Err(PolicyError::CycleDetected(parent_name.to_string()));
            }
            let parent_draft = self
                .profiles
                .get(parent_name)
                .ok_or_else(|| PolicyError::UnknownProfile(parent_name.to_string()))?;
            let parent_spec = self.resolve_draft_inner(parent_draft, visiting, false)?;
            visiting.remove(parent_name);
            acc = merge_specs(acc, parent_spec)?;
        }

        Ok(acc)
    }

    fn resolve_draft_inner(
        &self,
        draft: &ProfileDraft,
        visiting: &mut BTreeSet<String>,
        is_runtime_override: bool,
    ) -> Result<SandboxSpec> {
        let acc = self.resolve_parents(&draft.extends, visiting)?;
        apply_draft(acc, draft, is_runtime_override)
    }
}

fn merge_specs(mut base: SandboxSpec, next: SandboxSpec) -> Result<SandboxSpec> {
    base.version = next.version;
    base.name = next.name;
    if next.image.image_ref.is_some() {
        base.image.image_ref = next.image.image_ref;
    }
    if next.image.base.is_some() {
        base.image.base = next.image.base;
    }
    extend_unique(&mut base.image.packages, next.image.packages);
    base.image.run.extend(next.image.run);

    base.compute = next.compute;
    // Higher privilege network mode wins during profile composition
    if next.network.mode > base.network.mode {
        base.network.mode = next.network.mode;
    }
    merge_http_rules(&mut base.network.http, next.network.http)?;
    merge_pg_rules(&mut base.network.postgres, next.network.postgres)?;
    extend_unique_u16(&mut base.ingress.allow_ports, next.ingress.allow_ports);
    merge_host_services(&mut base.host_services, next.host_services)?;
    merge_secrets(&mut base.secrets, next.secrets)?;
    for (k, v) in next.env {
        base.env.insert(k, v);
    }
    base.export.max_bytes = next.export.max_bytes;
    base.export.max_files = next.export.max_files;
    extend_unique(&mut base.export.deny_touch_globs, next.export.deny_touch_globs);

    base.policy.locked |= next.policy.locked;
    base.policy.max_vcpus = min_opt_u32(base.policy.max_vcpus, next.policy.max_vcpus);
    base.policy.max_memory_mib = min_opt_u32(base.policy.max_memory_mib, next.policy.max_memory_mib);
    base.policy.max_workspace_mib =
        min_opt_u32(base.policy.max_workspace_mib, next.policy.max_workspace_mib);
    base.policy.max_idle_timeout_sec =
        min_opt_u64(base.policy.max_idle_timeout_sec, next.policy.max_idle_timeout_sec);
    base.policy.max_wall_time_sec =
        min_opt_u64(base.policy.max_wall_time_sec, next.policy.max_wall_time_sec);
    base.policy.max_export_bytes =
        min_opt_u64(base.policy.max_export_bytes, next.policy.max_export_bytes);
    base.policy.max_export_files =
        min_opt_u64(base.policy.max_export_files, next.policy.max_export_files);

    Ok(base)
}

fn apply_draft(
    mut base: SandboxSpec,
    draft: &ProfileDraft,
    is_runtime_override: bool,
) -> Result<SandboxSpec> {
    let enforce_narrow = is_runtime_override && base.policy.locked;

    if let Some(v) = draft.version {
        base.version = v;
    }
    if let Some(name) = &draft.name {
        base.name = name.clone();
    }

    if let Some(img) = &draft.image {
        if enforce_narrow
            && (img.image_ref.is_some()
                || img.base.is_some()
                || !img.packages.is_empty()
                || !img.run.is_empty())
        {
            return Err(PolicyError::LockedPolicyViolation(
                "cannot override image on a locked profile".into(),
            ));
        }
        if let Some(r) = &img.image_ref {
            base.image.image_ref = Some(r.clone());
        }
        if let Some(b) = &img.base {
            base.image.base = Some(b.clone());
        }
        extend_unique(&mut base.image.packages, img.packages.clone());
        base.image.run.extend(img.run.clone());
    }

    if let Some(c) = &draft.compute {
        if let Some(v) = c.vcpus {
            if enforce_narrow && v > base.compute.vcpus {
                return Err(PolicyError::LockedPolicyViolation(format!(
                    "cannot widen vcpus from {} to {v}",
                    base.compute.vcpus
                )));
            }
            base.compute.vcpus = v;
        }
        if let Some(v) = c.memory_mib {
            if enforce_narrow && v > base.compute.memory_mib {
                return Err(PolicyError::LockedPolicyViolation(format!(
                    "cannot widen memory_mib from {} to {v}",
                    base.compute.memory_mib
                )));
            }
            base.compute.memory_mib = v;
        }
        if let Some(v) = c.workspace_mib {
            if enforce_narrow && v > base.compute.workspace_mib {
                return Err(PolicyError::LockedPolicyViolation(format!(
                    "cannot widen workspace_mib from {} to {v}",
                    base.compute.workspace_mib
                )));
            }
            base.compute.workspace_mib = v;
        }
        if let Some(v) = c.idle_timeout_sec {
            if enforce_narrow && v > base.compute.idle_timeout_sec {
                return Err(PolicyError::LockedPolicyViolation(format!(
                    "cannot widen idle_timeout_sec from {} to {v}",
                    base.compute.idle_timeout_sec
                )));
            }
            base.compute.idle_timeout_sec = v;
        }
        if let Some(v) = c.max_wall_time_sec {
            if enforce_narrow && v > base.compute.max_wall_time_sec {
                return Err(PolicyError::LockedPolicyViolation(format!(
                    "cannot widen max_wall_time_sec from {} to {v}",
                    base.compute.max_wall_time_sec
                )));
            }
            base.compute.max_wall_time_sec = v;
        }
    }

    if let Some(net) = &draft.network {
        if let Some(mode) = net.mode {
            if enforce_narrow && mode > base.network.mode {
                return Err(PolicyError::LockedPolicyViolation(format!(
                    "cannot widen network.mode from {:?} to {mode:?}",
                    base.network.mode
                )));
            }
            // Narrowing from egress -> loopback or none clears inherited egress rules;
            // any rules explicitly passed in `net` still fail validation below.
            if mode != NetworkMode::Egress && base.network.mode == NetworkMode::Egress {
                base.network.http.clear();
                base.network.postgres.clear();
            }
            base.network.mode = mode;
        }
        if enforce_narrow && (!net.http.is_empty() || !net.postgres.is_empty()) {
            return Err(PolicyError::LockedPolicyViolation(
                "cannot add new network.http or network.postgres rules on a locked profile".into(),
            ));
        }
        merge_http_rules(&mut base.network.http, net.http.clone())?;
        merge_pg_rules(&mut base.network.postgres, net.postgres.clone())?;
        if let Some(restrict) = &net.restrict_hosts {
            let allowed: BTreeSet<String> =
                restrict.iter().map(|h| h.to_ascii_lowercase()).collect();
            base.network
                .http
                .retain(|r| allowed.contains(&r.host.to_ascii_lowercase()));
            base.network
                .postgres
                .retain(|r| allowed.contains(&r.host.to_ascii_lowercase()));
        }
    }

    if let Some(ing) = &draft.ingress {
        if enforce_narrow {
            for &port in &ing.allow_ports {
                if !base.ingress.allow_ports.contains(&port) {
                    return Err(PolicyError::LockedPolicyViolation(format!(
                        "cannot add ingress port {port} on a locked profile"
                    )));
                }
            }
        }
        extend_unique_u16(&mut base.ingress.allow_ports, ing.allow_ports.clone());
        if let Some(restrict) = &ing.restrict_ports {
            let allowed: BTreeSet<u16> = restrict.iter().copied().collect();
            base.ingress.allow_ports.retain(|p| allowed.contains(p));
        }
    }

    if let Some(incoming) = &draft.host_services {
        let mut seen_ports = BTreeSet::new();
        for svc in incoming {
            if !seen_ports.insert(svc.guest_port) {
                return Err(PolicyError::InvalidValue(format!(
                    "duplicate host_services guest_port {}",
                    svc.guest_port
                )));
            }
        }
        if base.policy.locked {
            for svc in incoming {
                let allowed = base
                    .host_services
                    .iter()
                    .any(|p| p.guest_port == svc.guest_port && p.target == svc.target);
                if !allowed {
                    return Err(PolicyError::LockedPolicyViolation(format!(
                        "cannot add host service '{}' (port {} -> '{}') on a locked profile",
                        svc.name, svc.guest_port, svc.target
                    )));
                }
            }
            base.host_services = incoming.clone();
        } else {
            merge_host_services(&mut base.host_services, incoming.clone())?;
        }
    }

    if enforce_narrow && !draft.secrets.is_empty() {
        // On a locked profile, callers may only supply ephemeral values for already-declared secret keys
        for (k, v) in &draft.secrets {
            if !base.secrets.contains_key(k) {
                return Err(PolicyError::LockedPolicyViolation(format!(
                    "cannot add new secret '{k}' on a locked profile"
                )));
            }
            base.secrets.insert(k.clone(), v.clone());
        }
    } else {
        merge_secrets(&mut base.secrets, draft.secrets.clone())?;
    }

    for (k, v) in &draft.env {
        base.env.insert(k.clone(), v.clone());
    }

    if let Some(exp) = &draft.export {
        if let Some(v) = exp.max_bytes {
            if enforce_narrow && v > base.export.max_bytes {
                return Err(PolicyError::LockedPolicyViolation(format!(
                    "cannot widen export.max_bytes from {} to {v}",
                    base.export.max_bytes
                )));
            }
            base.export.max_bytes = v;
        }
        if let Some(v) = exp.max_files {
            if enforce_narrow && v > base.export.max_files {
                return Err(PolicyError::LockedPolicyViolation(format!(
                    "cannot widen export.max_files from {} to {v}",
                    base.export.max_files
                )));
            }
            base.export.max_files = v;
        }
        extend_unique(&mut base.export.deny_touch_globs, exp.deny_touch_globs.clone());
    }

    if let Some(pol) = &draft.policy {
        if enforce_narrow && !pol.locked {
            return Err(PolicyError::LockedPolicyViolation(
                "cannot unlock a locked profile".into(),
            ));
        }
        base.policy.locked |= pol.locked;
        base.policy.max_vcpus = min_opt_u32(base.policy.max_vcpus, pol.max_vcpus);
        base.policy.max_memory_mib = min_opt_u32(base.policy.max_memory_mib, pol.max_memory_mib);
        base.policy.max_workspace_mib =
            min_opt_u32(base.policy.max_workspace_mib, pol.max_workspace_mib);
        base.policy.max_idle_timeout_sec =
            min_opt_u64(base.policy.max_idle_timeout_sec, pol.max_idle_timeout_sec);
        base.policy.max_wall_time_sec =
            min_opt_u64(base.policy.max_wall_time_sec, pol.max_wall_time_sec);
        base.policy.max_export_bytes =
            min_opt_u64(base.policy.max_export_bytes, pol.max_export_bytes);
        base.policy.max_export_files =
            min_opt_u64(base.policy.max_export_files, pol.max_export_files);
    }

    Ok(base)
}

fn merge_http_rules(existing: &mut Vec<HttpRule>, incoming: Vec<HttpRule>) -> Result<()> {
    for rule in incoming {
        if existing.contains(&rule) {
            continue;
        }
        for prev in existing.iter() {
            if prev.host.eq_ignore_ascii_case(&rule.host) && prev.port == rule.port {
                for p in &rule.path_prefixes {
                    if prev.path_prefixes.contains(p) {
                        return Err(PolicyError::HttpRuleConflict {
                            host: rule.host.clone(),
                            prefix: p.clone(),
                        });
                    }
                }
            }
        }
        existing.push(rule);
    }
    Ok(())
}

fn merge_pg_rules(existing: &mut Vec<PostgresRule>, incoming: Vec<PostgresRule>) -> Result<()> {
    for rule in incoming {
        if existing.contains(&rule) {
            continue;
        }
        if existing
            .iter()
            .any(|p| p.host.eq_ignore_ascii_case(&rule.host) && p.port == rule.port)
        {
            return Err(PolicyError::PostgresRuleConflict {
                host: rule.host.clone(),
                port: rule.port,
            });
        }
        existing.push(rule);
    }
    Ok(())
}

fn merge_host_services(
    existing: &mut Vec<HostServiceSpec>,
    incoming: Vec<HostServiceSpec>,
) -> Result<()> {
    for svc in incoming {
        if existing.contains(&svc) {
            continue;
        }
        if existing.iter().any(|p| p.guest_port == svc.guest_port) {
            return Err(PolicyError::InvalidValue(format!(
                "duplicate host_services guest_port {}",
                svc.guest_port
            )));
        }
        existing.push(svc);
    }
    Ok(())
}

fn merge_secrets(
    existing: &mut BTreeMap<String, SecretSpec>,
    incoming: BTreeMap<String, SecretSpec>,
) -> Result<()> {
    for (name, spec) in incoming {
        if let Some(prev) = existing.get(&name) {
            if prev != &spec {
                return Err(PolicyError::SecretConflict(name));
            }
        } else {
            existing.insert(name, spec);
        }
    }
    Ok(())
}

fn extend_unique(target: &mut Vec<String>, items: Vec<String>) {
    for item in items {
        if !target.contains(&item) {
            target.push(item);
        }
    }
}

fn extend_unique_u16(target: &mut Vec<u16>, items: Vec<u16>) {
    for item in items {
        if !target.contains(&item) {
            target.push(item);
        }
    }
}

fn min_opt_u32(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

fn min_opt_u64(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_profile_defaults_are_fail_closed() {
        let base = SandboxSpec::base();
        base.validate(false).unwrap();
        assert_eq!(base.image.base.as_deref(), Some("debian:bookworm-slim"));
        assert!(base.image.packages.is_empty());
        assert!(base.image.run.is_empty());
        assert_eq!(base.compute.workspace_mib, 2048);
        assert_eq!(base.network.mode, NetworkMode::Loopback);
        assert!(base.ingress.allow_ports.is_empty());
        assert!(base.derived_dns_allow().is_empty());
        assert!(base.export.deny_touch_globs.iter().any(|g| g == ".github/**"));

        // Sensible default env entries present and overridable
        assert_eq!(base.env.get("HOME").map(String::as_str), Some("/home/sandbox"));
        assert_eq!(
            base.env.get("PATH").map(String::as_str),
            Some("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        );
        assert_eq!(base.env.get("TERM").map(String::as_str), Some("xterm-256color"));
        assert_eq!(base.env.get("LANG").map(String::as_str), Some("C.UTF-8"));
        assert_eq!(base.env.get("LC_ALL").map(String::as_str), Some("C.UTF-8"));
        assert_eq!(
            base.env.get("SSL_CERT_FILE").map(String::as_str),
            Some("/etc/ssl/certs/ca-certificates.crt")
        );
        assert_eq!(
            base.env.get("NODE_EXTRA_CA_CERTS").map(String::as_str),
            Some("/run/blackwall/mitm-ca.crt")
        );

        let reg = ProfileRegistry::new();
        let child = ProfileDraft::from_toml_str(
            r#"
            [env]
            TERM = "dumb"
            CUSTOM = "1"
            "#,
        )
        .unwrap();
        let resolved = reg.resolve_api_request(&child).unwrap();
        assert_eq!(resolved.env.get("TERM").map(String::as_str), Some("dumb"));
        assert_eq!(resolved.env.get("HOME").map(String::as_str), Some("/home/sandbox"));
        assert_eq!(resolved.env.get("CUSTOM").map(String::as_str), Some("1"));
    }

    #[test]
    fn extends_composition_and_derived_dns() {
        let mut reg = ProfileRegistry::new();
        reg.insert(
            "rust-dev",
            ProfileDraft::from_toml_str(
                r#"
                version = 1
                name = "rust-dev"
                extends = ["base"]

                [image]
                packages = ["git", "build-essential"]

                [compute]
                vcpus = 4
                memory_mib = 4096

                [network]
                mode = "egress"

                [[network.http]]
                host = "crates.io"
                methods = ["GET"]
                path_prefixes = ["/api/v1/crates"]
                "#,
            )
            .unwrap(),
        );
        reg.insert(
            "agent",
            ProfileDraft::from_toml_str(
                r#"
                version = 1
                name = "agent"
                extends = ["rust-dev"]

                [image]
                packages = ["postgresql-client"]

                [[network.http]]
                host = "api.github.com"
                methods = ["GET", "POST"]
                path_prefixes = ["/repos/org/repo/"]
                auth = { secret = "GITHUB_TOKEN", kind = "bearer" }

                [[network.postgres]]
                host = "db.internal"
                port = 5432
                secret = "PGPASSWORD"

                [secrets.GITHUB_TOKEN]
                placeholder_prefix = "ghp_bw00"
                sealed = "seal1_abc"

                [secrets.PGPASSWORD]
                placeholder_prefix = "bwpg_"
                sealed = "seal1_def"
                "#,
            )
            .unwrap(),
        );

        let spec = reg.resolve_named("agent").unwrap();
        assert_eq!(spec.compute.vcpus, 4);
        assert_eq!(spec.compute.workspace_mib, 2048); // inherited from base
        assert_eq!(
            spec.image.packages,
            vec!["git", "build-essential", "postgresql-client"]
        );
        let dns = spec.derived_dns_allow();
        assert!(dns.contains("crates.io"));
        assert!(dns.contains("api.github.com"));
        assert!(dns.contains("db.internal"));
        assert_eq!(dns.len(), 3);
    }

    #[test]
    fn detects_cycles_and_rule_conflicts() {
        let mut reg = ProfileRegistry::new();
        reg.insert(
            "a",
            ProfileDraft::from_toml_str(r#"extends = ["b"]"#).unwrap(),
        );
        reg.insert(
            "b",
            ProfileDraft::from_toml_str(r#"extends = ["a"]"#).unwrap(),
        );
        assert!(matches!(
            reg.resolve_named("a"),
            Err(PolicyError::CycleDetected(_))
        ));

        let mut reg2 = ProfileRegistry::new();
        reg2.insert(
            "p1",
            ProfileDraft::from_toml_str(
                r#"
                [network]
                mode = "egress"
                [[network.http]]
                host = "api.github.com"
                methods = ["GET"]
                path_prefixes = ["/repos/"]
                "#,
            )
            .unwrap(),
        );
        reg2.insert(
            "p2",
            ProfileDraft::from_toml_str(
                r#"
                extends = ["p1"]
                [[network.http]]
                host = "api.github.com"
                methods = ["POST"]
                path_prefixes = ["/repos/"]
                "#,
            )
            .unwrap(),
        );
        assert!(matches!(
            reg2.resolve_named("p2"),
            Err(PolicyError::HttpRuleConflict { .. })
        ));
    }

    #[test]
    fn locked_profile_enforces_narrow_only_runtime_overrides() {
        let mut reg = ProfileRegistry::new();
        reg.insert(
            "locked-agent",
            ProfileDraft::from_toml_str(
                r#"
                [compute]
                vcpus = 4
                memory_mib = 4096

                [network]
                mode = "egress"
                [[network.http]]
                host = "crates.io"
                methods = ["GET"]
                path_prefixes = ["/api/"]

                [policy]
                locked = true
                "#,
            )
            .unwrap(),
        );

        // Widening vcpus fails
        let widen: ProfileDraft = serde_json::from_value(serde_json::json!({
            "extends": ["locked-agent"],
            "compute": { "vcpus": 8 }
        }))
        .unwrap();
        assert!(matches!(
            reg.resolve_api_request(&widen),
            Err(PolicyError::LockedPolicyViolation(_))
        ));

        // Adding new host fails
        let add_host: ProfileDraft = serde_json::from_value(serde_json::json!({
            "extends": ["locked-agent"],
            "network": {
                "http": [{
                    "host": "evil.example",
                    "methods": ["POST"],
                    "path_prefixes": ["/"]
                }]
            }
        }))
        .unwrap();
        assert!(matches!(
            reg.resolve_api_request(&add_host),
            Err(PolicyError::LockedPolicyViolation(_))
        ));

        // Narrowing vcpus and dropping to loopback succeeds
        let narrow: ProfileDraft = serde_json::from_value(serde_json::json!({
            "extends": ["locked-agent"],
            "compute": { "vcpus": 2 },
            "network": { "mode": "loopback", "restrict_hosts": [] }
        }))
        .unwrap();
        let resolved = reg.resolve_api_request(&narrow).unwrap();
        assert_eq!(resolved.compute.vcpus, 2);
        assert_eq!(resolved.network.mode, NetworkMode::Loopback);
    }

    #[test]
    fn ephemeral_secrets_allowed_on_api_but_forbidden_in_toml() {
        let bad_toml = r#"
            [secrets.API_KEY]
            placeholder_prefix = "sk_"
            ephemeral = "plain-secret"
        "#;
        assert!(matches!(
            ProfileDraft::from_toml_str(bad_toml),
            Err(PolicyError::EphemeralSecretInFile(_))
        ));

        let api_draft = ProfileDraft::from_json_str(
            r#"{
                "network": {
                    "mode": "egress",
                    "http": [{
                        "host": "api.anthropic.com",
                        "methods": ["POST"],
                        "path_prefixes": ["/v1/messages"],
                        "auth": { "kind": "header", "secret": "ANTHROPIC_API_KEY", "name": "x-api-key" }
                    }]
                },
                "secrets": {
                    "ANTHROPIC_API_KEY": {
                        "placeholder_prefix": "sk-ant-bw00-",
                        "ephemeral": "real-ephemeral-value"
                    }
                }
            }"#,
        )
        .unwrap();
        let reg = ProfileRegistry::new();
        let spec = reg.resolve_api_request(&api_draft).unwrap();
        assert_eq!(
            spec.redacted().secrets["ANTHROPIC_API_KEY"].ephemeral.as_deref(),
            Some("<redacted>")
        );
    }

    #[test]
    fn ingress_allow_ports_composition_validation_and_locked_enforcement() {
        // 1. Base profile is fail-closed (no ingress ports allowed by default)
        let base = SandboxSpec::base();
        assert!(base.ingress.allow_ports.is_empty());

        // 2. Composing profiles merges allow_ports uniquely
        let mut reg = ProfileRegistry::new();
        reg.insert(
            "web-base",
            ProfileDraft::from_toml_str(
                r#"
                version = 1
                name = "web-base"
                extends = ["base"]

                [ingress]
                allow_ports = [3000, 5173]
                "#,
            )
            .unwrap(),
        );
        reg.insert(
            "web-locked",
            ProfileDraft::from_toml_str(
                r#"
                version = 1
                name = "web-locked"
                extends = ["web-base"]

                [ingress]
                allow_ports = [5173, 8080]

                [policy]
                locked = true
                "#,
            )
            .unwrap(),
        );

        let resolved = reg.resolve_named("web-locked").unwrap();
        assert_eq!(resolved.ingress.allow_ports, vec![3000, 5173, 8080]);

        // 3. Port 0 is rejected by validation
        let zero_port: ProfileDraft = serde_json::from_value(serde_json::json!({
            "ingress": { "allow_ports": [0] }
        }))
        .unwrap();
        assert!(matches!(
            reg.resolve_api_request(&zero_port),
            Err(PolicyError::InvalidValue(_))
        ));

        // 4. Locked profile rejects widening ingress ports at runtime
        let widen_port: ProfileDraft = serde_json::from_value(serde_json::json!({
            "extends": ["web-locked"],
            "ingress": { "allow_ports": [9090] }
        }))
        .unwrap();
        assert!(matches!(
            reg.resolve_api_request(&widen_port),
            Err(PolicyError::LockedPolicyViolation(_))
        ));

        // 5. Locked profile allows narrowing via restrict_ports (and never adds unlisted ports)
        let narrow_port: ProfileDraft = serde_json::from_value(serde_json::json!({
            "extends": ["web-locked"],
            "ingress": { "restrict_ports": [3000, 9999] }
        }))
        .unwrap();
        let narrowed = reg.resolve_api_request(&narrow_port).unwrap();
        assert_eq!(narrowed.ingress.allow_ports, vec![3000]);

        // 6. Real profiles/ts-dev.toml parses and exposes expected dev ports
        let ts_dev_raw = include_str!("../../../profiles/ts-dev.toml");
        let ts_dev_draft = ProfileDraft::from_toml_str(ts_dev_raw).unwrap();
        let ts_dev_spec = reg.resolve_api_request(&ts_dev_draft).unwrap();
        assert_eq!(ts_dev_spec.ingress.allow_ports, vec![3000, 5173, 8080, 8787]);
    }

    #[test]
    fn validate_profile_name_and_draft_to_toml_roundtrip() {
        assert!(validate_profile_name("dev-1_ok").is_ok());
        assert!(validate_profile_name("a").is_ok());
        assert!(validate_profile_name(&"a".repeat(64)).is_ok());
        assert!(validate_profile_name("base").is_err());
        assert!(validate_profile_name("").is_err());
        assert!(validate_profile_name(&"a".repeat(65)).is_err());
        assert!(validate_profile_name("-leading-dash").is_err());
        assert!(validate_profile_name("UpperCase").is_err());
        assert!(validate_profile_name("../escape").is_err());

        let mut draft = ProfileDraft {
            version: Some(1),
            name: Some("custom-net".into()),
            extends: vec!["base".into()],
            network: Some(NetworkPatch {
                mode: Some(NetworkMode::Egress),
                restrict_hosts: Some(vec!["api.github.com".into()]),
                http: vec![HttpRule {
                    host: "api.github.com".into(),
                    port: 443,
                    methods: vec!["GET".into()],
                    path_prefixes: vec!["/repos/".into()],
                    max_request_bytes: None,
                    auth: None,
                }],
                postgres: vec![],
            }),
            ..ProfileDraft::default()
        };
        let rendered = draft.to_toml_string().unwrap();
        let reparsed = ProfileDraft::from_toml_str(&rendered).unwrap();
        assert_eq!(reparsed, draft);

        // Ephemeral secret rejected when serializing to on-disk TOML
        draft.secrets.insert(
            "PLAIN".into(),
            SecretSpec {
                placeholder_prefix: "p_".into(),
                sealed: None,
                ephemeral: Some("super-secret".into()),
            },
        );
        assert!(matches!(
            draft.to_toml_string(),
            Err(PolicyError::EphemeralSecretInFile(_))
        ));
    }

    #[test]
    fn validate_host_service_enforces_name_port_and_target_bounds() {
        // Valid loopback IPv4, IPv6, and unix socket targets
        for svc in [
            HostServiceSpec {
                name: "local-pg_1.dev".into(),
                guest_port: 5432,
                target: "127.0.0.1:5432".into(),
            },
            HostServiceSpec {
                name: "LoopbackV6".into(),
                guest_port: 6379,
                target: "[::1]:6379".into(),
            },
            HostServiceSpec {
                name: "unix-pg".into(),
                guest_port: 5433,
                target: "unix:///run/pg.sock".into(),
            },
            HostServiceSpec {
                name: "a".repeat(64),
                guest_port: 1,
                target: "127.0.1.1:8080".into(),
            },
        ] {
            assert!(
                validate_host_service(&svc).is_ok(),
                "expected valid host service: {svc:?}"
            );
        }

        // Invalid names, ports, non-loopback IPs, hostnames, and malformed unix paths
        for bad in [
            HostServiceSpec {
                name: "".into(),
                guest_port: 5432,
                target: "127.0.0.1:5432".into(),
            },
            HostServiceSpec {
                name: "a".repeat(65),
                guest_port: 5432,
                target: "127.0.0.1:5432".into(),
            },
            HostServiceSpec {
                name: "bad name".into(),
                guest_port: 5432,
                target: "127.0.0.1:5432".into(),
            },
            HostServiceSpec {
                name: "bad/name".into(),
                guest_port: 5432,
                target: "127.0.0.1:5432".into(),
            },
            HostServiceSpec {
                name: "zero-port".into(),
                guest_port: 0,
                target: "127.0.0.1:5432".into(),
            },
            HostServiceSpec {
                name: "target-zero-port".into(),
                guest_port: 5432,
                target: "127.0.0.1:0".into(),
            },
            HostServiceSpec {
                name: "v6-zero-port".into(),
                guest_port: 5432,
                target: "[::1]:0".into(),
            },
            HostServiceSpec {
                name: "rfc1918".into(),
                guest_port: 5432,
                target: "192.168.1.1:5432".into(),
            },
            HostServiceSpec {
                name: "imds".into(),
                guest_port: 80,
                target: "169.254.169.254:80".into(),
            },
            HostServiceSpec {
                name: "public-ip".into(),
                guest_port: 53,
                target: "8.8.8.8:53".into(),
            },
            HostServiceSpec {
                name: "hostname".into(),
                guest_port: 5432,
                target: "localhost:5432".into(),
            },
            HostServiceSpec {
                name: "unix-traversal".into(),
                guest_port: 5432,
                target: "unix:///../etc/passwd".into(),
            },
            HostServiceSpec {
                name: "unix-nested-traversal".into(),
                guest_port: 5432,
                target: "unix:///run/../etc/passwd".into(),
            },
            HostServiceSpec {
                name: "unix-relative".into(),
                guest_port: 5432,
                target: "unix://run/pg.sock".into(),
            },
            HostServiceSpec {
                name: "unix-root-only".into(),
                guest_port: 5432,
                target: "unix:///".into(),
            },
            HostServiceSpec {
                name: "unix-nul".into(),
                guest_port: 5432,
                target: "unix:///run/pg\0.sock".into(),
            },
        ] {
            assert!(
                matches!(validate_host_service(&bad), Err(PolicyError::InvalidValue(_))),
                "expected InvalidValue for {bad:?}"
            );
        }
    }

    #[test]
    fn host_services_resolution_none_mode_duplicates_locked_and_toml_roundtrip() {
        // 1. Base profile is fail-closed
        let base = SandboxSpec::base();
        assert!(base.host_services.is_empty());

        let mut reg = ProfileRegistry::new();

        // 2. Reject host_services when network.mode == none
        let none_mode_draft = ProfileDraft::from_toml_str(
            r#"
            [network]
            mode = "none"

            [[host_services]]
            name = "pg"
            guest_port = 5432
            target = "127.0.0.1:5432"
            "#,
        )
        .unwrap();
        match reg.resolve_api_request(&none_mode_draft) {
            Err(PolicyError::InvalidValue(msg)) => {
                assert_eq!(msg, "host_services cannot be used when network.mode is 'none'");
            }
            other => panic!("expected InvalidValue for none mode, got {other:?}"),
        }

        // 3. Reject duplicate guest_port within a single draft
        let dup_draft = ProfileDraft::from_toml_str(
            r#"
            [[host_services]]
            name = "pg1"
            guest_port = 5432
            target = "127.0.0.1:5432"

            [[host_services]]
            name = "pg2"
            guest_port = 5432
            target = "127.0.0.1:5433"
            "#,
        )
        .unwrap();
        assert!(matches!(
            reg.resolve_api_request(&dup_draft),
            Err(PolicyError::InvalidValue(_))
        ));

        // 4. Reject duplicate guest_port across inherited profiles
        reg.insert(
            "svc-base",
            ProfileDraft::from_toml_str(
                r#"
                version = 1
                name = "svc-base"

                [[host_services]]
                name = "pg"
                guest_port = 5432
                target = "127.0.0.1:5432"
                "#,
            )
            .unwrap(),
        );
        let dup_child = ProfileDraft::from_toml_str(
            r#"
            extends = ["svc-base"]

            [[host_services]]
            name = "pg-conflict"
            guest_port = 5432
            target = "127.0.0.1:5433"
            "#,
        )
        .unwrap();
        assert!(matches!(
            reg.resolve_api_request(&dup_child),
            Err(PolicyError::InvalidValue(_))
        ));

        // 5. Locked profile ceiling enforcement (both child profiles and runtime overrides)
        reg.insert(
            "svc-locked",
            ProfileDraft::from_toml_str(
                r#"
                version = 1
                name = "svc-locked"

                [policy]
                locked = true

                [[host_services]]
                name = "pg"
                guest_port = 5432
                target = "127.0.0.1:5432"

                [[host_services]]
                name = "redis"
                guest_port = 6379
                target = "unix:///run/redis.sock"
                "#,
            )
            .unwrap(),
        );

        // Omitting host_services inherits parent's host_services
        let inherit_override: ProfileDraft = serde_json::from_value(serde_json::json!({
            "extends": ["svc-locked"],
            "compute": { "vcpus": 1 }
        }))
        .unwrap();
        let inherited = reg.resolve_api_request(&inherit_override).unwrap();
        assert_eq!(inherited.host_services.len(), 2);

        // Narrowing to a subset of parent's (guest_port, target) pairs succeeds
        let narrow_override: ProfileDraft = serde_json::from_value(serde_json::json!({
            "extends": ["svc-locked"],
            "host_services": [
                { "name": "pg", "guest_port": 5432, "target": "127.0.0.1:5432" }
            ]
        }))
        .unwrap();
        let narrowed = reg.resolve_api_request(&narrow_override).unwrap();
        assert_eq!(narrowed.host_services.len(), 1);
        assert_eq!(narrowed.host_services[0].guest_port, 5432);

        // Narrowing to empty list succeeds (and allows dropping to network.mode = none)
        let empty_override: ProfileDraft = serde_json::from_value(serde_json::json!({
            "extends": ["svc-locked"],
            "network": { "mode": "none" },
            "host_services": []
        }))
        .unwrap();
        let emptied = reg.resolve_api_request(&empty_override).unwrap();
        assert!(emptied.host_services.is_empty());
        assert_eq!(emptied.network.mode, NetworkMode::None);

        // Adding a new host service fails with LockedPolicyViolation
        let add_new: ProfileDraft = serde_json::from_value(serde_json::json!({
            "extends": ["svc-locked"],
            "host_services": [
                { "name": "pg", "guest_port": 5432, "target": "127.0.0.1:5432" },
                { "name": "evil", "guest_port": 8080, "target": "127.0.0.1:8080" }
            ]
        }))
        .unwrap();
        assert!(matches!(
            reg.resolve_api_request(&add_new),
            Err(PolicyError::LockedPolicyViolation(_))
        ));

        // Changing target on an existing port fails with LockedPolicyViolation
        let change_target: ProfileDraft = serde_json::from_value(serde_json::json!({
            "extends": ["svc-locked"],
            "host_services": [
                { "name": "pg", "guest_port": 5432, "target": "127.0.0.1:9999" }
            ]
        }))
        .unwrap();
        assert!(matches!(
            reg.resolve_api_request(&change_target),
            Err(PolicyError::LockedPolicyViolation(_))
        ));

        // Child named profile extending a locked parent also cannot add host services
        reg.insert(
            "svc-child-widen",
            ProfileDraft::from_toml_str(
                r#"
                version = 1
                name = "svc-child-widen"
                extends = ["svc-locked"]

                [[host_services]]
                name = "extra"
                guest_port = 9000
                target = "127.0.0.1:9000"
                "#,
            )
            .unwrap(),
        );
        assert!(matches!(
            reg.resolve_named("svc-child-widen"),
            Err(PolicyError::LockedPolicyViolation(_))
        ));

        // 6. ProfileDraft::to_toml_string round-trips cleanly with non-empty and empty host_services
        let draft_with_svcs = ProfileDraft {
            version: Some(1),
            name: Some("with-host-svcs".into()),
            extends: vec!["base".into()],
            host_services: Some(vec![
                HostServiceSpec {
                    name: "pg".into(),
                    guest_port: 5432,
                    target: "127.0.0.1:5432".into(),
                },
                HostServiceSpec {
                    name: "redis".into(),
                    guest_port: 6379,
                    target: "unix:///run/redis.sock".into(),
                },
            ]),
            network: Some(NetworkPatch {
                mode: Some(NetworkMode::Loopback),
                ..NetworkPatch::default()
            }),
            policy: Some(PolicyGovernance {
                locked: true,
                ..PolicyGovernance::default()
            }),
            ..ProfileDraft::default()
        };
        let rendered = draft_with_svcs.to_toml_string().unwrap();
        let reparsed = ProfileDraft::from_toml_str(&rendered).unwrap();
        assert_eq!(reparsed, draft_with_svcs);

        let draft_empty_svcs = ProfileDraft {
            version: Some(1),
            name: Some("empty-host-svcs".into()),
            extends: vec!["svc-locked".into()],
            host_services: Some(vec![]),
            network: Some(NetworkPatch {
                mode: Some(NetworkMode::None),
                ..NetworkPatch::default()
            }),
            ..ProfileDraft::default()
        };
        let rendered_empty = draft_empty_svcs.to_toml_string().unwrap();
        let reparsed_empty = ProfileDraft::from_toml_str(&rendered_empty).unwrap();
        assert_eq!(reparsed_empty, draft_empty_svcs);
    }

    #[test]
    fn policy_ceiling_parses_toml_and_enforces_all_limits() {
        let ceiling = PolicyCeiling::from_toml_str(
            r#"
            max_network_mode = "egress"
            allowed_egress_hosts = ["API.GitHub.com", "db.internal"]
            allow_host_services = false
            allow_image_build = false
            max_vcpus = 4
            max_memory_mib = 2048
            max_workspace_mib = 1024
            max_idle_timeout_sec = 300
            max_wall_time_sec = 1800
            "#,
        )
        .unwrap();

        assert_eq!(ceiling.max_network_mode, Some(NetworkMode::Egress));
        assert_eq!(ceiling.allow_host_services, Some(false));
        assert_eq!(ceiling.allow_image_build, Some(false));
        assert_eq!(ceiling.max_vcpus, Some(4));

        // Base-like spec within ceiling passes (case-insensitive egress host match).
        let mut ok_spec = SandboxSpec::base();
        ok_spec.compute.vcpus = 4;
        ok_spec.compute.memory_mib = 2048;
        ok_spec.compute.workspace_mib = 1024;
        ok_spec.compute.idle_timeout_sec = 300;
        ok_spec.compute.max_wall_time_sec = 1800;
        ok_spec.network.mode = NetworkMode::Egress;
        ok_spec.network.http.push(HttpRule {
            host: "api.github.com".into(),
            port: 443,
            methods: vec!["GET".into()],
            path_prefixes: vec!["/repos/".into()],
            max_request_bytes: None,
            auth: None,
        });
        ok_spec.network.postgres.push(PostgresRule {
            host: "DB.INTERNAL".into(),
            port: 5432,
            secret: "PG".into(),
            require_upstream_tls: true,
        });
        assert!(ceiling.enforce(&ok_spec).is_ok());

        // Disallowed HTTP egress host fails.
        let mut bad_http = ok_spec.clone();
        bad_http.network.http.push(HttpRule {
            host: "evil.example".into(),
            port: 443,
            methods: vec!["GET".into()],
            path_prefixes: vec!["/".into()],
            max_request_bytes: None,
            auth: None,
        });
        assert!(matches!(
            ceiling.enforce(&bad_http),
            Err(PolicyError::LockedPolicyViolation(_))
        ));

        // Disallowed Postgres egress host fails.
        let mut bad_pg = ok_spec.clone();
        bad_pg.network.postgres.push(PostgresRule {
            host: "other-db.internal".into(),
            port: 5432,
            secret: "PG".into(),
            require_upstream_tls: true,
        });
        assert!(matches!(
            ceiling.enforce(&bad_pg),
            Err(PolicyError::LockedPolicyViolation(_))
        ));

        // Network mode exceeding max_network_mode fails.
        let loopback_ceiling = PolicyCeiling {
            max_network_mode: Some(NetworkMode::Loopback),
            ..PolicyCeiling::default()
        };
        assert!(matches!(
            loopback_ceiling.enforce(&ok_spec),
            Err(PolicyError::LockedPolicyViolation(_))
        ));

        // Host services rejected when allow_host_services == Some(false).
        let mut bad_hs = ok_spec.clone();
        bad_hs.host_services.push(HostServiceSpec {
            name: "pg".into(),
            guest_port: 5432,
            target: "127.0.0.1:5432".into(),
        });
        assert!(matches!(
            ceiling.enforce(&bad_hs),
            Err(PolicyError::LockedPolicyViolation(_))
        ));

        // Each compute/timeout limit enforced.
        let mut over_vcpus = ok_spec.clone();
        over_vcpus.compute.vcpus = 5;
        assert!(matches!(
            ceiling.enforce(&over_vcpus),
            Err(PolicyError::LockedPolicyViolation(_))
        ));

        let mut over_mem = ok_spec.clone();
        over_mem.compute.memory_mib = 2049;
        assert!(matches!(
            ceiling.enforce(&over_mem),
            Err(PolicyError::LockedPolicyViolation(_))
        ));

        let mut over_ws = ok_spec.clone();
        over_ws.compute.workspace_mib = 1025;
        assert!(matches!(
            ceiling.enforce(&over_ws),
            Err(PolicyError::LockedPolicyViolation(_))
        ));

        let mut over_idle = ok_spec.clone();
        over_idle.compute.idle_timeout_sec = 301;
        assert!(matches!(
            ceiling.enforce(&over_idle),
            Err(PolicyError::LockedPolicyViolation(_))
        ));

        let mut over_wall = ok_spec.clone();
        over_wall.compute.max_wall_time_sec = 1801;
        assert!(matches!(
            ceiling.enforce(&over_wall),
            Err(PolicyError::LockedPolicyViolation(_))
        ));
    }

    #[test]
    fn require_locked_parent_enforces_locked_profile_inheritance_and_narrow_only() {
        let mut reg = ProfileRegistry::new();
        reg.insert(
            "unlocked-dev",
            ProfileDraft::from_toml_str(
                r#"
                version = 1
                name = "unlocked-dev"
                extends = ["base"]

                [compute]
                vcpus = 2
                "#,
            )
            .unwrap(),
        );
        reg.insert(
            "locked-prod",
            ProfileDraft::from_toml_str(
                r#"
                version = 1
                name = "locked-prod"
                extends = ["base"]

                [compute]
                vcpus = 2
                memory_mib = 1024

                [policy]
                locked = true
                "#,
            )
            .unwrap(),
        );

        // Empty extends rejected (even if runtime draft tries to set policy.locked = true).
        let empty_extends: ProfileDraft = serde_json::from_value(serde_json::json!({
            "policy": { "locked": true }
        }))
        .unwrap();
        match reg.resolve_api_request_with_options(&empty_extends, true) {
            Err(PolicyError::LockedPolicyViolation(msg)) => {
                assert!(msg.contains("--require-locked-profiles"), "unexpected msg: {msg}");
            }
            other => panic!("expected LockedPolicyViolation for empty extends, got {other:?}"),
        }

        // extends = ["base"] rejected.
        let base_only: ProfileDraft = serde_json::from_value(serde_json::json!({
            "extends": ["base"]
        }))
        .unwrap();
        assert!(matches!(
            reg.resolve_api_request_with_options(&base_only, true),
            Err(PolicyError::LockedPolicyViolation(_))
        ));

        // Extending an unlocked profile rejected (even if runtime draft passes policy.locked = true).
        let unlocked: ProfileDraft = serde_json::from_value(serde_json::json!({
            "extends": ["unlocked-dev"],
            "policy": { "locked": true }
        }))
        .unwrap();
        match reg.resolve_api_request_with_options(&unlocked, true) {
            Err(PolicyError::LockedPolicyViolation(msg)) => {
                assert!(msg.contains("policy.locked = true"), "unexpected msg: {msg}");
            }
            other => panic!("expected LockedPolicyViolation for unlocked parent, got {other:?}"),
        }

        // Extending a locked profile succeeds and allows narrowing.
        let locked_narrow: ProfileDraft = serde_json::from_value(serde_json::json!({
            "extends": ["locked-prod"],
            "compute": { "vcpus": 1 }
        }))
        .unwrap();
        let resolved = reg
            .resolve_api_request_with_options(&locked_narrow, true)
            .unwrap();
        assert_eq!(resolved.compute.vcpus, 1);
        assert!(resolved.policy.locked);

        // Extending a locked profile still rejects widening!
        let locked_widen: ProfileDraft = serde_json::from_value(serde_json::json!({
            "extends": ["locked-prod"],
            "compute": { "vcpus": 4 }
        }))
        .unwrap();
        assert!(matches!(
            reg.resolve_api_request_with_options(&locked_widen, true),
            Err(PolicyError::LockedPolicyViolation(_))
        ));
    }
}
