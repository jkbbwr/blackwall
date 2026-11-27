//! `clap` v4 command-line interface definitions for `blackwall`.

use blackwall_policy::NetworkMode;
use blackwall_proto::{DownloadFormat, SignalKind};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};

/// Blackwall — rootless interactive LLM sandbox CLI.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "blackwall",
    version,
    about = "Launch and drive rootless interactive Blackwall sandboxes over a local Unix socket"
)]
pub struct Cli {
    /// Path to the blackwall-daemon Unix domain socket
    /// (default: $BLACKWALL_SOCKET or $XDG_RUNTIME_DIR/blackwall.sock)
    #[arg(long, global = true, value_name = "PATH")]
    pub socket: Option<PathBuf>,

    /// Emit machine-readable JSON output
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Create a new interactive sandbox from composed profiles or a TOML file
    Create(CreateArgs),
    /// List active sandboxes
    #[command(visible_alias = "ls")]
    List,
    /// Inspect a running sandbox's status, caps, timers, and background processes
    Inspect(InspectArgs),
    /// Destroy a sandbox immediately and wipe its ephemeral encrypted workspace
    #[command(visible_alias = "rm")]
    Destroy(DestroyArgs),
    /// Execute a command inside a sandbox (synchronous, streaming NDJSON, or background)
    Exec(ExecArgs),
    /// List tracked background processes inside a sandbox
    Ps(PsArgs),
    /// Fetch or follow stdout/stderr logs for a tracked background process
    Logs(LogsArgs),
    /// Signal or kill & reap a tracked background process inside a sandbox
    Kill(KillArgs),
    /// Attach an interactive PTY shell (or command) inside a sandbox
    Shell(ShellArgs),
    /// Forward a local TCP port to an allowlisted guest port via the daemon UDS tunnel
    Forward(ForwardArgs),
    /// Dynamically allow, close, or list allowlisted guest ingress ports on a running sandbox
    Ingress(IngressArgs),
    /// Bridge a host loopback TCP or Unix socket service into a running sandbox
    Bridge(BridgeArgs),
    /// Upload a local file or directory into a sandbox's /workspace
    Upload(UploadArgs),
    /// Download a file or sanitized .tar.gz archive from a sandbox's /workspace
    Download(DownloadArgs),
    /// View or stream daemon/sandbox audit events
    Audit(AuditArgs),
    /// Reset a running sandbox's idle timeout timer
    Keepalive(KeepaliveArgs),
    /// Build or list immutable erofs + dm-verity rootfs images
    Image(ImageArgs),
    /// Manage offline HPKE-sealed secrets
    Secret(SecretArgs),
    /// List or inspect resolved sandbox profiles
    Profiles(ProfilesArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NetworkModeArg {
    #[value(name = "none")]
    None,
    #[value(name = "loopback")]
    Loopback,
    #[value(name = "egress")]
    Egress,
}

impl From<NetworkModeArg> for NetworkMode {
    fn from(arg: NetworkModeArg) -> Self {
        match arg {
            NetworkModeArg::None => NetworkMode::None,
            NetworkModeArg::Loopback => NetworkMode::Loopback,
            NetworkModeArg::Egress => NetworkMode::Egress,
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct CreateArgs {
    /// Profile name(s) to extend (defaults to built-in `base`)
    #[arg(long = "profile", value_name = "NAME")]
    pub profiles: Vec<String>,

    /// Path to a local sandbox profile TOML (or JSON) file
    #[arg(long, value_name = "FILE")]
    pub file: Option<PathBuf>,

    /// Ephemeral encrypted /workspace size in MiB
    #[arg(long, value_name = "MIB")]
    pub workspace_mib: Option<u32>,

    /// Guest vCPU count
    #[arg(long, value_name = "N")]
    pub vcpus: Option<u32>,

    /// Guest RAM in MiB
    #[arg(long, value_name = "MIB")]
    pub memory_mib: Option<u32>,

    /// Idle timeout in seconds before automatic reaping
    #[arg(long, value_name = "SEC")]
    pub idle_timeout_sec: Option<u64>,

    /// Hard maximum wall-clock lifetime in seconds
    #[arg(long, value_name = "SEC")]
    pub max_wall_time_sec: Option<u64>,

    /// Network isolation mode (`none`, `loopback`, or `egress`)
    #[arg(long, value_enum, value_name = "MODE")]
    pub network: Option<NetworkModeArg>,

    /// Allowlisted guest loopback ingress port (repeatable, e.g. `--port 3000 --port 5173`)
    #[arg(long = "port", value_name = "PORT")]
    pub ports: Vec<u16>,

    /// Host service bridge (`<GUEST_PORT>:<TARGET>` or `<NAME>=<GUEST_PORT>:<TARGET>`, repeatable)
    #[arg(long = "bridge", value_name = "SPEC")]
    pub bridges: Vec<String>,

    /// HPKE-sealed secret (`NAME=seal1_...`, repeatable)
    #[arg(long = "secret", value_name = "NAME=SEALED")]
    pub secrets: Vec<String>,

    /// Allowlisted HTTP egress rule (`METHOD:HOST/PATH[:SECRET]`, repeatable)
    #[arg(long = "allow-http", value_name = "RULE")]
    pub allow_http: Vec<String>,

    /// Additional guest environment variables (`KEY=VAL`, repeatable)
    #[arg(long = "env", value_name = "KEY=VAL")]
    pub env: Vec<String>,
}

#[derive(Debug, Clone, Args)]
pub struct InspectArgs {
    /// Sandbox ID
    pub id: String,
}

#[derive(Debug, Clone, Args)]
pub struct DestroyArgs {
    /// Sandbox ID
    pub id: String,
}

#[derive(Debug, Clone, Args)]
pub struct ExecArgs {
    /// Sandbox ID
    pub id: String,

    /// Working directory inside the sandbox
    #[arg(long, value_name = "DIR")]
    pub cwd: Option<String>,

    /// Per-command execution timeout in seconds
    #[arg(long, value_name = "SEC")]
    pub timeout_sec: Option<u64>,

    /// Additional environment variables (`KEY=VAL`, repeatable)
    #[arg(long = "env", value_name = "KEY=VAL")]
    pub env: Vec<String>,

    /// Stream live stdout/stderr/exit frames via NDJSON
    #[arg(long, conflicts_with = "background")]
    pub stream: bool,

    /// Launch as a tracked background process and print its proc_id
    #[arg(short = 'd', long, visible_alias = "bg", conflicts_with = "stream")]
    pub background: bool,

    /// Command and arguments to run inside the sandbox
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub cmd: Vec<String>,
}

#[derive(Debug, Clone, Args)]
pub struct PsArgs {
    /// Sandbox ID
    pub id: String,
}

#[derive(Debug, Clone, Args)]
pub struct LogsArgs {
    /// Sandbox ID
    pub id: String,

    /// Tracked background process ID
    pub proc_id: String,

    /// Number of trailing log lines/chunks to fetch
    #[arg(long, value_name = "N")]
    pub tail: Option<usize>,

    /// Stream live log output until process exits
    #[arg(long)]
    pub follow: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SignalArg {
    #[value(name = "SIGTERM", alias = "sigterm", alias = "TERM", alias = "term")]
    Sigterm,
    #[value(name = "SIGKILL", alias = "sigkill", alias = "KILL", alias = "kill")]
    Sigkill,
    #[value(name = "SIGINT", alias = "sigint", alias = "INT", alias = "int")]
    Sigint,
}

impl From<SignalArg> for SignalKind {
    fn from(arg: SignalArg) -> Self {
        match arg {
            SignalArg::Sigterm => SignalKind::Sigterm,
            SignalArg::Sigkill => SignalKind::Sigkill,
            SignalArg::Sigint => SignalKind::Sigint,
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct KillArgs {
    /// Sandbox ID
    pub id: String,

    /// Tracked background process ID
    pub proc_id: String,

    /// Send a specific POSIX signal (`SIGTERM`, `SIGKILL`, `SIGINT`) instead of killing & reaping the handle
    #[arg(long, value_enum)]
    pub signal: Option<SignalArg>,
}

#[derive(Debug, Clone, Args)]
pub struct ShellArgs {
    /// Sandbox ID
    pub id: String,

    /// Initial PTY columns (auto-detected from terminal if omitted)
    #[arg(long, value_name = "N")]
    pub cols: Option<u16>,

    /// Initial PTY rows (auto-detected from terminal if omitted)
    #[arg(long, value_name = "N")]
    pub rows: Option<u16>,

    /// Initial working directory inside the sandbox
    #[arg(long, value_name = "DIR")]
    pub cwd: Option<String>,

    /// Optional command to launch inside the PTY (defaults to guest shell)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub cmd: Vec<String>,
}

#[derive(Debug, Clone, Args)]
pub struct ForwardArgs {
    /// Sandbox ID
    pub id: String,

    /// Guest loopback TCP port inside the sandbox (must be allowlisted in [ingress])
    pub guest_port: u16,

    /// Local loopback bind address or port (default: 127.0.0.1:<guest_port>)
    #[arg(long, value_name = "ADDR")]
    pub local: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct IngressArgs {
    /// Sandbox ID (or unique prefix)
    pub id: String,

    /// Guest loopback TCP port to allow for ingress tunneling
    #[arg(value_name = "PORT", conflicts_with_all = ["allow", "close", "list"])]
    pub port: Option<u16>,

    /// Allow a guest loopback TCP port for ingress tunneling
    #[arg(
        short = 'a',
        long = "allow",
        value_name = "PORT",
        conflicts_with_all = ["port", "close", "list"]
    )]
    pub allow: Option<u16>,

    /// Close (remove) an allowlisted guest ingress port
    #[arg(
        short = 'c',
        long = "close",
        visible_alias = "remove",
        value_name = "PORT",
        conflicts_with_all = ["port", "allow", "list"]
    )]
    pub close: Option<u16>,

    /// List allowlisted guest ingress ports on this sandbox
    #[arg(short = 'l', long, conflicts_with_all = ["port", "allow", "close"])]
    pub list: bool,
}

#[derive(Debug, Clone, Args)]
pub struct BridgeArgs {
    /// Sandbox ID (or unique prefix)
    pub id: String,

    /// Bridge specification `<GUEST_PORT>:<TARGET>` (or `<NAME>=<GUEST_PORT>:<TARGET>`)
    /// where `<TARGET>` is `127.0.0.1:<port>`, `[::1]:<port>`, or `unix:///abs/path.sock`
    #[arg(value_name = "SPEC", conflicts_with_all = ["list", "remove"])]
    pub spec: Option<String>,

    /// Optional friendly service name (defaults to `bridge-<guest_port>`)
    #[arg(long, value_name = "NAME", requires = "spec", conflicts_with_all = ["list", "remove"])]
    pub name: Option<String>,

    /// List active host service bridges on this sandbox
    #[arg(short = 'l', long, conflicts_with = "remove")]
    pub list: bool,

    /// Detach an active host service bridge by guest port
    #[arg(short = 'r', long = "remove", visible_alias = "detach", value_name = "GUEST_PORT")]
    pub remove: Option<u16>,
}

#[derive(Debug, Clone, Args)]
pub struct UploadArgs {
    /// Sandbox ID
    pub id: String,

    /// Local host file or directory to upload
    pub local_path: PathBuf,

    /// Destination path inside the sandbox (must be under /workspace)
    pub remote_path: String,

    /// Skip common secret files (.env*, .git/config, *.key, *.pem, id_rsa*, etc.) and heavy build dirs
    #[arg(long)]
    pub exclude_secrets: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DownloadFormatArg {
    #[value(name = "raw")]
    Raw,
    #[value(name = "tar.gz", alias = "targz")]
    TarGz,
}

impl From<DownloadFormatArg> for DownloadFormat {
    fn from(arg: DownloadFormatArg) -> Self {
        match arg {
            DownloadFormatArg::Raw => DownloadFormat::Raw,
            DownloadFormatArg::TarGz => DownloadFormat::TarGz,
        }
    }
}

impl DownloadFormatArg {
    pub fn as_query_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::TarGz => "tar.gz",
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct DownloadArgs {
    /// Sandbox ID
    pub id: String,

    /// Remote path inside /workspace to download
    pub remote_path: String,

    /// Write raw file or canonical .tar.gz output to this host path (defaults to stdout)
    #[arg(short = 'o', long = "output", value_name = "PATH", conflicts_with = "unpack_dir")]
    pub output: Option<PathBuf>,

    /// Download format (`raw` for a single file, `tar.gz` for a directory or archive)
    #[arg(long, value_enum)]
    pub format: Option<DownloadFormatArg>,

    /// Safely unpack downloaded archive into this host directory via blackwall-unpacker (enforcing deny_touch_globs)
    #[arg(long, value_name = "DIR", conflicts_with = "output")]
    pub unpack_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct AuditArgs {
    /// Optional sandbox ID (or unique prefix) to filter audit events
    pub id: Option<String>,

    /// Maximum number of recent audit events to fetch
    #[arg(long, default_value_t = 100, value_name = "N")]
    pub limit: usize,

    /// Stream live audit events as NDJSON
    #[arg(short = 'f', long)]
    pub follow: bool,
}

#[derive(Debug, Clone, Args)]
pub struct KeepaliveArgs {
    /// Sandbox ID (or unique prefix)
    pub id: String,
}

#[derive(Debug, Clone, Args)]
pub struct ImageArgs {
    #[command(subcommand)]
    pub command: ImageCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ImageCommand {
    /// Build an immutable erofs + dm-verity rootfs image from an OCI ref or profile TOML
    Build(ImageBuildArgs),
    /// List locally built erofs + dm-verity images
    List(ImageListArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ImageBuildArgs {
    /// OCI image reference (e.g. `ghcr.io/org/rust-dev:latest`) or path to a profile `.toml`
    pub target: String,

    /// Optional display tag label for the built image
    #[arg(long, value_name = "NAME")]
    pub tag: Option<String>,

    /// Override local image cache directory
    #[arg(long, value_name = "DIR")]
    pub cache_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct ImageListArgs {
    /// Read directly from local image cache directory instead of querying blackwall-daemon
    #[arg(long)]
    pub local: bool,

    /// Override local image cache directory when `--local` is set
    #[arg(long, value_name = "DIR")]
    pub cache_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct SecretArgs {
    #[command(subcommand)]
    pub command: SecretCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum SecretCommand {
    /// Seal a secret offline into a `seal1_...` HPKE ciphertext (reads plaintext from --value-env or stdin, never argv)
    Seal(SecretSealArgs),
}

#[derive(Debug, Clone, Args)]
pub struct SecretSealArgs {
    /// Logical secret name in profile TOML (e.g. `GITHUB_TOKEN`)
    #[arg(long, value_name = "NAME")]
    pub name: String,

    /// Allowed destination hostnames (comma-separated or repeatable)
    #[arg(long = "hosts", value_delimiter = ',', value_name = "HOST")]
    pub hosts: Vec<String>,

    /// Allowed HTTP path templates (comma-separated or repeatable; defaults to `/*`)
    #[arg(long = "paths", value_delimiter = ',', value_name = "PATH")]
    pub paths: Vec<String>,

    /// Policy tag bound into HPKE AEAD AAD
    #[arg(long, default_value = "", value_name = "TAG")]
    pub policy_tag: String,

    /// Optional expiration TTL in seconds from now
    #[arg(long, value_name = "SEC")]
    pub exp_sec: Option<u64>,

    /// Path to the host X25519 HPKE key file (defaults to `$XDG_CONFIG_HOME/blackwall/host.key`)
    #[arg(long, value_name = "PATH")]
    pub key_path: Option<PathBuf>,

    /// Name of the environment variable containing the secret plaintext (if omitted, reads from stdin)
    #[arg(long, value_name = "ENV_VAR")]
    pub value_env: Option<String>,

    /// Optional placeholder prefix for the generated TOML snippet
    #[arg(long, value_name = "PREFIX")]
    pub placeholder_prefix: Option<String>,

    /// Print only the bare `seal1_...` ciphertext followed by a newline
    #[arg(long)]
    pub raw: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ProfilesArgs {
    #[command(subcommand)]
    pub command: Option<ProfilesCommand>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ProfilesCommand {
    /// List available profiles
    List,
    /// Inspect a resolved profile (secrets redacted)
    Show {
        /// Profile name
        name: String,
    },
}

/// Resolve the daemon Unix domain socket path with precedence:
/// 1. Explicit `--socket <path>`
/// 2. `$BLACKWALL_SOCKET`
/// 3. `$XDG_RUNTIME_DIR/blackwall.sock`
/// 4. `<temp_dir>/blackwall.sock`
pub fn resolve_socket_path(cli_socket: Option<&Path>) -> PathBuf {
    if let Some(p) = cli_socket {
        return p.to_path_buf();
    }
    if let Some(env_sock) = std::env::var_os("BLACKWALL_SOCKET") {
        if !env_sock.is_empty() {
            return PathBuf::from(env_sock);
        }
    }
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("blackwall.sock");
        }
    }
    std::env::temp_dir().join("blackwall.sock")
}
