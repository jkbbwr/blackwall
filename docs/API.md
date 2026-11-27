# Blackwall — Sandbox Definition & Interactive API Specification

> **Design Goal:** A minimal, composable, fail-closed specification for launching and driving interactive LLM sandboxes over a `0600` local Unix domain socket, backed by identical schemas in `blackwall-core` (Rust SDK) and `blackwall` (CLI).

---

## 1. Composable Sandbox Definition (`SandboxSpec` / Profiles)

Every sandbox resolves to a single self-contained `SandboxSpec` (expressible identically in TOML or JSON). Profiles compose left-to-right via `extends = [...]` on top of a built-in **`base`** profile so callers only specify what differs.

### 1.1 Built-In `base` Defaults (Fail-Closed)
Every profile implicitly inherits `base` unless explicitly overridden:
- **Image:** `base = "debian:bookworm-slim"` (glibc default for broad compatibility with prebuilt binaries, Python wheels, Node, Rust, and Postgres; any OCI image ref is supported). Root filesystem `/` (`vda`) is **strictly immutable** (`erofs + dm-verity`); system packages are installed declaratively at image build time via `[image]` (`packages` / `run`, built via Docker/Podman and cached by content hash), while runtime user-mode installs (`uv`/venv, `cargo`, `npm`, `go`, `mise`/`pixi`, `~/.local/bin`) run unprivileged inside `/workspace` / `$HOME`.
- **Compute:** `vcpus = 2`, `memory_mib = 2048`, `workspace_mib = 1024` (1 GiB encrypted ephemeral `vdb` at `/workspace`)
- **Session Lifecycle:** `idle_timeout_sec = 600` (10m), `max_wall_time_sec = 3600` (1h)
- **Network:** `mode = "loopback"` (`vmlinux-lo` native `127.0.0.1` for local tests/DBs, **zero egress**, no proxy/`pasta` spawned) with `http = []`, `postgres = []`. Other modes: `"none"` (`vmlinux-noinet`, `CONFIG_INET=n`) and `"egress"` (`vmlinux-lo` + `tun0`/`smoltcp` + per-VM Pingora proxy). Allowed DNS hostnames are **derived automatically** from declared `[[network.http]]` and `[[network.postgres]]` rules.
- **Export (`blackwall-unpacker`):** `max_bytes = 52428800` (50 MiB), `max_files = 10000`, default protected-path `deny_touch_globs` enabled when unpacking onto host disk

### 1.2 Composition & Merge Rules (`extends = [...]`)
Profiles stored on disk (e.g. `~/.config/blackwall/profiles/*.toml`) or passed inline compose deterministically:
1. **Left-to-right resolution** with cycle detection (`base` is always the root).
2. **Scalar fields** (`image.ref` / `image.base`, `compute.*`, `network.mode`, `export.max_*`): later profile overrides earlier profile.
3. **Additive lists & maps** (`image.packages`, `image.run`, `http`, `postgres`, `secrets`, `env`, `deny_touch_globs`): merged by concatenation/union. Conflicting `http` rules on the same `(host, path_prefixes)` or duplicate `secrets` keys with different values fail validation explicitly rather than silently shadowing.
4. **Content-addressed image caching:** If a resolved profile specifies `image.packages` or `image.run`, `blackwall-oci` generates a deterministic `Dockerfile`, builds it via `docker build` / `podman build` (build-time only; zero Docker at VM runtime), strips setuid/caps, packs `erofs + dm-verity`, and caches `vda` by content hash of `(base, packages, run)`. If only `image.ref` is given, it converts that pre-built OCI/Docker image directly.
5. **Ceiling / narrow-only lock (`[policy] locked = true`):** When a base/org profile sets `locked = true` (or explicit `max_vcpus`, `max_memory_mib`, `max_workspace_mib`, `max_wall_time_sec`), downstream runtime overrides on `POST /v1/sandboxes` may only **narrow** (lower compute/TTL/export caps, remove hosts/methods/prefixes, add `deny_touch_globs`) — never widen.

### 1.3 Example Composed Profiles

```toml
# ~/.config/blackwall/profiles/rust-dev.toml
version = 1
name = "rust-dev"
extends = ["base"]

[image]
base = "debian:bookworm-slim"
packages = ["ca-certificates", "git", "curl", "ripgrep", "jq", "build-essential", "pkg-config", "libssl-dev"]
run = [
  "curl -LsSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable",
]

[compute]
vcpus = 4
memory_mib = 4096
workspace_mib = 4096

[network]
mode = "egress"

[[network.http]]
host = "crates.io"
methods = ["GET", "HEAD"]
path_prefixes = ["/api/v1/crates"]

[[network.http]]
host = "static.crates.io"
methods = ["GET", "HEAD"]
path_prefixes = ["/crates/"]

[[network.http]]
host = "index.crates.io"
methods = ["GET", "HEAD"]
path_prefixes = ["/"]

[env]
RUST_BACKTRACE = "1"
```

```toml
# ~/.config/blackwall/profiles/my-repo-agent.toml
version = 1
name = "my-repo-agent"
extends = ["rust-dev"]

[image]
packages = ["postgresql-client"]         # Appended to rust-dev's packages & cached by content hash

[[network.http]]
host = "api.github.com"
methods = ["GET", "POST", "PUT", "PATCH"]
path_prefixes = ["/repos/my-org/my-repo/"]
max_request_bytes = 4194304
auth = { secret = "GITHUB_TOKEN", kind = "bearer" }

[[network.http]]
host = "github.com"
methods = ["GET", "POST"]
path_prefixes = ["/my-org/my-repo.git/"]
auth = { secret = "GITHUB_TOKEN", kind = "basic", username = "x-access-token" }

[[network.postgres]]
host = "db.internal"
port = 5432
secret = "PGPASSWORD"
require_upstream_tls = true

[secrets.GITHUB_TOKEN]
placeholder_prefix = "ghp_bw00"
sealed = "seal1_Z2l0aHViX3NlYWxlZF90b2tlbl9ibG9i..."

[secrets.PGPASSWORD]
placeholder_prefix = "bwpg_"
sealed = "seal1_cG9zdGdyZXNfc2VhbGVkX3Bhc3N3b3JkX2Jsb2I..."
```

> **Auth Invariant:** Omitting `auth` on an `[[network.http]]` rule means unauthenticated access (guest auth headers are not required and not injected). Specifying `auth` (`kind = "bearer"` | `kind = "header", name = "x-api-key"` | `kind = "basic", username = "..."`) **always** enforces mandatory auth stripping & identity pinning (`force_brokered`) — guest-supplied third-party credentials are stripped and replaced with the brokered secret.

### 1.4 Secret Supply Modes
Each `[secrets.<NAME>]` entry provides **exactly one** source:
1. **`sealed = "seal1_..."`** (mandatory for checked-in TOML files): HPKE X25519 ciphertext bound to `(allow_hosts, allow_path_templates, policy_tag, exp)`, opened exclusively inside the per-VM `blackwall-proxy` (`memfd_secret`).
2. **`ephemeral = "..."`** (API-only over the `0600` local Unix socket): Allows programmatic LLM harnesses that already pull secrets from Vault / env to pass a short-lived secret on `POST /v1/sandboxes`. `blackwall-daemon` forwards it straight into the per-VM `blackwall-proxy`'s `memfd_secret` memory, zeroizes its own copy immediately, and **never logs or persists it to disk**.

In both cases, the guest receives only a freshly minted 256-bit random SDK-shaped placeholder (`<placeholder_prefix><random>`).

---

## 2. Interactive Daemon API (`blackwall-daemon`)

`blackwall-daemon` runs **100% rootless** and listens on a `0600` Unix domain socket (default `$XDG_RUNTIME_DIR/blackwall.sock`, e.g. `/run/user/1000/blackwall.sock`), speaking **HTTP/1.1 + JSON + raw binary / NDJSON / WebSocket** streams.

### 2.1 Sandbox Lifecycle

| Method & Path | Request | Response |
| :--- | :--- | :--- |
| `POST /v1/sandboxes` | `SandboxSpec` JSON (may include `"extends": ["..."]` + overrides) | `201 Created` — `{ id, state, image_roothash, created_at, expires_at, idle_deadline_at }` |
| `GET /v1/sandboxes` | — | `200 OK` — list of active sandboxes |
| `GET /v1/sandboxes/{id}` | — | `200 OK` — full sandbox status, resource caps, active background processes, idle/wall timers |
| `DELETE /v1/sandboxes/{id}` | — | `204 No Content` — shuts down VM, closes unlinked encrypted `vdb`, terminates per-VM proxy, `pasta`, and `unpacker` |

Any API call targeting `{id}` refreshes `idle_deadline_at` (bounded by `max_wall_time_sec`).

### 2.2 Command Execution & Background Processes

| Method & Path | Request | Response |
| :--- | :--- | :--- |
| `POST /v1/sandboxes/{id}/exec` | `{ cmd: string[], cwd?: string, env?: map, stdin?: string, timeout_sec?: u64, background?: bool }` | • Default (sync): `200 OK` `{ exit_code, stdout, stderr, timed_out, duration_ms }`<br/>• `?stream=true`: `200 OK` (`application/x-ndjson`) streaming `stdout`, `stderr`, and final `exit` frames<br/>• `background: true`: `202 Accepted` `{ proc_id, pid }` |
| `GET /v1/sandboxes/{id}/processes` | — | `200 OK` — list of tracked background processes (`proc_id`, `cmd`, `state`, `exit_code`) |
| `GET /v1/sandboxes/{id}/processes/{proc_id}/logs` | `?follow=true&tail=200` | `200 OK` — buffered or streaming NDJSON `stdout`/`stderr` ring buffer |
| `POST /v1/sandboxes/{id}/processes/{proc_id}/signal` | `{ signal: "SIGTERM" \| "SIGKILL" \| "SIGINT" }` | `204 No Content` |
| `DELETE /v1/sandboxes/{id}/processes/{proc_id}` | — | `204 No Content` — kills process group and reaps handle |

### 2.3 Interactive PTY (Shell / In-VM Agent)

| Method & Path | Protocol | Behavior |
| :--- | :--- | :--- |
| `GET /v1/sandboxes/{id}/pty?cols=120&rows=40` | HTTP `Upgrade: websocket` | Attaches a PTY inside the VM (default shell or optional `cmd` query param). Binary frames carry raw stdin/stdout; text JSON frames carry `{ "type": "resize", "cols": N, "rows": M }` and `{ "type": "exit", "code": N }`. |

### 2.4 File I/O (Single Clean Ingress / Egress Surface)

| Method & Path | Request / Query | Behavior |
| :--- | :--- | :--- |
| `PUT /v1/sandboxes/{id}/files?path=/workspace/...` | `Content-Type: application/octet-stream` (single file) or `application/x-tar` / `application/gzip` (extract into `path`) | Streams bytes over `Port 1002` directly into encrypted `/workspace` (`vdb`). Rejects paths outside `/workspace` and enforces `vdb` free-space bounds. |
| `GET /v1/sandboxes/{id}/files?path=/workspace/...&format=raw\|tar.gz` | `format=raw` (single file) or `format=tar.gz` (directory or file set) | Streams out of `/workspace` over `Port 1002` through jailed **`blackwall-unpacker`**, which enforces `export.max_bytes` / `export.max_files`, strips symlinks/hardlinks/devices/setuid/`..`, and returns a clean raw stream or canonically re-packed `.tar.gz`. |

*(Optional future extension without breaking this API: `[[volumes]]` in `SandboxSpec` for attaching pre-built read-only `.erofs` datasets at `/mnt/...`.)*

### 2.5 Profiles & Images

| Method & Path | Purpose |
| :--- | :--- |
| `GET /v1/profiles` / `GET /v1/profiles/{name}` | List or inspect resolved composed profiles (secrets redacted) |
| `GET /v1/images` | List locally built `erofs + dm-verity` base images and roothashes |

---

## 3. CLI (`blackwall`) & Rust SDK (`blackwall-core`) Ergonomics

`blackwall-core` wraps the daemon API (and can also run embedded in-process without a persistent daemon). The CLI mirrors the exact same verbs:

```bash
# Build a base rootfs image once (OCI -> erofs + dm-verity vda)
blackwall image build ghcr.io/org/rust-dev:latest --tag blackwall/rust-dev:latest

# Seal a secret offline for checked-in profile TOML
blackwall secret seal --name GITHUB_TOKEN --hosts api.github.com,github.com

# Create an interactive sandbox from composed profiles
SB=$(blackwall create --profile my-repo-agent --workspace-mib 4096)

# Upload files (optional client-side filter skips .env / target / .git/config)
blackwall upload "$SB" ./my-project /workspace --exclude-secrets

# Run synchronous commands or background servers
blackwall exec "$SB" -- cargo test
PROC=$(blackwall exec "$SB" --background -- cargo run --bin server)
blackwall logs "$SB" "$PROC" --follow

# Attach interactive PTY (human shell or in-VM coding agent)
blackwall shell "$SB"

# Extract a file or sanitized .tar.gz (or unpack to host dir with deny_touch_globs check)
blackwall download "$SB" /workspace/dist/out.tar.gz -o ./out.tar.gz
blackwall download "$SB" /workspace --format tar.gz -o ./result.tar.gz

# Destroy sandbox (wipes unlinked encrypted vdb immediately)
blackwall destroy "$SB"
```
