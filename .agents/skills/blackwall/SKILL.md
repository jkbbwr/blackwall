---
name: blackwall
description: Create, drive, inspect, and tear down rootless KVM microVM sandboxes with the `blackwall` CLI (or local daemon API). Load when running untrusted code, builds, tests, dev servers, or isolated workflows inside a Blackwall sandbox, mixing language/GitHub profiles, uploading/downloading workspace files, bridging local host services, brokering HPKE-sealed secrets, or diagnosing proxy/egress audit blocks.
---

# Blackwall Sandboxes

`blackwall` drives rootless Linux KVM (`cloud-hypervisor`) microVMs managed by `blackwall-daemon` over a local `0600` Unix domain socket (`$BLACKWALL_SOCKET` or `$XDG_RUNTIME_DIR/blackwall.sock`).

Every sandbox has:
- **Immutable rootfs (`/`):** read-only `EROFS + dm-verity`. System package installs (`apt-get install`) fail with `Read-only file system`.
- **Ephemeral encrypted workspace (`/workspace`):** writable `dm-crypt` `ext4` disk wiped immediately when the sandbox exits or is destroyed.
- **Fail-closed networking:** defaults to `loopback` (offline; `127.0.0.1` only). `none` boots a `CONFIG_INET=n` kernel. `egress` routes only allowlisted HTTPS hosts/methods/paths through a jailed per-VM `blackwall-proxy`.

## Rules for an agent

- **Prefer `--json`** on every `blackwall` command whose output you parse (`create`, `ls`, `inspect`, `exec`, `ps`, `ingress`, `bridge`, `profiles`, `audit`).
- **Use `exec`, never `shell`.** `blackwall shell` attaches an interactive TTY meant for humans. Use `blackwall exec` for synchronous commands, `exec --stream` for live NDJSON output, and `exec -d` for long-running servers/daemons.
- **Write only inside `/workspace` (or `/tmp`).** Never try to mutate `/usr`, `/etc`, or run `apt-get` inside a running VM. If a toolchain is missing, recreate the sandbox with the right `--profile` mixin(s) instead of trying to install OS packages at runtime.
- **Upload with `--exclude-secrets`** when copying a host repo into a sandbox (`blackwall upload --exclude-secrets <id> . /workspace/repo`) so `.env*`, private keys, and `.git/config` credentials stay off the VM.
- **Never ask for, echo, or pass plaintext secrets on the command line.** Blackwall only accepts offline HPKE-sealed `seal1_...` ciphertexts (`--secret NAME=seal1_...`). Inside the guest, env vars hold random `bw_*` placeholders — never treat them as real credentials or try to exfiltrate them.
- **Respect `deny_touch_globs` on export.** `blackwall download --unpack-dir` filters exports through `blackwall-unpacker`, which rejects symlinks, hardlinks, setuid, path traversal, and protected files (`.git/**`, `.env*`, shell rc files, `Makefile`, `justfile`, `.vscode/**`).
- **Keep sandboxes alive during long pauses, and destroy them when done.** Sandboxes auto-reap on `idle_timeout_sec` and `max_wall_time_sec`. Call `blackwall keepalive <id>` before long reasoning steps, and `blackwall rm <id>` as soon as you finish.
- **When a network call fails (`NXDOMAIN`, `403`, or connection refused), inspect `blackwall audit <id>` immediately** instead of retrying blindly — the audit log tells you the exact rule, host, method, or path that was denied.

## Prerequisites & Identifiers

Check that the daemon is reachable and see installed profiles:

```bash
blackwall --json ls
blackwall --json profiles list
```

If `blackwall` is not on `$PATH` inside a source checkout, use `./target/release/blackwall` (or `./target/debug/blackwall`). Start the daemon with `just daemon-release` (or `just daemon`).

- **Sandbox IDs** have the form `bw-<12-hex>` (e.g. `bw-fed6f0f2a47c`). Every command accepts any unique ID prefix (e.g. `fed6` or `bw-fed6`).
- **Socket override:** pass `--socket /path/to/blackwall.sock` or set `BLACKWALL_SOCKET`.

## Profiles & Mixins

Built-in profiles live in `profiles/` and can be **composed by repeating `--profile`** (left-to-right; packages, install commands, egress rules, ingress ports, and env vars merge cleanly without `PATH` collisions):

| Profile | Stack / Purpose | Default Network |
|---|---|---|
| `base` | Minimal Debian + default `/workspace` (`2048 MiB`) + CA env | `loopback` (offline) |
| `ts-dev` | Node.js LTS, npm, pnpm, bun, TypeScript | `egress` (npm / Node registries) |
| `py-dev` | Python 3, `uv`, `ruff`, `pytest` | `egress` (PyPI / Astral) |
| `rust-dev` | `rustup` stable, `cargo`, `clippy`, `rustfmt`, `sccache` | `egress` (crates.io) |
| `go-dev` | Go toolchain, `gopls`, `staticcheck` | `egress` (proxy.golang.org) |
| `cpp-dev` | `clang`, `lld`, `cmake`, `ninja`, `gdb`, `pkg-config` | inherits `loopback` (or mixed profile's network) |
| `github` | `git`, `gh` CLI + HTTPS egress for `github.com`, `api.github.com`, `uploads.github.com`, `objects.githubusercontent.com` | `egress` |

Examples:

```bash
# Single offline C++ sandbox
blackwall --json create --profile cpp-dev

# Polyglot TypeScript + Go + GitHub CLI sandbox
blackwall --json create --profile ts-dev --profile go-dev --profile github

# Force a language profile offline (strips inherited egress rules)
blackwall --json create --profile py-dev --network loopback

# Inspect merged profile details (secrets redacted)
blackwall --json profiles show ts-dev
```

> **Note:** `github` uses HTTPS (not SSH port 22) so `blackwall-proxy` can inspect paths, inject sealed tokens from `memfd_secret`, and audit every request. First creation for a new profile combination builds and caches its `EROFS + dm-verity` rootfs image automatically (subsequent boots reuse the cached content hash).

## Core Workflow

### 1. Create & inspect a sandbox

```bash
ID=$(blackwall --json create \
  --profile ts-dev \
  --workspace-mib 4096 \
  --vcpus 2 \
  --memory-mib 2048 \
  --idle-timeout-sec 900 \
  | jq -r '.sandbox_id')

blackwall --json inspect "$ID"
```

### 2. Upload code into `/workspace`

```bash
blackwall upload --exclude-secrets "$ID" ./my-repo /workspace/repo
```

Destinations must be inside `/workspace`.

### 3. Run commands (`exec`)

```bash
# Synchronous command (returns exit_code, stdout, stderr)
blackwall --json exec "$ID" --cwd /workspace/repo --timeout-sec 120 -- npm test

# Live streaming output (NDJSON frames when --json is set)
blackwall exec "$ID" --cwd /workspace/repo --stream -- npm run build

# Pass per-command environment variables
blackwall exec "$ID" --cwd /workspace/repo --env CI=1 -- pytest -q
```

Always separate `blackwall exec` flags from the guest command with `--`.

### 4. Background processes (`exec -d`, `ps`, `logs`, `kill`)

Use `-d` / `--background` for dev servers, watchers, or long-running daemons so `exec` does not block:

```bash
PROC=$(blackwall --json exec -d "$ID" --cwd /workspace/repo -- npm run dev -- --host 127.0.0.1 --port 3000 \
  | jq -r '.proc_id')

blackwall --json ps "$ID"
blackwall logs "$ID" "$PROC" --tail 50
blackwall logs "$ID" "$PROC" --follow
blackwall kill "$ID" "$PROC" --signal SIGTERM   # or omit --signal to kill & reap
```

### 5. Download artifacts back to the host

```bash
# Single file
blackwall download "$ID" /workspace/repo/dist/bundle.js --format raw -o ./bundle.js

# Directory as sanitized .tar.gz
blackwall download "$ID" /workspace/repo/dist --format tar.gz -o ./dist.tar.gz

# Directory unpacked directly via blackwall-unpacker (enforces deny_touch_globs)
blackwall download "$ID" /workspace/repo/src --unpack-dir ./out-src
```

### 6. Keepalive & cleanup

```bash
blackwall keepalive "$ID"
blackwall rm "$ID"
```

## Network Modes, Ingress & Host Bridges

### Egress allowlisting

Add ad-hoc HTTPS egress rules at creation time with `--allow-http` (`METHOD[,METHOD...]:HOST[:PORT][/PATH][:SECRET]`):

```bash
blackwall --json create --profile py-dev \
  --allow-http "GET:api.example.com/v1/*" \
  --allow-http "POST:httpbin.org/anything"
```

In `egress` mode, `blackwall-proxy` enforces DNS allowlisting, blocks all RFC1918/loopback/link-local/host IPs (`pasta --no-map-gw` + locked `nftables`), and MITMs TLS using the sandbox's per-VM CA (already wired into `SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS`).

### Host-to-guest ingress (accessing a guest server)

Guest services should bind to `127.0.0.1:<port>`. Allowlist ports at creation (`--port 3000`) or dynamically on a running sandbox (unless the profile sets `policy.locked = true`, which only permits closing ports):

```bash
blackwall ingress "$ID" --allow 3000
blackwall ingress "$ID" --list
blackwall forward "$ID" 3000 --local 127.0.0.1:3000   # tunnels host -> guest:3000
blackwall ingress "$ID" --close 3000
```

HTTP previews for allowlisted ports are also served on the isolated preview origin (`http://127.0.0.1:7701/v1/sandboxes/<id>/proxy/<port>/`).

### Guest-to-host service bridges (Postgres, Redis, Ollama, Unix sockets)

Because `pasta` intentionally blocks host/LAN IPs, use `blackwall bridge` to expose a **single explicit** host loopback TCP port or Unix socket into the sandbox over `AF_VSOCK` Port 1002. Bridges work even in offline `loopback` mode (no internet egress required):

```bash
# Attach at creation time
blackwall --json create --profile py-dev --network loopback \
  --bridge "ollama=11434:127.0.0.1:11434"

# Or attach / list / detach dynamically on a running sandbox
blackwall bridge "$ID" 5432:127.0.0.1:5432 --name local-pg
blackwall bridge "$ID" 2375:unix:///run/user/1000/podman/podman.sock --name podman
blackwall --json bridge "$ID" --list
blackwall bridge "$ID" --remove 5432
```

Inside the sandbox, connect to `127.0.0.1:<guest_port>` (e.g. `127.0.0.1:5432`). Daemon control ports (`:7700`, `:7701`, and the daemon UDS) are unconditionally forbidden as bridge targets.

## Brokered Secrets (HPKE `seal1_`)

When a sandbox needs an authenticated API call (e.g. GitHub, OpenAI, private registry) without exposing the credential to guest code:

1. **Human/host seals the secret offline** (plaintext read from `--value-env` or `stdin`, never argv):
   ```bash
   SEALED=$(blackwall secret seal --raw \
     --name GITHUB_TOKEN \
     --value-env GH_PAT \
     --hosts api.github.com,github.com \
     --paths / \
     --exp-sec 7200)
   ```
2. **Create the sandbox with the sealed blob bound to an HTTP egress rule:**
   ```bash
   blackwall --json create --profile ts-dev \
     --secret "GITHUB_TOKEN=$SEALED" \
     --allow-http "GET,POST,PUT,PATCH:api.github.com/:GITHUB_TOKEN" \
     --allow-http "GET,HEAD,POST:github.com/:GITHUB_TOKEN"
   ```
3. **Inside the sandbox**, use `$GITHUB_TOKEN` normally (e.g. `Authorization: Bearer $GITHUB_TOKEN` or `gh` CLI). The guest only sees a 256-bit `bw_*` placeholder; `blackwall-proxy` swaps in the real secret from `memfd_secret` on outbound requests matching `(hosts, paths, exp)` and blocks with `403 auth_mismatch` if the placeholder is sent anywhere else.

> **Important:** Do not combine `--profile github` with a second `--allow-http` rule on the same host/path if you want strict secret binding — `--profile github` already includes an unauthenticated `api.github.com` rule. Extend your language profile directly or define a local profile TOML (`--file`).

## Debugging & Audit Logs

Every sandbox lifecycle event, exec, DNS query, HTTP proxy decision, secret injection/mismatch, ingress open/close, and host bridge connection is recorded in the daemon audit ring:

```bash
# Recent events for one sandbox
blackwall audit "$ID" --limit 50

# Live JSON event stream
blackwall --json audit "$ID" --follow
```

Common failure diagnostics:
- **`NXDOMAIN` inside guest:** Host is not in `network.http` allowlist (or sandbox is in `loopback`/`none` mode). Check `blackwall audit "$ID"` for `dns_query` `deny`.
- **`HTTP 403` from proxy:** Host is allowed, but the HTTP method or path prefix is not, or a secret placeholder was sent to an unbound host/path (`auth_mismatch`). Check `http_request` / `auth_mismatch` in `blackwall audit "$ID"`.
- **Cannot reach `127.0.0.1` host service:** Host IPs are blocked by design in `egress` mode. Attach a `blackwall bridge` instead.
- **`Read-only file system`:** Command tried to write outside `/workspace`, `/tmp`, or `/home/sandbox`.
- **`403` on dynamic `ingress`/`bridge` or `profiles`:** Daemon is running with operator lockdown flags (`--readonly-profiles`, `--require-locked-profiles`, `--policy-ceiling`, or `policy.locked = true` on the profile).

## Direct UDS / HTTP API (for programmatic agents)

The CLI covers almost every workflow. If you call `blackwall-daemon` directly:
- **Prefer the UDS socket** (`$XDG_RUNTIME_DIR/blackwall.sock`) via `curl --unix-socket`: no bearer token required (`0600` host user socket).
- **Over HTTP (`127.0.0.1:7700`)**, send `Authorization: Bearer $(cat "$XDG_RUNTIME_DIR/blackwall-http.token")` with a loopback `Host` header. Previews live separately on `127.0.0.1:7701`.
- **Agent-friendly endpoints with no CLI subcommand:**
  - `GET /v1/sandboxes/{id}/fs?path=/workspace` — structured JSON directory listing (avoids `exec_command` audit noise).
  - `GET /v1/sandboxes/{id}/ports` — live list of listening TCP ports inside the guest.
  - `POST /v1/profiles` / `DELETE /v1/profiles/{name}` — manage custom profiles (unless `--readonly-profiles`).
  - `DELETE /v1/images/{content_hash}` — prune unused rootfs images.
