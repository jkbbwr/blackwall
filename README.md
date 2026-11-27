# Blackwall

A 100% rootless Linux KVM microVM sandbox for running untrusted code and AI agents with hardware isolation, immutable `EROFS + dm-verity` root filesystems, ephemeral encrypted `dm-crypt` workspaces, per-VM jailed egress proxies with zero-trust HPKE secret injection, and a live SolidJS control-plane dashboard.

## Security Architecture

- **Zero root / zero sudo:** Every component runs as an unprivileged host user (`/dev/kvm` rw only).
- **Hardware KVM boundary (`cloud-hypervisor`):** Each sandbox runs inside its own `userns`, empty `netns`, `pivot_root`, Landlock, `seccomp-bpf`, `CapEff=0`, `NoNewPrivs=1`, `PR_SET_DUMPABLE=0`. No `virtio-net` NIC and no `virtio-fs` — only `AF_VSOCK` (Ports 1000/1001/1002).
- **Hardened Linux 6.12 guest kernels:** `vmlinux-lo` and `vmlinux-noinet` (`CONFIG_INET=n`) with `CONFIG_IO_URING=n`, `CONFIG_USER_NS=n`, `CONFIG_MODULES=n`, `CONFIG_BPF_SYSCALL=n`, `CONFIG_XFRM=n`, `CONFIG_KEXEC=n`.
- **Two-disk storage model:**
  - `vda`: Read-only content-addressed `EROFS + dm-verity` rootfs (`setuid` & file capabilities stripped).
  - `vdb`: Ephemeral `dm-crypt` `ext4` mounted at `/workspace` (random in-RAM key discarded on VM exit).
- **Three fail-closed network modes:** `none` (`CONFIG_INET=n`), `loopback` (default; `127.0.0.1` only), and `egress` (dedicated per-VM `pasta --no-map-gw` + locked `nftables` pinned to public IPs + jailed `blackwall-proxy` with Pingora `rustls` SNI MITM & Postgres `SCRAM-SHA-256` brokering).
- **Zero-trust secret brokering:** On-disk profiles require offline HPKE X25519 `seal1_...` ciphertexts bound to `(hosts, paths, exp)`. Guests only ever see 256-bit random placeholders; `blackwall-proxy` swaps them from `memfd_secret` memory on egress and rejects `auth_mismatch`.
- **Decoupled Host Service Bridges (`host_services` / `blackwall bridge`):** Explicitly bridge a sandbox (including offline `loopback` VMs) to a single local `unix://` socket or loopback TCP port over `AF_VSOCK` Port 1002 without weakening `pasta`'s public-IP-only boundary.
- **Sanitized file exports (`blackwall-unpacker`):** Ephemeral Landlock+seccomp child re-packs canonical `.tar.gz`, rejecting zip-bombs, symlinks, hardlinks, devices, setuid, traversal, and Unicode-normalized `deny_touch_globs`.
- **Isolated HTTP dashboard & preview origins:** Loopback control plane (`:7700`) enforces per-boot token auth (`HttpOnly; SameSite=Strict` cookie / Bearer), strict `Host` (DNS-rebinding) & `Origin`/`Sec-Fetch-Site` checks, while guest HTTP previews run on an isolated origin (`:7701`) with zero control routes.

## Quickstart

```bash
# 1. Verify host toolchain & build full release stack (musl guest, hardened kernels, host binaries, UI)
just check-deps
just build-release

# 2. Start blackwall-daemon (prints authenticated dashboard URL on startup)
just daemon-release

# 3. Launch a sandbox from built-in or mixed language profiles (ts-dev, py-dev, rust-dev, go-dev, cpp-dev)
./target/release/blackwall create --profile ts-dev
./target/release/blackwall create --profile ts-dev --profile go-dev

# 4. Run commands, attach PTY, inspect live proxy/DNS/bridge audit logs
./target/release/blackwall exec <id-prefix> -- uname -a
./target/release/blackwall shell <id-prefix>
./target/release/blackwall audit <id-prefix> --follow

# 5. Seal an API key offline & attach it to an egress rule (guest never sees the real key)
SEALED=$(printf '%s' "$MY_API_KEY" | ./target/release/blackwall secret seal --raw \
  --name API_KEY --hosts httpbin.org --paths /anything --exp-sec 7200)
./target/release/blackwall create --profile ts-dev \
  --secret "API_KEY=$SEALED" \
  --allow-http "POST:httpbin.org/anything:API_KEY"

# 6. Dynamic host-to-guest ingress & guest-to-host local service bridges
./target/release/blackwall ingress <id-prefix> --allow 3000
./target/release/blackwall forward <id-prefix> 3000
./target/release/blackwall bridge <id-prefix> 5435:127.0.0.1:5435 --name local-pg
```

## Documentation

- [Agent Skill (`SKILL.md`)](.agents/skills/blackwall/SKILL.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [API Reference](docs/API.md)
- [Kernel Hardening](docs/KERNEL_HARDENING.md)
- [Roadmap](docs/ROADMAP.md)
