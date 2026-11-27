set shell := ["bash", "-euo", "pipefail", "-c"]

arch := `uname -m`
musl_target := arch + "-unknown-linux-musl"
kernel_version := env("BLACKWALL_KERNEL_VERSION", "6.12.119")
kernel_src := "kernel/src/linux-" + kernel_version
kernel_out := "kernel/out/" + arch
jobs := `nproc`
http_listen := env("BLACKWALL_HTTP_LISTEN", "127.0.0.1:7700")
audit_log := env("BLACKWALL_AUDIT_LOG", "/tmp/blackwall-audit.jsonl")

# Show available recipes
default:
    @just --list

# Check required host build & runtime dependencies
check-deps:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Checking Blackwall host toolchain ({{arch}})..."
    for cmd in rustc cargo clang lld cloud-hypervisor pasta nft mkfs.erofs veritysetup pnpm curl tar; do
        if command -v "$cmd" >/dev/null 2>&1; then
            printf "  [ok] %-18s %s\n" "$cmd" "$(command -v "$cmd")"
        else
            printf "  [MISSING] %s\n" "$cmd"
            exit 1
        fi
    done
    if command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1; then
        printf "  [ok] %-18s %s\n" "oci-runtime" "$(command -v docker || command -v podman)"
    else
        echo "  [MISSING] docker or podman"
        exit 1
    fi
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        echo "  [ok] /dev/kvm           rw"
    else
        echo "  [WARN] /dev/kvm is not rw for current user"
    fi
    if rustup target list --installed | grep -qx "{{musl_target}}"; then
        echo "  [ok] rustup target      {{musl_target}}"
    else
        echo "  [MISSING] run: rustup target add {{musl_target}}"
        exit 1
    fi

# Ensure the static musl Rust target is installed
setup-targets:
    rustup target add {{musl_target}}

# Cross-compile static musl guest binaries (blackwall-init & blackwall-netbridge)
build-guest:
    cargo build --release --target {{musl_target}} -p blackwall-init -p blackwall-netbridge

# Download and extract Linux kernel source into kernel/src/ if not already present
fetch-kernel:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ ! -d "{{kernel_src}}" ]; then
        mkdir -p kernel/src
        tarball="linux-{{kernel_version}}.tar.xz"
        url="https://cdn.kernel.org/pub/linux/kernel/v6.x/$tarball"
        echo "Downloading $url..."
        curl -fL "$url" -o "kernel/src/$tarball"
        tar -xJf "kernel/src/$tarball" -C kernel/src
        rm -f "kernel/src/$tarball"
    else
        echo "Kernel source already present at {{kernel_src}}"
    fi

# Build hardened guest kernels (lo, noinet, or all) and reproducible initramfs
build-kernel profile="all": build-guest fetch-kernel
    ./kernel/scripts/build-kernel.sh \
        --profile {{profile}} \
        --arch {{arch}} \
        --kernel-src ./{{kernel_src}} \
        --build-initramfs \
        --init-bin ./target/{{musl_target}}/release/blackwall-init \
        --netbridge-bin ./target/{{musl_target}}/release/blackwall-netbridge \
        --out-dir ./{{kernel_out}} \
        --jobs {{jobs}}

# Verify hardened kernel configs without compiling
verify-kernel-configs:
    ./kernel/scripts/verify-configs.sh

# Install UI dependencies, typecheck, and build SolidJS production bundle into ui/dist/
build-ui:
    cd ui && pnpm install --frozen-lockfile && pnpm exec tsc --noEmit && pnpm run build

# Build debug host binaries and SolidJS UI
build: build-ui
    RUSTFLAGS="-D warnings" cargo build --bin blackwall-daemon --bin blackwall-proxy --bin blackwall

# Build the full optimized release stack (guest musl, hardened kernels, host binaries, UI)
build-release: check-deps build-kernel build-ui
    RUSTFLAGS="-D warnings" cargo build --release --bin blackwall-daemon --bin blackwall-proxy --bin blackwall

# Package a self-contained release tarball + SHA256SUMS into dist/
package-release: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    stage="dist/blackwall-{{arch}}"
    rm -rf "$stage" "dist/blackwall-{{arch}}.tar.gz"
    mkdir -p "$stage/bin" "$stage/kernel" "$stage/ui" "$stage/profiles"
    cp target/release/blackwall target/release/blackwall-daemon target/release/blackwall-proxy "$stage/bin/"
    cp "{{kernel_out}}/vmlinux-lo" "{{kernel_out}}/vmlinux-noinet" "{{kernel_out}}/initramfs-{{arch}}.cpio.gz" "$stage/kernel/"
    cp -r ui/dist "$stage/ui/dist"
    cp profiles/*.toml "$stage/profiles/"
    cp README.md "$stage/"
    tar -czf "dist/blackwall-{{arch}}.tar.gz" -C dist "blackwall-{{arch}}"
    (cd dist && sha256sum "blackwall-{{arch}}.tar.gz" > SHA256SUMS)
    echo "Packaged dist/blackwall-{{arch}}.tar.gz"
    cat dist/SHA256SUMS

# Run full workspace Rust tests (-D warnings), kernel config checks, and UI typecheck
test: verify-kernel-configs
    RUSTFLAGS="-D warnings" cargo test --workspace
    cd ui && pnpm exec tsc --noEmit

# Build an immutable EROFS + dm-verity image for a named profile via the CLI
build-image profile="ts-dev":
    ./target/debug/blackwall image build --profile {{profile}}

# Launch blackwall-daemon (debug build) with local UI, profiles, and hardened kernels
daemon:
    RUST_LOG=blackwall_daemon=info,blackwall_core=info ./target/debug/blackwall-daemon \
        --http-listen {{http_listen}} \
        --ui-dir ./ui/dist \
        --profile-dir ./profiles \
        --kernel-lo ./{{kernel_out}}/vmlinux-lo \
        --kernel-noinet ./{{kernel_out}}/vmlinux-noinet \
        --initramfs ./{{kernel_out}}/initramfs-{{arch}}.cpio.gz \
        --audit-log {{audit_log}}

# Launch blackwall-daemon (release build) with local UI, profiles, and hardened kernels
daemon-release:
    RUST_LOG=blackwall_daemon=info,blackwall_core=info ./target/release/blackwall-daemon \
        --http-listen {{http_listen}} \
        --ui-dir ./ui/dist \
        --profile-dir ./profiles \
        --kernel-lo ./{{kernel_out}}/vmlinux-lo \
        --kernel-noinet ./{{kernel_out}}/vmlinux-noinet \
        --initramfs ./{{kernel_out}}/initramfs-{{arch}}.cpio.gz \
        --audit-log {{audit_log}}

# Launch blackwall-daemon in operator-locked mode (read-only profiles + locked profiles required)
daemon-locked:
    RUST_LOG=blackwall_daemon=info,blackwall_core=info ./target/release/blackwall-daemon \
        --http-listen {{http_listen}} \
        --ui-dir ./ui/dist \
        --profile-dir ./profiles \
        --readonly-profiles \
        --require-locked-profiles \
        --kernel-lo ./{{kernel_out}}/vmlinux-lo \
        --kernel-noinet ./{{kernel_out}}/vmlinux-noinet \
        --initramfs ./{{kernel_out}}/initramfs-{{arch}}.cpio.gz \
        --audit-log {{audit_log}}

# Remove build artifacts (preserves kernel/src and kernel/out)
clean:
    cargo clean
    rm -rf ui/dist dist
