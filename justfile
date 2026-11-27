set shell := ["bash", "-euo", "pipefail", "-c"]

arch := `uname -m`
musl_target := arch + "-unknown-linux-musl"
kernel_version := env("BLACKWALL_KERNEL_VERSION", "7.3.6")
kernel_src := "kernel/src/linux-" + kernel_version
kernel_out := "kernel/out/" + arch
jobs := `nproc`
http_listen := env("BLACKWALL_HTTP_LISTEN", "127.0.0.1:7700")
audit_log := env("BLACKWALL_AUDIT_LOG", "/tmp/blackwall-audit.jsonl")

# Show available recipes
default:
    @just --list

# Check ALL required host build & runtime dependencies in a single pass
check-deps:
    #!/usr/bin/env bash
    set -euo pipefail
    missing=()
    warnings=()

    check_cmd() {
        local cmd="$1"
        local note="${2:-}"
        if command -v "$cmd" >/dev/null 2>&1; then
            if [ -n "$note" ]; then
                printf "  [ok]      %-20s %s (%s)\n" "$cmd" "$(command -v "$cmd")" "$note"
            else
                printf "  [ok]      %-20s %s\n" "$cmd" "$(command -v "$cmd")"
            fi
        else
            printf "  [MISSING] %-20s%s\n" "$cmd" "${note:+ ($note)}"
            missing+=("$cmd")
        fi
    }

    echo "Checking Blackwall host toolchain ({{arch}})..."

    echo ""
    echo "Runtime & Sandbox:"
    check_cmd cloud-hypervisor
    check_cmd pasta "from passt"
    check_cmd nft "from nftables"
    check_cmd mkfs.erofs "from erofs-utils"
    check_cmd veritysetup "from cryptsetup"
    if command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1; then
        printf "  [ok]      %-20s %s\n" "oci-runtime" "$(command -v docker || command -v podman)"
    else
        printf "  [MISSING] %-20s (docker or podman)\n" "oci-runtime"
        missing+=("docker|podman")
    fi
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        printf "  [ok]      %-20s rw\n" "/dev/kvm"
    elif [ -e /dev/kvm ]; then
        printf "  [WARN]    %-20s exists but not rw for %s (run: sudo usermod -aG kvm %s)\n" "/dev/kvm" "$USER" "$USER"
        warnings+=("/dev/kvm permissions")
    else
        printf "  [WARN]    %-20s device missing (enable KVM virtualization)\n" "/dev/kvm"
        warnings+=("/dev/kvm missing")
    fi

    echo ""
    echo "Rust Toolchain:"
    check_cmd rustc
    check_cmd cargo
    check_cmd rustup
    if command -v rustup >/dev/null 2>&1; then
        if rustup target list --installed | grep -qx "{{musl_target}}"; then
            printf "  [ok]      %-20s installed\n" "{{musl_target}}"
        else
            printf "  [MISSING] %-20s (run: rustup target add {{musl_target}})\n" "{{musl_target}}"
            missing+=("rustup-target:{{musl_target}}")
        fi
    else
        printf "  [MISSING] %-20s (rustup not installed)\n" "{{musl_target}}"
        missing+=("rustup-target:{{musl_target}}")
    fi

    echo ""
    echo "Kernel & Initramfs Build (Linux {{kernel_version}}):"
    clang_ver=""
    if command -v clang >/dev/null 2>&1; then
        clang_ver="$(clang --version | head -n 1)"
    fi
    check_cmd clang "$clang_ver"
    for cmd in ld.lld llvm-ar llvm-nm llvm-objcopy llvm-objdump llvm-readelf llvm-strip make flex bison bc perl python3 cpio gzip xz tar curl; do
        check_cmd "$cmd"
    done

    echo ""
    echo "Dashboard UI:"
    check_cmd node
    check_cmd pnpm

    echo ""
    if [ "${#warnings[@]}" -gt 0 ]; then
        echo "Warnings (${#warnings[@]}): ${warnings[*]}"
    fi
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "Missing dependencies (${#missing[@]}): ${missing[*]}"
        echo "Run \`just install-deps\` for platform-specific install commands."
        exit 1
    fi
    echo "All dependencies OK!"

# Detect host distro (or pass arch|debian|ubuntu|fedora|opensuse|alpine|nix) and print install commands
install-deps platform="":
    #!/usr/bin/env bash
    set -euo pipefail

    override="{{platform}}"
    os_id=""
    os_like=""
    os_pretty=""

    if [ -n "$override" ]; then
        os_id="${override,,}"
        os_pretty="override: $override"
    elif [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        os_id="${ID:-}"
        os_like="${ID_LIKE:-}"
        os_pretty="${PRETTY_NAME:-${NAME:-$os_id}}"
    else
        os_id="$(uname -s | tr '[:upper:]' '[:lower:]')"
        os_pretty="$os_id"
    fi

    family="unknown"
    case "$os_id" in
        arch|cachyos|endeavouros|manjaro|garuda|artix) family="arch" ;;
        debian|ubuntu|pop|linuxmint|kali|raspbian)     family="debian" ;;
        fedora|rhel|centos|rocky|almalinux|nobara)     family="fedora" ;;
        opensuse*|sles|suse)                           family="opensuse" ;;
        alpine)                                        family="alpine" ;;
        nixos|nix)                                     family="nix" ;;
        *)
            case "$os_like" in
                *arch*)                 family="arch" ;;
                *debian*|*ubuntu*)      family="debian" ;;
                *fedora*|*rhel*)        family="fedora" ;;
                *suse*)                 family="opensuse" ;;
                *)
                    if command -v pacman >/dev/null 2>&1; then family="arch"
                    elif command -v apt-get >/dev/null 2>&1; then family="debian"
                    elif command -v dnf >/dev/null 2>&1; then family="fedora"
                    elif command -v zypper >/dev/null 2>&1; then family="opensuse"
                    elif command -v apk >/dev/null 2>&1; then family="alpine"
                    elif command -v nix >/dev/null 2>&1; then family="nix"
                    fi
                    ;;
            esac
            ;;
    esac

    ch_arch="{{arch}}"
    ch_bin="cloud-hypervisor-static"
    if [ "$ch_arch" = "aarch64" ]; then
        ch_bin="cloud-hypervisor-static-aarch64"
    fi

    echo "Detected platform: ${os_pretty} (family=${family}, arch=${ch_arch})"
    echo "Run the following commands to install all Blackwall dependencies:"
    echo ""

    case "$family" in
        arch)
            aur_helper="paru"
            if ! command -v paru >/dev/null 2>&1 && command -v yay >/dev/null 2>&1; then
                aur_helper="yay"
            fi
            cat <<EOF
    # 1. Core build, kernel, sandbox, and UI packages
    sudo pacman -S --needed \\
      rustup clang lld llvm make flex bison bc perl python cpio gzip xz tar curl \\
      libelf openssl passt nftables erofs-utils cryptsetup podman nodejs pnpm

    # 2. Cloud Hypervisor (AUR, or grab the official static release binary)
    ${aur_helper} -S --needed cloud-hypervisor
    # (Without AUR helper:)
    # curl -fL https://github.com/cloud-hypervisor/cloud-hypervisor/releases/latest/download/${ch_bin} \\
    #   -o ~/.local/bin/cloud-hypervisor && chmod +x ~/.local/bin/cloud-hypervisor
    EOF
            ;;
        debian)
            cat <<EOF
    # 1. Core build, kernel, sandbox, and container packages
    sudo apt-get update && sudo apt-get install -y \\
      clang lld llvm make flex bison bc perl python3 cpio gzip xz-utils tar curl \\
      libelf-dev libssl-dev passt nftables erofs-utils cryptsetup-bin podman nodejs npm

    # 2. Rust toolchain (if not installed) + pnpm
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    sudo npm install -g pnpm

    # 3. Cloud Hypervisor static release binary
    mkdir -p ~/.local/bin
    curl -fL https://github.com/cloud-hypervisor/cloud-hypervisor/releases/latest/download/${ch_bin} \\
      -o ~/.local/bin/cloud-hypervisor && chmod +x ~/.local/bin/cloud-hypervisor
    EOF
            ;;
        fedora)
            cat <<EOF
    # 1. Core build, kernel, sandbox, and UI packages
    sudo dnf install -y \\
      rustup clang lld llvm make flex bison bc perl python3 cpio gzip xz tar curl \\
      elfutils-libelf-devel openssl-devel cloud-hypervisor passt nftables \\
      erofs-utils cryptsetup podman nodejs pnpm
    EOF
            ;;
        opensuse)
            cat <<EOF
    # 1. Core build, kernel, sandbox, and UI packages
    sudo zypper install -y \\
      rustup clang lld llvm make flex bison bc perl python3 cpio gzip xz tar curl \\
      libelf-devel libopenssl-devel cloud-hypervisor passt nftables \\
      erofs-utils cryptsetup podman nodejs pnpm
    EOF
            ;;
        alpine)
            cat <<EOF
    # 1. Core build, kernel, sandbox, and UI packages
    sudo apk add \\
      rustup clang lld llvm make flex bison bc perl python3 cpio gzip xz tar curl \\
      elfutils-dev openssl-dev passt nftables erofs-utils cryptsetup podman nodejs pnpm

    # 2. Cloud Hypervisor static release binary
    mkdir -p ~/.local/bin
    curl -fL https://github.com/cloud-hypervisor/cloud-hypervisor/releases/latest/download/${ch_bin} \\
      -o ~/.local/bin/cloud-hypervisor && chmod +x ~/.local/bin/cloud-hypervisor
    EOF
            ;;
        nix)
            cat <<EOF
    # Enter a shell with all Blackwall dependencies via nixpkgs
    nix shell \\
      nixpkgs#rustup nixpkgs#clang nixpkgs#lld nixpkgs#llvm nixpkgs#gnumake \\
      nixpkgs#flex nixpkgs#bison nixpkgs#bc nixpkgs#perl nixpkgs#python3 \\
      nixpkgs#cpio nixpkgs#gzip nixpkgs#xz nixpkgs#gnutar nixpkgs#curl \\
      nixpkgs#cloud-hypervisor nixpkgs#passt nixpkgs#nftables nixpkgs#erofs-utils \\
      nixpkgs#cryptsetup nixpkgs#podman nixpkgs#nodejs nixpkgs#pnpm
    EOF
            ;;
        *)
            cat <<EOF
    Could not guess package manager for '${os_pretty}'.
    Pass a platform explicitly: just install-deps <arch|debian|ubuntu|fedora|opensuse|alpine|nix>

    Required tools:
      rustc cargo rustup clang lld llvm make flex bison bc perl python3 cpio gzip xz tar curl
      cloud-hypervisor pasta(passt) nft(nftables) mkfs.erofs(erofs-utils) veritysetup(cryptsetup)
      docker|podman node pnpm
    EOF
            ;;
    esac

    cat <<EOF

    # Post-install: static musl Rust target & /dev/kvm access
    rustup toolchain install stable && rustup target add {{musl_target}}
    sudo usermod -aG kvm "\$USER"   # log out/in or run \`newgrp kvm\` if /dev/kvm is not rw
    just check-deps
    EOF

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
        major="${tarball#linux-}"
        major="${major%%.*}"
        url="https://cdn.kernel.org/pub/linux/kernel/v${major}.x/$tarball"
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
