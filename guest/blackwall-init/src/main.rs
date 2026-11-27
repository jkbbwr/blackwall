//! `blackwall-init` binary entrypoint.
//!
//! - In guest initramfs PID 1 mode (`std::process::id() == 1`):
//!   mounts `/proc`, `/sys`, `/dev`, `/dev/pts`, `/run`, listens on `AF_VSOCK`
//!   Ports `1000`, `1001`, `1002`, applies `BootConfig` (`dm-verity` on `vda`,
//!   ephemeral 256-bit `dm-crypt` + `ext4` on `vdb` at `/workspace`, spawns
//!   `blackwall-netbridge` when `network_mode == Egress`), drops workload
//!   privileges (`uid 1000`, `PR_SET_NO_NEW_PRIVS=1`), and serves Port 1002.
//! - In local host test mode:
//!   `blackwall-init --test-unix-sock <path> --workspace <dir>`

use blackwall_init::dm::{
    query_block_device_sectors, setup_crypt, setup_verity, VerityCorruptionMode,
};
use blackwall_init::pty::PrivilegeDrop;
use blackwall_init::session::{serve_session, BootApplyOutcome, SessionOptions};
use blackwall_init::vsock::{VsockListener, VsockStream};
use blackwall_proto::{
    write_audit_frame, BootConfig, GuestAuditFrame, GuestNetMode, PORT_AUDIT_UNI, PORT_CTRL_SESSION,
    PORT_NET_MUX,
};
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const WORKLOAD_UID: u32 = 1000;
const WORKLOAD_GID: u32 = 1000;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if let Some((sock_path, workspace)) = parse_test_args(&args) {
        if let Err(e) = run_test_unix_mode(&sock_path, &workspace) {
            eprintln!("blackwall-init test mode failed: {e}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    if std::process::id() == 1 {
        if let Err(e) = run_pid1() {
            eprintln!("blackwall-init PID 1 fatal error: {e}");
        }
        unsafe {
            libc::sync();
            libc::reboot(libc::RB_POWER_OFF);
        }
        return ExitCode::FAILURE;
    }

    eprintln!(
        "usage:\n  PID 1 inside guest initramfs (automatic)\n  blackwall-init --test-unix-sock <path> --workspace <dir>"
    );
    ExitCode::FAILURE
}

fn parse_test_args(args: &[String]) -> Option<(PathBuf, PathBuf)> {
    let mut sock: Option<PathBuf> = None;
    let mut workspace: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--test-unix-sock" if i + 1 < args.len() => {
                sock = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--workspace" if i + 1 < args.len() => {
                workspace = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            _ => i += 1,
        }
    }
    match (sock, workspace) {
        (Some(s), Some(w)) => Some((s, w)),
        _ => None,
    }
}

fn run_test_unix_mode(sock_path: &Path, workspace: &Path) -> io::Result<()> {
    fs::create_dir_all(workspace)?;
    let stream = match UnixStream::connect(sock_path) {
        Ok(s) => s,
        Err(_) => {
            let _ = fs::remove_file(sock_path);
            let listener = UnixListener::bind(sock_path)?;
            let (s, _) = listener.accept()?;
            s
        }
    };
    let rx = stream.try_clone()?;
    serve_session(rx, stream, SessionOptions::for_testing(workspace.to_path_buf()))
}

fn run_pid1() -> io::Result<()> {
    mount_essential_filesystems()?;

    // Listen on all three host-initiated AF_VSOCK ports before accepting so the
    // host orchestrator can connect in any order without deadlocking.
    let l_net = VsockListener::bind(PORT_NET_MUX)?;
    let l_audit = VsockListener::bind(PORT_AUDIT_UNI)?;
    let l_ctrl = VsockListener::bind(PORT_CTRL_SESSION)?;

    // Accept Port 1000 in the background only when the host connects (Egress mode).
    // Do NOT join it unconditionally, because Loopback and None modes never connect Port 1000.
    let net_rx_slot: Arc<Mutex<Option<thread::JoinHandle<io::Result<VsockStream>>>>> =
        Arc::new(Mutex::new(Some(thread::spawn(move || l_net.accept()))));
    let h_audit = thread::spawn(move || l_audit.accept());
    let ctrl_stream = l_ctrl.accept()?;

    let mut audit_stream = h_audit
        .join()
        .map_err(|_| io::Error::other("audit accept thread panicked"))??;

    // Emit initial boot handshake audit event on Port 1001 (unidirectional).
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let _ = write_audit_frame(
        &mut audit_stream,
        &GuestAuditFrame {
            timestamp_ns: now_ns,
            source: "blackwall-init".into(),
            kind: "boot_handshake".into(),
            payload: serde_json::json!({ "pid": 1 }),
        },
    );

    let netbridge_child: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(None));

    let net_slot_hook = Arc::clone(&net_rx_slot);
    let netbridge_hook = Arc::clone(&netbridge_child);

    let opts = SessionOptions {
        workspace_root: PathBuf::from("/workspace"),
        virtual_workspace_mount: "/workspace".to_string(),
        drop_privs: Some(PrivilegeDrop {
            uid: WORKLOAD_UID,
            gid: WORKLOAD_GID,
        }),
        on_boot_configure: Some(Box::new(move |cfg: &BootConfig| {
            apply_pid1_boot_config(cfg, &net_slot_hook, &netbridge_hook)
        })),
    };

    let ctrl_rx = ctrl_stream.try_clone()?;
    let res = serve_session(ctrl_rx, ctrl_stream, opts);

    if let Some(mut child) = netbridge_child.lock().unwrap().take() {
        let _ = child.kill();
        let _ = child.wait();
    }

    res
}

fn apply_pid1_boot_config(
    cfg: &BootConfig,
    net_slot: &Arc<Mutex<Option<thread::JoinHandle<io::Result<VsockStream>>>>>,
    netbridge_child: &Arc<Mutex<Option<Child>>>,
) -> Result<BootApplyOutcome, String> {
    // 0. Stage blackwall-netbridge into /run before switching root so it remains
    //    accessible after pivoting into read-only vda.
    let _ = fs::create_dir_all("/run/blackwall");
    if let Some(src_bin) = find_netbridge_binary() {
        let dst = "/run/blackwall/blackwall-netbridge";
        if fs::copy(src_bin, dst).is_ok() {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dst, fs::Permissions::from_mode(0o755));
        }
    }

    // 1. Set up dm-verity on /dev/vda and switch_root into the immutable erofs rootfs.
    if let Some(ref verity) = cfg.vda_verity {
        if Path::new("/dev/vda").exists() {
            let mapper = setup_verity(
                "vda-verity",
                "/dev/vda",
                verity,
                VerityCorruptionMode::PanicOnCorruption,
            )
            .map_err(|e| format!("dm-verity setup on /dev/vda failed: {e}"))?;
            mount_ro_erofs(&mapper, "/newroot")
                .map_err(|e| format!("mount erofs {mapper} -> /newroot: {e}"))?;
            switch_root("/newroot").map_err(|e| format!("switch_root /newroot: {e}"))?;
        }
    }

    // 2. Set up ephemeral 256-bit dm-crypt + ext4 on /dev/vdb at workspace_mount.
    //    (Runs AFTER switch_root so /sbin/mkfs.ext4 inside vda is available.)
    let ws_mount = if cfg.workspace_mount.is_empty() {
        "/workspace"
    } else {
        cfg.workspace_mount.as_str()
    };
    if !Path::new(ws_mount).exists() {
        let _ = fs::create_dir_all(ws_mount);
    }

    let workspace_mounted = if Path::new("/dev/vdb").exists() {
        let sectors = query_block_device_sectors("/dev/vdb")
            .map_err(|e| format!("query /dev/vdb sectors: {e}"))?;
        let mapper =
            setup_crypt("vdb-crypt", "/dev/vdb", sectors).map_err(|e| format!("dm-crypt: {e}"))?;
        format_and_mount_ext4(&mapper, ws_mount)?;
        true
    } else {
        mount_fs("tmpfs", ws_mount, "tmpfs", 0, Some("mode=0755"))
            .map_err(|e| format!("mount tmpfs workspace: {e}"))?;
        true
    };

    // Ensure workload user owns workspace and has a writable $HOME tmpfs on read-only vda.
    if let Ok(cpath) = CString::new(ws_mount) {
        unsafe {
            libc::chown(cpath.as_ptr(), WORKLOAD_UID, WORKLOAD_GID);
        }
    }
    if Path::new("/home/sandbox").is_dir() {
        let _ = mount_fs(
            "tmpfs",
            "/home/sandbox",
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV,
            Some("mode=0755,uid=1000,gid=1000"),
        );
    }

    // 3. Install ephemeral MITM CA certificate into /run and bind-mount over trust bundle if present.
    if let Some(ref pem) = cfg.mitm_ca_pem {
        let _ = fs::create_dir_all("/run/blackwall");
        let _ = fs::write("/run/blackwall/mitm-ca.crt", pem);
        let bundle_src = "/etc/ssl/certs/ca-certificates.crt";
        let bundle_dst = "/run/blackwall/ca-certificates.crt";
        if let Ok(mut existing) = fs::read_to_string(bundle_src) {
            existing.push('\n');
            existing.push_str(pem);
            if fs::write(bundle_dst, existing).is_ok() {
                let _ = mount_fs(bundle_dst, bundle_src, "", libc::MS_BIND, None);
            }
        }
    }

    // 4. Bring up loopback when networking is enabled (`Loopback` or `Egress`).
    if cfg.network_mode != GuestNetMode::None {
        let _ = bring_up_loopback();
    }

    // 5. Spawn `blackwall-netbridge` inheriting Port 1000 vsock fd in `Egress` mode.
    let mut netbridge_ready = false;
    if cfg.network_mode == GuestNetMode::Egress {
        // Bind-mount writable resolv.conf over read-only /etc/resolv.conf for synthetic DNS.
        let _ = fs::write("/run/blackwall/resolv.conf", "nameserver 198.18.0.53\n");
        if Path::new("/etc/resolv.conf").exists() {
            let _ = mount_fs(
                "/run/blackwall/resolv.conf",
                "/etc/resolv.conf",
                "",
                libc::MS_BIND,
                None,
            );
        }
        if let Some(handle) = net_slot.lock().unwrap().take() {
            let net_stream = handle
                .join()
                .map_err(|_| "port 1000 accept thread panicked".to_string())?
                .map_err(|e| format!("accept port 1000: {e}"))?;
            net_stream
                .clear_cloexec()
                .map_err(|e| format!("clear cloexec on port 1000: {e}"))?;
            let fd_num = net_stream.as_raw_fd();
            let bin = if Path::new("/run/blackwall/blackwall-netbridge").is_file() {
                "/run/blackwall/blackwall-netbridge"
            } else {
                find_netbridge_binary()
                    .ok_or_else(|| "blackwall-netbridge binary not found in initramfs".to_string())?
            };
            let child = Command::new(bin)
                .args(["--vsock-fd", &fd_num.to_string(), "--tun-name", "tun0"])
                .spawn()
                .map_err(|e| format!("spawn blackwall-netbridge: {e}"))?;
            *netbridge_child.lock().unwrap() = Some(child);
            drop(net_stream);
            netbridge_ready = true;
        }
    }

    Ok(BootApplyOutcome {
        workspace_mounted,
        netbridge_ready,
    })
}

fn switch_root(newroot: &str) -> io::Result<()> {
    for sub in ["proc", "sys", "dev", "run", "tmp"] {
        let src = format!("/{sub}");
        let dst = format!("{newroot}/{sub}");
        if Path::new(&dst).exists() {
            mount_fs(&src, &dst, "", libc::MS_MOVE, None)?;
        }
    }
    let c_newroot = CString::new(newroot).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let c_dot = CString::new(".").unwrap();
    let c_slash = CString::new("/").unwrap();
    unsafe {
        if libc::chdir(c_newroot.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::mount(
            c_dot.as_ptr(),
            c_slash.as_ptr(),
            std::ptr::null(),
            libc::MS_MOVE,
            std::ptr::null(),
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        if libc::chroot(c_dot.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::chdir(c_slash.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn mount_essential_filesystems() -> io::Result<()> {
    let mounts: &[(&str, &str, &str, libc::c_ulong, Option<&str>)] = &[
        ("proc", "/proc", "proc", libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV, Some("hidepid=2")),
        ("sysfs", "/sys", "sysfs", libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV, None),
        ("devtmpfs", "/dev", "devtmpfs", libc::MS_NOSUID, Some("mode=0755")),
        ("devpts", "/dev/pts", "devpts", libc::MS_NOSUID | libc::MS_NOEXEC, Some("gid=5,mode=620")),
        ("tmpfs", "/run", "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, Some("mode=0755")),
        ("tmpfs", "/tmp", "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, Some("mode=1777")),
    ];
    for &(src, target, fstype, flags, data) in mounts {
        fs::create_dir_all(target)?;
        if let Err(e) = mount_fs(src, target, fstype, flags, data) {
            // EBUSY means already mounted by kernel (e.g. devtmpfs).
            if e.raw_os_error() != Some(libc::EBUSY) {
                return Err(e);
            }
        }
    }
    Ok(())
}

fn mount_ro_erofs(dev: &str, target: &str) -> io::Result<()> {
    fs::create_dir_all(target)?;
    mount_fs(dev, target, "erofs", libc::MS_RDONLY, None)
}

fn format_and_mount_ext4(dev: &str, target: &str) -> Result<(), String> {
    // Format ephemeral dm-crypt device if mke2fs/mkfs.ext4 is available in initramfs.
    for tool in ["/sbin/mkfs.ext4", "/usr/sbin/mkfs.ext4", "/sbin/mke2fs"] {
        if Path::new(tool).is_file() {
            let status = Command::new(tool)
                .args(["-q", "-F", "-m", "0", "-E", "root_owner=1000:1000", dev])
                .status()
                .map_err(|e| format!("run {tool}: {e}"))?;
            if !status.success() {
                return Err(format!("{tool} exited with {status}"));
            }
            break;
        }
    }
    mount_fs(dev, target, "ext4", libc::MS_NOSUID | libc::MS_NODEV, None)
        .map_err(|e| format!("mount ext4 {dev} -> {target}: {e}"))?;
    // Ephemeral workspace is wiped on VM exit; remove ext4's root-only lost+found before boot completes.
    let _ = fs::remove_dir(Path::new(target).join("lost+found"));
    Ok(())
}

fn mount_fs(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let c_src = CString::new(source).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let c_tgt = CString::new(target).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let c_fs = if fstype.is_empty() {
        None
    } else {
        Some(CString::new(fstype).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?)
    };
    let c_data = match data {
        Some(d) => Some(CString::new(d).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?),
        None => None,
    };
    let fs_ptr = c_fs
        .as_ref()
        .map(|s| s.as_ptr())
        .unwrap_or(std::ptr::null());
    let data_ptr = c_data
        .as_ref()
        .map(|s| s.as_ptr() as *const libc::c_void)
        .unwrap_or(std::ptr::null());
    let rc = unsafe { libc::mount(c_src.as_ptr(), c_tgt.as_ptr(), fs_ptr, flags, data_ptr) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn bring_up_loopback() -> io::Result<()> {
    #[cfg(target_env = "musl")]
    type IoctlReq = libc::c_int;
    #[cfg(not(target_env = "musl"))]
    type IoctlReq = libc::c_ulong;

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_name[0] = b'l' as libc::c_char;
    ifr.ifr_name[1] = b'o' as libc::c_char;
    let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS as IoctlReq, &mut ifr) };
    if rc == 0 {
        unsafe {
            ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            let _ = libc::ioctl(fd, libc::SIOCSIFFLAGS as IoctlReq, &mut ifr);
        }
    }
    unsafe {
        libc::close(fd);
    }
    Ok(())
}

fn find_netbridge_binary() -> Option<&'static str> {
    [
        "/sbin/blackwall-netbridge",
        "/usr/sbin/blackwall-netbridge",
        "/bin/blackwall-netbridge",
        "/blackwall-netbridge",
    ]
    .into_iter()
    .find(|p| Path::new(p).is_file())
}
