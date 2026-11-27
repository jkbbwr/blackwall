//! Linux `/dev/net/tun` (`IFF_TUN | IFF_NO_PI`) opener and ioctl interface
//! bringup (`198.18.0.1/15`, MTU 1500, default route via `tun0`, `/etc/resolv.conf`).

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub const DEFAULT_TUN_NAME: &str = "tun0";
pub const TUN_LOCAL_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
pub const TUN_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 254, 0, 0); // /15
pub const TUN_DNS_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 53);
pub const TUN_MTU: u16 = 1500;

const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const TUNSETIFF: u32 = 0x4004_54CA;

const SIOCGIFFLAGS: u32 = 0x8913;
const SIOCSIFFLAGS: u32 = 0x8914;
const SIOCSIFADDR: u32 = 0x8916;
const SIOCSIFNETMASK: u32 = 0x891C;
const SIOCSIFMTU: u32 = 0x8922;
const SIOCADDRT: u32 = 0x890B;
const RTF_UP: libc::c_ushort = 0x0001;

#[cfg(target_env = "musl")]
type IoctlReq = libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlReq = libc::c_ulong;

/// Linux `<linux/route.h>` `struct rtentry` layout for 64-bit Linux (both glibc & musl).
#[repr(C)]
struct LinuxRtEntry {
    rt_pad1: libc::c_ulong,
    rt_dst: libc::sockaddr,
    rt_gateway: libc::sockaddr,
    rt_genmask: libc::sockaddr,
    rt_flags: libc::c_ushort,
    rt_pad2: libc::c_short,
    rt_pad3: libc::c_ulong,
    rt_pad4: *mut libc::c_void,
    rt_metric: libc::c_short,
    rt_dev: *mut libc::c_char,
    rt_mtu: libc::c_ulong,
    rt_window: libc::c_ulong,
    rt_irtt: libc::c_ushort,
}

pub struct TunDevice {
    fd: OwnedFd,
    name: String,
}

impl TunDevice {
    /// Open `/dev/net/tun` and attach an `IFF_TUN | IFF_NO_PI` device named `name`.
    pub fn open(name: &str) -> io::Result<Self> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid tun interface name: {name:?}"),
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        let raw_fd = file.as_raw_fd();

        // Set non-blocking mode for event-loop polling.
        let fl = unsafe { libc::fcntl(raw_fd, libc::F_GETFL) };
        if fl < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(raw_fd, libc::F_SETFL, fl | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        for (i, b) in name.as_bytes().iter().enumerate() {
            ifr.ifr_name[i] = *b as libc::c_char;
        }
        ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;

        let rc = unsafe { libc::ioctl(raw_fd, TUNSETIFF as IoctlReq, &mut ifr) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let assigned_len = ifr
            .ifr_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(ifr.ifr_name.len());
        let assigned_bytes: Vec<u8> = ifr.ifr_name[..assigned_len]
            .iter()
            .map(|&c| c as u8)
            .collect();
        let assigned_name = String::from_utf8_lossy(&assigned_bytes).into_owned();

        Ok(Self {
            fd: OwnedFd::from(file),
            name: assigned_name,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read a single IP packet from `tun0`. Returns `Err(WouldBlock)` if none ready.
    pub fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            return Ok(n as usize);
        }
    }

    /// Write a single IP packet to `tun0`.
    pub fn write_packet(&self, pkt: &[u8]) -> io::Result<usize> {
        loop {
            let n = unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    pkt.as_ptr() as *const libc::c_void,
                    pkt.len(),
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            return Ok(n as usize);
        }
    }
}

impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Configure `name` (`tun0`) with IPv4 address (`198.18.0.1`), netmask (`255.254.0.0` /15),
/// MTU (`1500`), bring link UP, and install default route `0.0.0.0/0` into `name`.
pub fn configure_interface(
    name: &str,
    ip: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: u16,
) -> io::Result<()> {
    let sock_raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock_raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let sock = unsafe { OwnedFd::from_raw_fd(sock_raw) };
    let fd = sock.as_raw_fd();

    // 1. Set IPv4 address.
    let mut ifr = make_ifreq(name)?;
    ifr.ifr_ifru.ifru_addr = ipv4_to_sockaddr(ip);
    ioctl_ifreq(fd, SIOCSIFADDR, &mut ifr)?;

    // 2. Set IPv4 netmask.
    let mut ifr = make_ifreq(name)?;
    ifr.ifr_ifru.ifru_netmask = ipv4_to_sockaddr(netmask);
    ioctl_ifreq(fd, SIOCSIFNETMASK, &mut ifr)?;

    // 3. Set MTU.
    let mut ifr = make_ifreq(name)?;
    ifr.ifr_ifru.ifru_mtu = mtu as libc::c_int;
    ioctl_ifreq(fd, SIOCSIFMTU, &mut ifr)?;

    // 4. Bring interface UP | RUNNING.
    let mut ifr = make_ifreq(name)?;
    ioctl_ifreq(fd, SIOCGIFFLAGS, &mut ifr)?;
    unsafe {
        ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    }
    ioctl_ifreq(fd, SIOCSIFFLAGS, &mut ifr)?;

    // 5. Add default route 0.0.0.0/0 -> dev `name`.
    let dev_c = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in interface name"))?;
    let mut rt: LinuxRtEntry = unsafe { std::mem::zeroed() };
    rt.rt_dst = ipv4_to_sockaddr(Ipv4Addr::UNSPECIFIED);
    rt.rt_genmask = ipv4_to_sockaddr(Ipv4Addr::UNSPECIFIED);
    rt.rt_gateway = ipv4_to_sockaddr(Ipv4Addr::UNSPECIFIED);
    rt.rt_flags = RTF_UP;
    rt.rt_dev = dev_c.as_ptr() as *mut libc::c_char;

    let rc = unsafe { libc::ioctl(fd, SIOCADDRT as IoctlReq, &mut rt as *mut LinuxRtEntry) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        // EEXIST means default route already configured.
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(err);
        }
    }

    Ok(())
}

/// Write `/etc/resolv.conf` pointing at synthetic DNS `198.18.0.53`.
pub fn write_guest_resolv_conf(dns_ip: Ipv4Addr) -> io::Result<()> {
    let _ = std::fs::create_dir_all("/etc");
    std::fs::write("/etc/resolv.conf", format!("nameserver {dns_ip}\n"))
}

fn make_ifreq(name: &str) -> io::Result<libc::ifreq> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid interface name: {name:?}"),
        ));
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in name.as_bytes().iter().enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    Ok(ifr)
}

fn ioctl_ifreq(fd: RawFd, req: u32, ifr: &mut libc::ifreq) -> io::Result<()> {
    let rc = unsafe { libc::ioctl(fd, req as IoctlReq, ifr as *mut libc::ifreq) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ipv4_to_sockaddr(ip: Ipv4Addr) -> libc::sockaddr {
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(ip.octets()),
    };
    unsafe { std::mem::transmute_copy(&sin) }
}
