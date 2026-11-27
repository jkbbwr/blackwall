//! `blackwall-netbridge` — Static `musl` userspace `tun0` + `smoltcp` TCP/UDP/DNS
//! bridge multiplexing guest egress traffic over `AF_VSOCK` Port `1000` (`NET_MUX`).

pub mod bridge;
pub mod dns;
pub mod tun;
