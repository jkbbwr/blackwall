//! `blackwall-init` — Static `musl` guest initramfs PID 1 & Port 1002 session daemon.
//!
//! Exposed as a library crate alongside `main.rs` so host unit and integration
//! tests can exercise Device Mapper table builders, PTY helpers, confined file
//! transfers, and the full Port 1002 session protocol over a Unix `socketpair`.

pub mod dm;
pub mod files;
pub mod pty;
pub mod session;
pub mod vsock;
