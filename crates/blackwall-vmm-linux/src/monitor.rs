//! Deterministic fatal-exit monitoring for `cloud-hypervisor` VMM instances.
//!
//! Captures bounded stderr/console output from the VMM child process and inspects
//! both the exit status and hypervisor/guest output for fatal traps:
//! - `KVM_EXIT_INTERNAL_ERROR`
//! - `KVM_EXIT_UNKNOWN`
//! - Guest `Kernel panic` / `Oops:` / `BUG:` / `pvpanic`
//! - Triple fault / unexpected unhandled MMIO exits
//! - Unexpected signal termination or non-zero exit when not host-killed
//!
//! On any fatal exit, emits a single `AuditEventKind::VmmFatalExit` event to the
//! configured `AuditSink`.

use blackwall_audit::{AuditEvent, AuditEventKind, AuditSink};
use blackwall_vmm::VmExitStatus;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;

const MAX_CAPTURED_LOG_BYTES: usize = 64 * 1024;

/// Fatal hypervisor / guest trap signatures scanned in VMM stderr & console logs.
const FATAL_SIGNATURES: &[(&str, &str)] = &[
    ("KVM_EXIT_INTERNAL_ERROR", "kvm_exit_internal_error"),
    ("KVM_EXIT_UNKNOWN", "kvm_exit_unknown"),
    ("Kernel panic", "guest_kernel_panic"),
    ("kernel panic", "guest_kernel_panic"),
    ("not syncing:", "guest_kernel_panic"),
    ("pvpanic", "guest_pvpanic"),
    ("Guest panicked", "guest_pvpanic"),
    ("triple fault", "guest_triple_fault"),
    ("Triple fault", "guest_triple_fault"),
    ("unhandled MMIO", "unhandled_mmio"),
    ("UnhandledMmio", "unhandled_mmio"),
    ("Oops:", "guest_kernel_oops"),
    ("BUG:", "guest_kernel_bug"),
];

/// Inspect VMM exit status and captured console/stderr output to determine whether
/// termination represents a deterministic fatal hypervisor or guest trap.
pub fn classify_vmm_exit(
    status: ExitStatus,
    captured_log: &str,
    host_initiated_kill: bool,
) -> VmExitStatus {
    let code = status.code();
    let signal = status.signal();

    // Check captured VMM/guest logs first—even if the VMM exited cleanly after
    // `oops=panic panic=-1` + `--guest-reset-action exit-vmm`, a kernel panic
    // or KVM_EXIT_* signature MUST be classified as fatal.
    if let Some((reason, matched_line)) = detect_fatal_signature(captured_log) {
        return VmExitStatus {
            code,
            signal,
            fatal: true,
            detail: Some(format!("{reason}: {matched_line}")),
        };
    }

    if host_initiated_kill {
        return VmExitStatus {
            code,
            signal,
            fatal: false,
            detail: Some("terminated by host".into()),
        };
    }

    if let Some(sig) = signal {
        return VmExitStatus {
            code,
            signal: Some(sig),
            fatal: true,
            detail: Some(format!("vmm_killed_by_signal: signal {sig}")),
        };
    }

    if let Some(exit_code) = code {
        if exit_code != 0 {
            let tail = tail_non_empty_line(captured_log)
                .unwrap_or("non-zero VMM exit without console output");
            return VmExitStatus {
                code: Some(exit_code),
                signal: None,
                fatal: true,
                detail: Some(format!("vmm_nonzero_exit({exit_code}): {tail}")),
            };
        }
    }

    VmExitStatus {
        code,
        signal,
        fatal: false,
        detail: None,
    }
}

/// Scan captured VMM stderr / console output for known fatal signatures.
pub fn detect_fatal_signature(log: &str) -> Option<(&'static str, String)> {
    for line in log.lines() {
        for (needle, reason) in FATAL_SIGNATURES {
            if line.contains(needle) {
                return Some((*reason, line.trim().to_string()));
            }
        }
    }
    None
}

fn tail_non_empty_line(log: &str) -> Option<&str> {
    log.lines().rev().map(str::trim).find(|l| !l.is_empty())
}

/// Shared bounded log capture + once-only `VmmFatalExit` audit emitter.
pub struct VmmMonitorState {
    sandbox_id: String,
    audit_sink: Arc<dyn AuditSink>,
    captured_log: Mutex<String>,
    host_killed: AtomicBool,
    fatal_emitted: AtomicBool,
}

impl VmmMonitorState {
    pub fn new(sandbox_id: String, audit_sink: Arc<dyn AuditSink>) -> Arc<Self> {
        Arc::new(Self {
            sandbox_id,
            audit_sink,
            captured_log: Mutex::new(String::new()),
            host_killed: AtomicBool::new(false),
            fatal_emitted: AtomicBool::new(false),
        })
    }

    /// Spawn a lightweight background thread draining a VMM stdout/stderr pipe
    /// into the bounded capture buffer and immediately emitting `VmmFatalExit`
    /// if a fatal trap signature appears in real time.
    pub fn spawn_stream_watcher<R: Read + Send + 'static>(
        self: &Arc<Self>,
        stream: R,
        stream_name: &'static str,
    ) -> thread::JoinHandle<()> {
        let state = Arc::clone(self);
        thread::Builder::new()
            .name(format!("bw-vmm-{stream_name}-{}", state.sandbox_id))
            .spawn(move || {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(_) => {
                            state.append_line(&line);
                            if let Some((reason, detail)) = detect_fatal_signature(&line) {
                                state.emit_fatal_once(reason, detail);
                            }
                        }
                        Err(_) => break,
                    }
                }
            })
            .expect("spawn VMM stream watcher thread")
    }

    pub fn mark_host_killed(&self) {
        self.host_killed.store(true, Ordering::SeqCst);
    }

    pub fn is_host_killed(&self) -> bool {
        self.host_killed.load(Ordering::SeqCst)
    }

    pub fn captured_log(&self) -> String {
        self.captured_log
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Classify `status`, emit `AuditEventKind::VmmFatalExit` if fatal (at most once),
    /// and return the structured `VmExitStatus`.
    pub fn record_exit(&self, status: ExitStatus) -> VmExitStatus {
        let log = self.captured_log();
        let classified = classify_vmm_exit(status, &log, self.is_host_killed());
        if classified.fatal {
            let detail = classified
                .detail
                .clone()
                .unwrap_or_else(|| "fatal VMM exit".into());
            let reason = detail
                .split(':')
                .next()
                .unwrap_or("vmm_fatal_exit")
                .to_string();
            self.emit_fatal_once(&reason, detail);
        }
        classified
    }

    fn append_line(&self, line: &str) {
        if let Ok(mut buf) = self.captured_log.lock() {
            if buf.len() + line.len() > MAX_CAPTURED_LOG_BYTES {
                let drop_len = (buf.len() + line.len() - MAX_CAPTURED_LOG_BYTES).min(buf.len());
                // Find a valid UTF-8 char boundary >= drop_len.
                let mut cut = drop_len;
                while cut < buf.len() && !buf.is_char_boundary(cut) {
                    cut += 1;
                }
                buf.drain(..cut);
            }
            buf.push_str(line);
        }
    }

    fn emit_fatal_once(&self, reason: &str, exit_detail: String) {
        if !self.fatal_emitted.swap(true, Ordering::SeqCst) {
            tracing::error!(
                sandbox_id = %self.sandbox_id,
                reason,
                detail = %exit_detail,
                "deterministic VMM fatal exit detected"
            );
            self.audit_sink.record(AuditEvent::now(
                &self.sandbox_id,
                AuditEventKind::VmmFatalExit {
                    reason: reason.to_string(),
                    exit_detail,
                },
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_audit::MemoryAuditSink;
    use std::io::Cursor;

    #[test]
    fn watcher_detects_kvm_exit_internal_error_and_emits_audit_event_once() {
        let sink = Arc::new(MemoryAuditSink::new());
        let state = VmmMonitorState::new("sb-fatal-1".into(), sink.clone());

        let log_data = b"booting vmlinux-lo...\ncloud-hypervisor: ERROR KVM_EXIT_INTERNAL_ERROR suberror=1\nKernel panic - not syncing: Attempted to kill init!\n";
        let handle = state.spawn_stream_watcher(Cursor::new(log_data.to_vec()), "stderr");
        handle.join().unwrap();

        // Simulate exit status 1 and call record_exit; event must still be emitted only once.
        let status = ExitStatus::from_raw(1 << 8);
        let vm_exit = state.record_exit(status);
        assert!(vm_exit.fatal);
        assert!(vm_exit
            .detail
            .as_deref()
            .unwrap()
            .contains("kvm_exit_internal_error"));

        let events = sink.snapshot();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sandbox_id, "sb-fatal-1");
        assert!(matches!(
            &events[0].kind,
            AuditEventKind::VmmFatalExit { reason, .. } if reason == "kvm_exit_internal_error"
        ));
    }

    #[test]
    fn host_initiated_kill_without_trap_is_not_classified_fatal() {
        let sink = Arc::new(MemoryAuditSink::new());
        let state = VmmMonitorState::new("sb-clean-kill".into(), sink.clone());
        state.mark_host_killed();

        let status = ExitStatus::from_raw(libc::SIGKILL);
        let vm_exit = state.record_exit(status);
        assert!(!vm_exit.fatal);
        assert_eq!(vm_exit.signal, Some(libc::SIGKILL));
        assert!(sink.snapshot().is_empty());
    }
}
