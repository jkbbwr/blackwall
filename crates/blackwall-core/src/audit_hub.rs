//! Per-sandbox partitioned in-memory ring buffer, proxy rate limiter, and live
//! broadcast hub for Blackwall audit events.
//!
//! [`AuditHub`] implements [`blackwall_audit::AuditSink`] and wraps any downstream
//! sink (such as `JsonlAuditSink` or `MemoryAuditSink`). Events are partitioned by
//! `sandbox_id` (with LRU eviction across sandboxes) so a noisy or compromised VM
//! can never evict sibling sandboxes' audit logs. Proxy-originated events
//! (`AuditOrigin::Proxy`) are additionally protected by a per-sandbox token bucket
//! rate limiter so a flooded proxy cannot DoS [`AuditHub`] or downstream log files.

use blackwall_audit::{AuditError, AuditEvent, AuditEventKind, AuditOrigin, AuditSink};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

/// Legacy default total ring capacity constant (retained for backwards compatibility).
pub const DEFAULT_RING_CAPACITY: usize = 2048;

/// Default bounded event capacity per sandbox partition.
pub const DEFAULT_PER_SANDBOX_CAPACITY: usize = 512;

/// Default maximum number of sandbox partitions retained simultaneously (LRU-evicted).
pub const DEFAULT_MAX_SANDBOXES: usize = 64;

/// Default bounded capacity of the live broadcast channel.
pub const DEFAULT_BROADCAST_CAPACITY: usize = 512;

/// Default burst token capacity for per-sandbox proxy audit rate limiting.
pub const DEFAULT_PROXY_RATE_BURST: f64 = 200.0;

/// Default sustained refill rate (events/sec) for per-sandbox proxy audit rate limiting.
pub const DEFAULT_PROXY_RATE_PER_SEC: f64 = 100.0;

/// Minimum interval between daemon-originated `audit_throttled` warnings per sandbox.
const THROTTLE_WARN_WINDOW: Duration = Duration::from_secs(10);

struct StoredEvent {
    seq: u64,
    event: AuditEvent,
}

struct SandboxRing {
    events: VecDeque<StoredEvent>,
}

struct ProxyRateBucket {
    tokens: f64,
    last_refill: Instant,
    last_throttle_warn: Option<Instant>,
    dropped_since_warn: u64,
}

struct AuditHubState {
    rings: HashMap<String, SandboxRing>,
    /// LRU order of sandbox IDs: front = least recently active, back = most recently active.
    lru: VecDeque<String>,
    next_seq: u64,
    rate_limiters: HashMap<String, ProxyRateBucket>,
}

struct AuditHubInner {
    state: Mutex<AuditHubState>,
    per_sandbox_capacity: usize,
    max_sandboxes: usize,
    proxy_rate_burst: f64,
    proxy_rate_per_sec: f64,
    tx: broadcast::Sender<AuditEvent>,
    downstream: Arc<dyn AuditSink>,
}

/// Thread-safe, clonable audit fan-out hub combining per-sandbox partitioned ring
/// buffers, per-sandbox proxy rate limiting, a live `tokio::sync::broadcast` channel,
/// and a downstream [`AuditSink`].
#[derive(Clone)]
pub struct AuditHub {
    inner: Arc<AuditHubInner>,
}

impl AuditHub {
    /// Construct an [`AuditHub`] with default per-sandbox partitioning (`64` sandboxes,
    /// `512` events/sandbox) and `512` live broadcast capacity.
    pub fn new(downstream: Arc<dyn AuditSink>) -> Self {
        Self::with_limits(
            downstream,
            DEFAULT_PER_SANDBOX_CAPACITY,
            DEFAULT_MAX_SANDBOXES,
            DEFAULT_BROADCAST_CAPACITY,
        )
    }

    /// Construct an [`AuditHub`] with explicit per-sandbox ring buffer and broadcast capacities.
    pub fn with_capacity(
        downstream: Arc<dyn AuditSink>,
        ring_capacity: usize,
        broadcast_capacity: usize,
    ) -> Self {
        Self::with_limits(
            downstream,
            ring_capacity,
            DEFAULT_MAX_SANDBOXES,
            broadcast_capacity,
        )
    }

    /// Construct an [`AuditHub`] with explicit per-sandbox capacity, max tracked
    /// sandboxes (LRU-evicted), and broadcast channel capacity.
    pub fn with_limits(
        downstream: Arc<dyn AuditSink>,
        per_sandbox_capacity: usize,
        max_sandboxes: usize,
        broadcast_capacity: usize,
    ) -> Self {
        let per_sandbox_capacity = per_sandbox_capacity.max(1);
        let max_sandboxes = max_sandboxes.max(1);
        let broadcast_capacity = broadcast_capacity.max(1);
        let (tx, _) = broadcast::channel(broadcast_capacity);
        Self {
            inner: Arc::new(AuditHubInner {
                state: Mutex::new(AuditHubState {
                    rings: HashMap::new(),
                    lru: VecDeque::new(),
                    next_seq: 0,
                    rate_limiters: HashMap::new(),
                }),
                per_sandbox_capacity,
                max_sandboxes,
                proxy_rate_burst: DEFAULT_PROXY_RATE_BURST,
                proxy_rate_per_sec: DEFAULT_PROXY_RATE_PER_SEC,
                tx,
                downstream,
            }),
        }
    }

    /// Return up to `limit` most recent matching events in chronological order
    /// (oldest of the matching tail first, newest last).
    pub fn recent(&self, sandbox_id: Option<&str>, limit: usize) -> Vec<AuditEvent> {
        if limit == 0 {
            return Vec::new();
        }
        let Ok(guard) = self.inner.state.lock() else {
            return Vec::new();
        };
        collect_recent(&guard, sandbox_id, limit)
    }

    /// Subscribe to live [`AuditEvent`]s recorded after this call.
    pub fn subscribe(&self) -> broadcast::Receiver<AuditEvent> {
        self.inner.tx.subscribe()
    }

    /// Atomically snapshot up to `limit` recent matching events AND subscribe to
    /// subsequent live events under the ring buffer lock so no event is missed or
    /// duplicated across the boundary.
    pub fn recent_and_subscribe(
        &self,
        sandbox_id: Option<&str>,
        limit: usize,
    ) -> (Vec<AuditEvent>, broadcast::Receiver<AuditEvent>) {
        if let Ok(guard) = self.inner.state.lock() {
            let rx = self.inner.tx.subscribe();
            let recent = if limit == 0 {
                Vec::new()
            } else {
                collect_recent(&guard, sandbox_id, limit)
            };
            (recent, rx)
        } else {
            (Vec::new(), self.inner.tx.subscribe())
        }
    }
}

fn collect_recent(
    state: &AuditHubState,
    sandbox_id: Option<&str>,
    limit: usize,
) -> Vec<AuditEvent> {
    match sandbox_id {
        Some(id) => {
            let Some(ring) = state.rings.get(id) else {
                return Vec::new();
            };
            let start = ring.events.len().saturating_sub(limit);
            ring.events
                .iter()
                .skip(start)
                .map(|stored| stored.event.clone())
                .collect()
        }
        None => {
            let mut all: Vec<&StoredEvent> = state
                .rings
                .values()
                .flat_map(|ring| ring.events.iter())
                .collect();
            all.sort_by_key(|stored| (stored.event.timestamp_ms, stored.seq));
            let start = all.len().saturating_sub(limit);
            all[start..]
                .iter()
                .map(|stored| stored.event.clone())
                .collect()
        }
    }
}

fn push_event_locked(
    state: &mut AuditHubState,
    per_sandbox_capacity: usize,
    max_sandboxes: usize,
    event: AuditEvent,
) {
    let seq = state.next_seq;
    state.next_seq = state.next_seq.saturating_add(1);

    let sid = event.sandbox_id.clone();
    if let Some(ring) = state.rings.get_mut(&sid) {
        if ring.events.len() >= per_sandbox_capacity {
            ring.events.pop_front();
        }
        ring.events.push_back(StoredEvent { seq, event });
        if let Some(pos) = state.lru.iter().position(|existing| existing == &sid) {
            state.lru.remove(pos);
        }
        state.lru.push_back(sid);
    } else {
        while state.rings.len() >= max_sandboxes {
            let Some(evicted_id) = state.lru.pop_front() else {
                break;
            };
            state.rings.remove(&evicted_id);
            state.rate_limiters.remove(&evicted_id);
        }
        let mut events = VecDeque::with_capacity(per_sandbox_capacity.min(64));
        events.push_back(StoredEvent { seq, event });
        state.rings.insert(sid.clone(), SandboxRing { events });
        state.lru.push_back(sid);
    }
}

enum RateDecision {
    Allow,
    Drop,
    ThrottleWarn(AuditEvent),
}

fn check_proxy_rate_limit(
    state: &mut AuditHubState,
    sandbox_id: &str,
    burst: f64,
    refill_per_sec: f64,
) -> RateDecision {
    let now = Instant::now();
    let bucket = state
        .rate_limiters
        .entry(sandbox_id.to_string())
        .or_insert_with(|| ProxyRateBucket {
            tokens: burst,
            last_refill: now,
            last_throttle_warn: None,
            dropped_since_warn: 0,
        });

    let elapsed = now
        .saturating_duration_since(bucket.last_refill)
        .as_secs_f64();
    if elapsed > 0.0 {
        bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(burst);
        bucket.last_refill = now;
    }

    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        return RateDecision::Allow;
    }

    bucket.dropped_since_warn = bucket.dropped_since_warn.saturating_add(1);
    let should_warn = match bucket.last_throttle_warn {
        None => true,
        Some(prev) => now.saturating_duration_since(prev) >= THROTTLE_WARN_WINDOW,
    };

    if should_warn {
        bucket.last_throttle_warn = Some(now);
        let dropped = bucket.dropped_since_warn;
        bucket.dropped_since_warn = 0;
        let warn = AuditEvent::now(
            sandbox_id.to_string(),
            AuditEventKind::SandboxLifecycle {
                phase: "audit_throttled".into(),
                image_roothash: None,
                details: Some(format!(
                    "proxy audit rate limit exceeded (dropped {dropped} event(s))"
                )),
            },
        )
        .with_origin(AuditOrigin::Daemon);
        RateDecision::ThrottleWarn(warn)
    } else {
        RateDecision::Drop
    }
}

impl AuditSink for AuditHub {
    fn record(&self, event: AuditEvent) {
        let to_forward: Option<AuditEvent> = {
            if let Ok(mut guard) = self.inner.state.lock() {
                if event.origin == AuditOrigin::Proxy {
                    match check_proxy_rate_limit(
                        &mut guard,
                        &event.sandbox_id,
                        self.inner.proxy_rate_burst,
                        self.inner.proxy_rate_per_sec,
                    ) {
                        RateDecision::Allow => {
                            push_event_locked(
                                &mut guard,
                                self.inner.per_sandbox_capacity,
                                self.inner.max_sandboxes,
                                event.clone(),
                            );
                            let _ = self.inner.tx.send(event.clone());
                            Some(event)
                        }
                        RateDecision::ThrottleWarn(warn_ev) => {
                            push_event_locked(
                                &mut guard,
                                self.inner.per_sandbox_capacity,
                                self.inner.max_sandboxes,
                                warn_ev.clone(),
                            );
                            let _ = self.inner.tx.send(warn_ev.clone());
                            Some(warn_ev)
                        }
                        RateDecision::Drop => None,
                    }
                } else {
                    push_event_locked(
                        &mut guard,
                        self.inner.per_sandbox_capacity,
                        self.inner.max_sandboxes,
                        event.clone(),
                    );
                    let _ = self.inner.tx.send(event.clone());
                    Some(event)
                }
            } else {
                let _ = self.inner.tx.send(event.clone());
                Some(event)
            }
        };

        if let Some(ev) = to_forward {
            self.inner.downstream.record(ev);
        }
    }

    fn flush(&self) -> Result<(), AuditError> {
        self.inner.downstream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_audit::{AuditEventKind, MemoryAuditSink};

    fn dns_event(sandbox_id: &str, fqdn: &str, allowed: bool) -> AuditEvent {
        AuditEvent::now(
            sandbox_id,
            AuditEventKind::DnsQuery {
                fqdn: fqdn.into(),
                allowed,
                synthetic_ip: if allowed {
                    Some("198.18.1.2".into())
                } else {
                    None
                },
            },
        )
    }

    fn proxy_dns_event(sandbox_id: &str, fqdn: &str, allowed: bool) -> AuditEvent {
        dns_event(sandbox_id, fqdn, allowed).with_origin(AuditOrigin::Proxy)
    }

    #[test]
    fn ring_buffer_bounds_filters_and_forwards_to_downstream() {
        let downstream = Arc::new(MemoryAuditSink::new());
        let hub = AuditHub::with_capacity(downstream.clone(), 3, 16);

        // 4 events in sb-1 (exceeds per-sandbox cap of 3 -> oldest "a.example" evicted)
        // plus 2 events in sb-2 (kept intact in its own partition).
        let mut e1 = dns_event("sb-1", "a.example", true);
        e1.timestamp_ms = 100;
        let mut e2 = dns_event("sb-2", "b.example", false);
        e2.timestamp_ms = 101;
        let mut e3 = dns_event("sb-1", "c.example", true);
        e3.timestamp_ms = 102;
        let mut e4 = dns_event("sb-2", "d.example", true);
        e4.timestamp_ms = 103;
        let mut e5 = dns_event("sb-1", "e.example", false);
        e5.timestamp_ms = 104;
        let mut e6 = dns_event("sb-1", "f.example", true);
        e6.timestamp_ms = 105;

        for ev in [e1, e2, e3, e4, e5, e6] {
            hub.record(ev);
        }

        // Downstream received all 6 events.
        assert_eq!(downstream.snapshot().len(), 6);

        // Global view merges all partitions sorted by (timestamp_ms, seq).
        let all = hub.recent(None, 10);
        let fqdns: Vec<&str> = all
            .iter()
            .map(|e| match &e.kind {
                AuditEventKind::DnsQuery { fqdn, .. } => fqdn.as_str(),
                _ => "",
            })
            .collect();
        assert_eq!(
            fqdns,
            vec!["b.example", "c.example", "d.example", "e.example", "f.example"]
        );

        // Global limit takes the newest N in chronological order.
        let last_two = hub.recent(None, 2);
        let last_two_fqdns: Vec<&str> = last_two
            .iter()
            .map(|e| match &e.kind {
                AuditEventKind::DnsQuery { fqdn, .. } => fqdn.as_str(),
                _ => "",
            })
            .collect();
        assert_eq!(last_two_fqdns, vec!["e.example", "f.example"]);

        // Per-sandbox filter + limit returns most recent matching tail in chronological order.
        let sb1_all = hub.recent(Some("sb-1"), 10);
        assert_eq!(sb1_all.len(), 3);
        let sb1_one = hub.recent(Some("sb-1"), 1);
        assert_eq!(sb1_one.len(), 1);
        assert!(matches!(
            &sb1_one[0].kind,
            AuditEventKind::DnsQuery { fqdn, allowed: true, .. } if fqdn == "f.example"
        ));
    }

    #[test]
    fn per_sandbox_ring_isolation_prevents_noisy_neighbor_eviction() {
        let downstream = Arc::new(MemoryAuditSink::new());
        let hub = AuditHub::new(downstream);

        // Record 5 events for victim sandbox B.
        for i in 0..5 {
            hub.record(dns_event("sb-victim", &format!("victim-{i}.example"), true));
        }

        // Flood noisy sandbox A with 1000 daemon events (well above per-sandbox cap 512).
        for i in 0..1000 {
            hub.record(dns_event("sb-noisy", &format!("noisy-{i}.example"), false));
        }

        // Sandbox B's 5 events MUST ALL STILL BE INTACT!
        let victim_events = hub.recent(Some("sb-victim"), 100);
        assert_eq!(
            victim_events.len(),
            5,
            "flooding sb-noisy must NEVER evict sb-victim's audit events"
        );
        for (i, ev) in victim_events.iter().enumerate() {
            assert_eq!(ev.sandbox_id, "sb-victim");
            assert!(matches!(
                &ev.kind,
                AuditEventKind::DnsQuery { fqdn, .. } if fqdn == &format!("victim-{i}.example")
            ));
        }

        // Sandbox A is capped at DEFAULT_PER_SANDBOX_CAPACITY (512), holding the newest tail.
        let noisy_events = hub.recent(Some("sb-noisy"), 1000);
        assert_eq!(noisy_events.len(), DEFAULT_PER_SANDBOX_CAPACITY);
        assert!(matches!(
            &noisy_events.last().unwrap().kind,
            AuditEventKind::DnsQuery { fqdn, .. } if fqdn == "noisy-999.example"
        ));
    }

    #[test]
    fn lru_evicts_least_recently_active_sandbox_when_exceeding_max_sandboxes() {
        let downstream = Arc::new(MemoryAuditSink::new());
        let hub = AuditHub::with_limits(downstream, 8, 2, 16);

        hub.record(dns_event("sb-1", "one.example", true));
        hub.record(dns_event("sb-2", "two.example", true));
        // Touch sb-1 so sb-2 becomes LRU.
        hub.record(dns_event("sb-1", "one-again.example", true));
        // Introducing sb-3 evicts sb-2, keeping sb-1 and sb-3.
        hub.record(dns_event("sb-3", "three.example", true));

        assert_eq!(hub.recent(Some("sb-1"), 10).len(), 2);
        assert_eq!(hub.recent(Some("sb-2"), 10).len(), 0);
        assert_eq!(hub.recent(Some("sb-3"), 10).len(), 1);
    }

    #[test]
    fn proxy_rate_limiter_caps_burst_floods_and_emits_single_daemon_warning() {
        let downstream = Arc::new(MemoryAuditSink::new());
        let hub = AuditHub::new(downstream.clone());

        // Burst-flood 1000 proxy-originated events from a compromised proxy.
        for i in 0..1000 {
            hub.record(proxy_dns_event(
                "sb-flood",
                &format!("flood-{i}.example"),
                false,
            ));
        }

        // Sibling sandbox proxy must NOT be affected by sb-flood's rate limiter!
        hub.record(proxy_dns_event("sb-clean", "ok.example", true));
        assert_eq!(hub.recent(Some("sb-clean"), 10).len(), 1);

        let flood_ring = hub.recent(Some("sb-flood"), 1000);
        let flood_downstream: Vec<AuditEvent> = downstream
            .snapshot()
            .into_iter()
            .filter(|e| e.sandbox_id == "sb-flood")
            .collect();

        // Must have capped proxy events well below 1000 (burst=200 + at most a tiny refill + 1 warn).
        let proxy_count = flood_ring
            .iter()
            .filter(|e| e.origin == AuditOrigin::Proxy)
            .count();
        assert!(
            (200..=220).contains(&proxy_count),
            "expected ~200 proxy events allowed in burst, got {proxy_count}"
        );

        // Exactly 1 daemon-originated `audit_throttled` warning in the throttle window.
        let warnings: Vec<&AuditEvent> = flood_ring
            .iter()
            .filter(|e| {
                e.origin == AuditOrigin::Daemon
                    && matches!(
                        &e.kind,
                        AuditEventKind::SandboxLifecycle { phase, .. } if phase == "audit_throttled"
                    )
            })
            .collect();
        assert_eq!(
            warnings.len(),
            1,
            "expected exactly 1 daemon audit_throttled warning per throttle window"
        );

        // Downstream sink (e.g. JSONL file) was ALSO protected from the flood!
        assert_eq!(flood_downstream.len(), flood_ring.len());
    }

    #[tokio::test]
    async fn recent_and_subscribe_has_no_gaps_or_duplicates() {
        let downstream = Arc::new(MemoryAuditSink::new());
        let hub = AuditHub::new(downstream);

        hub.record(dns_event("sb-1", "before.example", true));
        let (recent, mut rx) = hub.recent_and_subscribe(Some("sb-1"), 10);
        assert_eq!(recent.len(), 1);
        assert!(matches!(
            &recent[0].kind,
            AuditEventKind::DnsQuery { fqdn, .. } if fqdn == "before.example"
        ));

        hub.record(dns_event("sb-1", "after.example", false));
        let live = rx.recv().await.unwrap();
        assert!(matches!(
            &live.kind,
            AuditEventKind::DnsQuery { fqdn, allowed: false, .. } if fqdn == "after.example"
        ));
    }
}
