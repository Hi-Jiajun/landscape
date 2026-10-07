//! Datapath capability for the managed-DNS guard.
//!
//! The guard has two halves and both are required. Netfilter can only rule on a
//! packet that reaches it, and on this router a direct flow never does: the TC
//! chain forwards it with `bpf_redirect` before netfilter runs. So the decision
//! is taken in the datapath, and netfilter is what the packet is handed to.

use crate::proxy::{DnsGuardCounters, DnsGuardExempt};

/// What the guard should be, in full.
///
/// Declared state rather than a delta: applying the same specification twice
/// must be a no-op, and removing an entry from the lists must remove it from
/// the kernel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsGuardSpec {
    pub enabled: bool,
    /// Hijack plaintext DNS over TCP as well as over UDP. Only meaningful once the
    /// managed resolver serves TCP; see the switch's documentation in
    /// `bpf/dns_guard/dns_guard.h`.
    pub plaintext_tcp: bool,
    /// Refuse fragments that cannot be classified.
    pub drop_fragments: bool,
    /// Refuse packets whose header chain cannot be parsed.
    pub drop_unclassified: bool,
    /// DoH endpoints to refuse, by address.
    pub doh_block: Vec<std::net::IpAddr>,
    /// Trusted hosts and the one service each may keep using.
    pub exempt: Vec<DnsGuardExempt>,
}

/// eBPF capability for the managed-DNS guard.
pub trait DnsGuardDataplane: Send + Sync {
    /// Reconcile the datapath to `spec`.
    fn apply(&self, spec: &DnsGuardSpec) -> Result<(), String>;

    /// Read the per-packet counters. `None` when the datapath maps are not
    /// available, which is itself worth reporting rather than showing zeros.
    fn counters(&self) -> Result<DnsGuardCounters, String>;
}

/// No-op implementation for tests and for builds without the datapath.
pub struct NoopDnsGuardDataplane;

impl DnsGuardDataplane for NoopDnsGuardDataplane {
    fn apply(&self, _spec: &DnsGuardSpec) -> Result<(), String> {
        Ok(())
    }

    fn counters(&self) -> Result<DnsGuardCounters, String> {
        Ok(DnsGuardCounters::default())
    }
}
