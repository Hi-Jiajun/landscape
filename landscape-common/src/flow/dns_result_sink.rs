use crate::flow::{FlowMarkInfo, error::DnsMarkInstallError};

/// Side effects applied to DNS resolution results.
///
/// The DNS layer resolves a query, produces a set of (ip, mark) pairs and hands
/// them here. The concrete implementation decides how (and whether) to make
/// them take effect in the datapath: today that's eBPF maps and route caches,
/// any other backend (userspace routing, DPDK, TC, ...) can plug in later.
pub trait DnsResultSink: Send + Sync {
    /// Write (ip, mark) pairs for a freshly resolved answer.
    ///
    /// Failing here is a security event, not a bookkeeping problem: the marks
    /// are what keeps a proxied or blocked address from being sent out natively
    /// by a device whose own flow is direct. The caller decides what to do with
    /// the client answer, but it must not treat an error as "no marks needed".
    ///
    /// `generation` is the rule generation the answer was produced under. A
    /// query that started before a rule change keeps the snapshot it began with,
    /// so it can finish after the rebuild has already published the new table;
    /// without the stamp its mark would silently re-apply the old rules.
    fn record_dns_answer(
        &self,
        flow_id: u32,
        generation: u64,
        marks: Vec<FlowMarkInfo>,
    ) -> Result<(), DnsMarkInstallError>;

    /// Recompute the DNS mark table for a flow from its whole cache.
    ///
    /// This is the authoritative writer: it runs after a rule change and derives
    /// every mark from the whole cache, so its generation is the one later
    /// incremental answers are compared against.
    fn refresh_dns_marks(&self, flow_id: u32, generation: u64, marks: Vec<FlowMarkInfo>);

    /// Rebuild the LAN route cache.
    fn rebuild_route_cache(&self);
}

/// No-op sink used by tests and non-Linux builds.
pub struct NoopDnsResultSink;

impl DnsResultSink for NoopDnsResultSink {
    fn record_dns_answer(
        &self,
        _flow_id: u32,
        _generation: u64,
        _marks: Vec<FlowMarkInfo>,
    ) -> Result<(), DnsMarkInstallError> {
        Ok(())
    }

    fn refresh_dns_marks(&self, _flow_id: u32, _generation: u64, _marks: Vec<FlowMarkInfo>) {}

    fn rebuild_route_cache(&self) {}
}
