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

    /// Recompute the DNS mark table for a flow, deriving the marks from the whole
    /// cache with `collect`.
    ///
    /// This is the authoritative writer: it runs after a rule change, and its
    /// generation is the one later incremental answers are compared against.
    ///
    /// `collect` is called **while the datapath write is held**, which is the
    /// point of passing a closure instead of a finished list. A caller that
    /// collected the marks first would take a snapshot of the cache and publish
    /// it later, so an answer that finished in between — installed its marks and
    /// cached itself, both successfully — would be erased by the older list, and
    /// the address the client was just handed would lose its mark.
    ///
    /// Returns an error when the rebuilt table could not be installed. The caller
    /// must then keep the previous rules rather than adopt the new ones: the
    /// rules and the table have to describe the same configuration.
    fn refresh_dns_marks<'a>(
        &self,
        flow_id: u32,
        generation: u64,
        collect: Box<dyn FnOnce() -> Vec<FlowMarkInfo> + Send + 'a>,
    ) -> Result<(), DnsMarkInstallError>;

    /// Install marks only for addresses the table has no entry for.
    ///
    /// Called after an answer has become visible in the cache. Installing the
    /// marks and caching the answer cannot be one atomic step from the DNS side —
    /// the install takes the datapath write and the cache commit is an `await` —
    /// so a rebuild can collect the cache in between and publish a table derived
    /// from an answer it could not see yet, deleting that answer's marks. This
    /// fills exactly those holes.
    ///
    /// It never replaces an entry that exists: a rebuild resolves a shared
    /// address over the whole cache and may have decided to block it, and one
    /// answer's marks must not weaken that decision.
    fn ensure_dns_marks(
        &self,
        flow_id: u32,
        generation: u64,
        marks: Vec<FlowMarkInfo>,
    ) -> Result<(), DnsMarkInstallError>;

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

    fn refresh_dns_marks<'a>(
        &self,
        _flow_id: u32,
        _generation: u64,
        collect: Box<dyn FnOnce() -> Vec<FlowMarkInfo> + Send + 'a>,
    ) -> Result<(), DnsMarkInstallError> {
        let _ = collect();
        Ok(())
    }

    fn ensure_dns_marks(
        &self,
        _flow_id: u32,
        _generation: u64,
        _marks: Vec<FlowMarkInfo>,
    ) -> Result<(), DnsMarkInstallError> {
        Ok(())
    }

    fn rebuild_route_cache(&self) {}
}
