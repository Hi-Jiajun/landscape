//! MSS clamp dataplane: attach the TC/XDP MSS-clamp stage.

use crate::ebpf::DataplaneGuard;
use crate::wan_service::mss_clamp::MtuGuardStats;

/// eBPF capability for the MSS clamp service.
pub trait MssClampDataplane: Send + Sync {
    /// Attach the MSS-clamp stage (TC ingress/egress + XDP LAN/WAN) for
    /// `ifindex`, advertising `mtu` sized segments.  Dropping the
    /// returned guard removes the stage from the chains.
    fn attach(
        &self,
        ifindex: u32,
        mtu: u16,
        has_mac: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String>;

    /// What the egress saw of packets it could not carry.
    ///
    /// The counter belongs to the MSS stage because that stage is the one place
    /// every outbound packet passes and the one place the egress MTU is known.
    fn mtu_stats(&self) -> Result<MtuGuardStats, String>;
}

/// No-op implementation for tests.
pub struct NoopMssClampDataplane;

impl MssClampDataplane for NoopMssClampDataplane {
    fn attach(
        &self,
        _ifindex: u32,
        _mtu: u16,
        _has_mac: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }

    fn mtu_stats(&self) -> Result<MtuGuardStats, String> {
        Ok(MtuGuardStats::default())
    }
}
