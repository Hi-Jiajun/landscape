//! eBPF capability for the chamber.

use crate::ebpf::DataplaneGuard;
use crate::wan_service::mtu_chamber::{MtuChamberStats, MtuChamberWiring};

pub trait MtuChamberDataplane: Send + Sync {
    /// Attach the egress MTU stage to a WAN interface's chain.
    ///
    /// This is the stage that counts what the egress cannot carry and hands the
    /// IPv6 case to the chamber. It sits after the firewall, so a packet it acts
    /// on was already allowed out. Dropping the guard removes the stage.
    fn attach_stage(
        &self,
        ifindex: u32,
        mtu: u16,
        has_mac: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String>;

    /// Attach the return gate to the chamber's veth and enable the divert.
    ///
    /// The order is the caller's and it matters: the gate has to be attached
    /// before the datapath is told to send anything at it. Dropping the guard
    /// disables the divert first, so the divert can never outlive the gate that
    /// validates what comes back.
    fn attach_return_gate(
        &self,
        veth_ifindex: u32,
        wiring: MtuChamberWiring,
    ) -> Result<Box<dyn DataplaneGuard>, String>;

    fn stats(&self) -> Result<MtuChamberStats, String>;

    /// Admissions still waiting for an error to answer them.
    fn pending(&self) -> Result<u64, String>;

    /// What the datapath was last told, which is the only trustworthy answer to
    /// "is the divert on, and to where".
    fn wiring(&self) -> Result<MtuChamberWiring, String>;
}

/// No-op implementation for tests and for a build without eBPF.
pub struct NoopMtuChamberDataplane;

impl MtuChamberDataplane for NoopMtuChamberDataplane {
    fn attach_stage(
        &self,
        _ifindex: u32,
        _mtu: u16,
        _has_mac: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }

    fn attach_return_gate(
        &self,
        _veth_ifindex: u32,
        _wiring: MtuChamberWiring,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }

    fn stats(&self) -> Result<MtuChamberStats, String> {
        Ok(MtuChamberStats::default())
    }

    fn pending(&self) -> Result<u64, String> {
        Ok(0)
    }

    fn wiring(&self) -> Result<MtuChamberWiring, String> {
        Ok(MtuChamberWiring::default())
    }
}
