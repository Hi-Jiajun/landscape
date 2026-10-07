//! Attach the egress MTU stage and the chamber's return gate.
//!
//! Two programs with two lifetimes:
//!
//! * the egress stage belongs to a WAN interface and follows its chain. It counts
//!   what that egress cannot carry, for both families, and hands the IPv6 case to
//!   the chamber when there is one;
//! * the return gate belongs to the chamber's veth and exists only while the
//!   chamber does.
//!
//! The wiring in `mtu_chamber_cfg_map` is the switch between them, and it is
//! written last: until the gate is attached and the chamber is verified, the
//! datapath has no target to divert to and keeps behaving exactly as before.

use std::sync::Arc;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::{OwnedOpenObject, TcHookProxy, pin_and_reuse_map};
use crate::runtime::EbpfRuntime;

use landscape_common::ebpf::DataplaneGuard;
use landscape_common::wan_service::mtu_chamber::MtuChamberWiring;

pub(crate) mod tc_mtu_chamber_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_mtu_chamber.skel.rs"));
}

pub(crate) mod tc_mtu_chamber_return_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_mtu_chamber_return.skel.rs"));
}

// ========================================================================
// Egress MTU stage (part of a WAN interface's egress chain)
// ========================================================================

pub struct TcMtuChamberStageHandle {
    runtime: Arc<EbpfRuntime>,
    _skel: tc_mtu_chamber_skel::TcMtuChamberSkel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
    ifindex: u32,
}

impl DataplaneGuard for TcMtuChamberStageHandle {}

impl Drop for TcMtuChamberStageHandle {
    fn drop(&mut self) {
        use crate::chain::tc_manager::StageType;
        let _ = self.runtime.tc.remove(self.ifindex, StageType::EgressMtu);
    }
}

pub fn attach_tc_mtu_chamber_stage(
    rt: &Arc<EbpfRuntime>,
    ifindex: u32,
    mtu: u16,
    has_mac: bool,
) -> LdEbpfResult<TcMtuChamberStageHandle> {
    use crate::chain::tc_manager::{StageEntry, StageType};
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    let paths = &rt.paths;
    rt.tc.ensure_roots(ifindex, has_mac)?;

    let builder = tc_mtu_chamber_skel::TcMtuChamberSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_mtu_chamber skeleton")?;

    {
        let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
        rodata.mtu_size = mtu;
        rodata.current_l3_offset = if has_mac { 14 } else { 0 };
    }

    // Every map this skeleton shares with the rest of the daemon has to be
    // pinned here too. Left alone, libbpf would pin a second map of the same
    // name at the bpffs root and this program would read a config nobody writes
    // - which is the failure `maps/pin_coverage.rs` exists to catch.
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.mtu_guard_stats_map, &paths.mtu_guard_stats),
        "mtu chamber stage pin mtu_guard_stats_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.mtu_chamber_cfg_map, &paths.mtu_chamber_cfg),
        "mtu chamber stage pin mtu_chamber_cfg_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.mtu_chamber_stats_map, &paths.mtu_chamber_stats),
        "mtu chamber stage pin mtu_chamber_stats_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.mtu_chamber_state_map, &paths.mtu_chamber_state),
        "mtu chamber stage pin mtu_chamber_state_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.mtu_chamber_budget_map, &paths.mtu_chamber_budget),
        "mtu chamber stage pin mtu_chamber_budget_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v6, &paths.ip_mac_v6),
        "mtu chamber stage pin ip_mac_v6"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.tc_pipe_exits_wan_ingress,
            &paths.tc_pipe_exits_wan_ingress_path(),
        ),
        "mtu chamber stage pin tc_pipe_exits_wan_ingress"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.tc_pipe_exits_wan_egress,
            &paths.tc_pipe_exits_wan_egress_path(),
        ),
        "mtu chamber stage pin tc_pipe_exits_wan_egress"
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load tc_mtu_chamber skeleton")?;

    let entry = StageEntry {
        // Egress only: this stage has nothing to say about packets arriving from
        // the WAN, and the chain linking skips a zero fd.
        wan_ingress_prog_fd: 0,
        wan_egress_prog_fd: skel.progs.tc_mtu_chamber_wan_egress.as_fd().as_raw_fd(),
        wan_ingress_next_stage_fd: 0,
        wan_egress_next_stage_fd: skel.maps.wan_egress_next_stage.as_fd().as_raw_fd(),
    };

    rt.tc.inject(ifindex, StageType::EgressMtu, entry)?;

    Ok(TcMtuChamberStageHandle {
        runtime: rt.clone(),
        _skel: skel,
        _backing: backing,
        ifindex,
    })
}

// ========================================================================
// Return gate (attached to the chamber's veth)
// ========================================================================

/// The gate and the divert are one object on purpose: the wiring is written when
/// this is created and zeroed when it is dropped, so there is no way to leave the
/// datapath pointing at a veth nobody validates.
pub struct TcMtuChamberGateHandle {
    runtime: Arc<EbpfRuntime>,
    _skel: tc_mtu_chamber_return_skel::TcMtuChamberReturnSkel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
    hook: Option<TcHookProxy>,
    ifindex: i32,
}

impl DataplaneGuard for TcMtuChamberGateHandle {}

unsafe impl Send for TcMtuChamberGateHandle {}
unsafe impl Sync for TcMtuChamberGateHandle {}

impl Drop for TcMtuChamberGateHandle {
    fn drop(&mut self) {
        // Switch the divert off *before* the gate goes away. The other order
        // would leave a window where packets are sent to a link nothing checks.
        if let Err(e) = crate::maps::mtu_chamber::disable_mtu_chamber(&self.runtime.paths) {
            tracing::error!(
                "failed to disable the MTU chamber divert while tearing it down: {e}; \
                 the gate is being removed anyway, and the stage drops what it cannot divert"
            );
        }
        self.hook.take();
        tracing::info!("mtu chamber return gate removed from ifindex {}", self.ifindex);
    }
}

/// Attach the return gate on `veth_ifindex` and enable the divert.
///
/// The order inside is the safety property: attach, then program. A divert with
/// no gate would send packets into a link that forwards them to the local stack,
/// which is exactly what must not happen.
pub fn attach_tc_mtu_chamber_gate(
    rt: &Arc<EbpfRuntime>,
    veth_ifindex: u32,
    wiring: MtuChamberWiring,
) -> LdEbpfResult<TcMtuChamberGateHandle> {
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};

    let paths = &rt.paths;
    let builder = tc_mtu_chamber_return_skel::TcMtuChamberReturnSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_mtu_chamber_return skeleton")?;
    open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = 14;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.mtu_guard_stats_map, &paths.mtu_guard_stats),
        "mtu chamber gate pin mtu_guard_stats_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.mtu_chamber_cfg_map, &paths.mtu_chamber_cfg),
        "mtu chamber gate pin mtu_chamber_cfg_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.mtu_chamber_stats_map, &paths.mtu_chamber_stats),
        "mtu chamber gate pin mtu_chamber_stats_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.mtu_chamber_state_map, &paths.mtu_chamber_state),
        "mtu chamber gate pin mtu_chamber_state_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.mtu_chamber_budget_map, &paths.mtu_chamber_budget),
        "mtu chamber gate pin mtu_chamber_budget_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v6, &paths.ip_mac_v6),
        "mtu chamber gate pin ip_mac_v6"
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load tc_mtu_chamber_return skeleton")?;

    let mut hook = TcHookProxy::new(
        &skel.progs.tc_mtu_chamber_return,
        veth_ifindex as i32,
        libbpf_rs::TC_INGRESS,
        crate::TC_CHAMBER_RETURN_PRIORITY,
    );
    hook.attach();

    // Only now does the datapath learn there is somewhere to send the packet.
    let handle = TcMtuChamberGateHandle {
        runtime: rt.clone(),
        _skel: skel,
        _backing: backing,
        hook: Some(hook),
        ifindex: veth_ifindex as i32,
    };

    if let Err(e) = crate::maps::mtu_chamber::write_mtu_chamber_wiring(paths, &wiring) {
        // The gate is attached but the datapath does not know about it; dropping
        // the handle disables the (unwritten) divert and removes the hook.
        drop(handle);
        return Err(crate::bpf_error::LandscapeEbpfError::Io(std::io::Error::other(format!(
            "write mtu_chamber_cfg_map: {e}"
        ))));
    }

    tracing::info!(
        "mtu chamber enabled: {veth_ifindex} is the divert target, {} address(es) to speak with, error source {}",
        wiring.source_count,
        wiring
            .sources
            .first()
            .map(|s| std::net::Ipv6Addr::from(*s).to_string())
            .unwrap_or_else(|| "<none>".to_string())
    );

    Ok(handle)
}
