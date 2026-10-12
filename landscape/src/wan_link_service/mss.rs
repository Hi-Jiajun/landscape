use std::sync::Arc;
use std::time::Duration;

use landscape_common::ebpf::DataplaneGuard;
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::{RuntimeWanLinkMssConfig, SessionIface};
use landscape_common::wan_service::mss_clamp::dataplane::MssClampDataplane;
use landscape_common::wan_service::mtu_chamber::MtuChamberDataplane;
use landscape_common::wan_service::mtu_chamber::MtuChamberSettings;

use crate::wan_service::mtu_chamber_env::{
    MtuChamberEnv, MtuChamberProbe, bring_up as bring_up_mtu_chamber, probe as probe_mtu_chamber,
};

/// How often the chamber's shape is re-derived from the interfaces.
///
/// Both inputs move: the WAN device's MTU until PPPoE has set it, and a LAN
/// prefix when the ISP delegates a different one. Neither is a per-packet
/// concern, so this is slow on purpose - it exists to notice a change, not to
/// track one.
const MTU_CHAMBER_RECONCILE: Duration = Duration::from_secs(30);

/// What is attached for one shape of the interfaces.
///
/// The field order is the teardown order, and it is the safety property: the
/// chamber (whose guard switches the divert off before it detaches, then removes
/// its namespace) is dropped before the stage that decides whether to divert.
/// The other order would leave packets being sent to a link nothing validates.
struct MountedMtuChamber {
    chamber: Option<(Box<dyn DataplaneGuard>, MtuChamberEnv)>,
    /// Held for its `Drop`, which detaches the stage from the chain. Its position
    /// after `chamber` is the point: the stage decides whether to divert, so it
    /// has to outlive the divert.
    #[allow(dead_code)]
    stage: Option<Box<dyn DataplaneGuard>>,
    /// The shape this was built for. Last because it carries no teardown.
    probe: MtuChamberProbe,
}

/// Attach the egress MTU stage and, when asked for and possible, the chamber.
///
/// The stage is attached whether or not a chamber is configured: the counters
/// that say what the egress cannot carry are the evidence for whether the
/// remedy matters, and a zero means nothing unless the thing that counts is
/// running. Every failure past the stage leaves the "count only" behaviour and
/// says why.
async fn mount_mtu_chamber(
    iface_name: &str,
    ifindex: i32,
    has_mac: bool,
    dataplane: &Arc<dyn MtuChamberDataplane>,
    probe: Option<MtuChamberProbe>,
    settings: &Option<MtuChamberSettings>,
) -> Option<MountedMtuChamber> {
    let probe = probe?;

    let stage = match dataplane.attach_stage(ifindex as u32, probe.effective_mtu, has_mac) {
        Ok(guard) => guard,
        Err(err) => {
            tracing::error!(
                "failed to attach the egress MTU stage for {iface_name} at mtu {} (device {}, \
                 clamp {}): {err}; the oversize counters are blind and nothing is diverted",
                probe.effective_mtu,
                probe.device_mtu,
                probe.clamp_size
            );
            return None;
        }
    };

    // The stage is up and counting; whatever follows may still fail, and the
    // result is then exactly the pre-existing behaviour.
    let mut mounted = MountedMtuChamber {
        chamber: None,
        stage: Some(stage),
        probe: probe.clone(),
    };

    // No chamber configured, or nothing on the LAN to speak as (the `None` in the
    // probe): the stage is up and counting, and that is the whole result. A packet
    // the egress cannot carry keeps the old behaviour.
    let (Some(settings), Some(sources)) = (settings, probe.sources.as_ref()) else {
        return Some(mounted);
    };
    let sources = sources.clone();

    match bring_up_mtu_chamber(iface_name, ifindex as u32, settings, &probe, &sources).await {
        Ok(env) => {
            let wiring = env.wiring(settings.ttl_ms, settings.burst);
            match dataplane.attach_return_gate(env.veth_main_ifindex, wiring) {
                Ok(gate) => {
                    tracing::info!(
                        "IPv6 Packet Too Big chamber is up for {iface_name}: {} \
                         (device mtu {}, clamp {}, using {})",
                        env.describe(),
                        probe.device_mtu,
                        probe.clamp_size,
                        probe.effective_mtu
                    );
                    mounted.chamber = Some((gate, env));
                }
                Err(err) => {
                    // The namespace exists but nothing validates what comes back
                    // from it, so it must not stay: dropping it removes it, and
                    // the divert was never enabled.
                    tracing::error!(
                        "not enabling the IPv6 Packet Too Big chamber for {iface_name}: the \
                         return gate could not be attached: {err}"
                    );
                    drop(env);
                }
            }
        }
        Err(err) => {
            tracing::error!("not enabling the IPv6 Packet Too Big chamber for {iface_name}: {err}")
        }
    }

    Some(mounted)
}

pub(super) async fn run(
    iface: SessionIface,
    config: RuntimeWanLinkMssConfig,
    service_status: ServiceHandle,
    dataplane: Arc<dyn MssClampDataplane>,
    mtu_chamber_dataplane: Arc<dyn MtuChamberDataplane>,
) {
    let mss_clamp = match dataplane.attach(iface.ifindex, config.clamp_size, iface.has_mac()) {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start mss clamp for {}: {err}", iface.iface_name);
            service_status.just_change_status(ServiceStatus::Failed);
            return;
        }
    };

    // The egress MTU stage and the chamber are rebuilt together whenever the
    // shape they were built for changes, because they have to agree: the stage
    // decides with the egress's effective MTU, and the chamber both advertises
    // that number and speaks as the LAN. Both inputs move under this code - the
    // WAN device is 1500 until PPPoE has set it, and a LAN prefix changes when
    // the ISP delegates a different one - so reading them once at startup latches
    // whatever a restart happened to look like. Measured on 2026-10-07: it came
    // up advertising 1500 and speaking as one address.
    //
    // The rebuild is ordered so that a gap is always covered by the old
    // behaviour rather than by nothing: the divert is switched off before the
    // gate goes away, the gate goes away before its namespace, and the stage is
    // detached before it is re-attached. A packet arriving in the gap is dropped
    // exactly as it was before this feature existed.
    let mut mounted: Option<MountedMtuChamber> = None;
    let mut last_error: Option<String> = None;

    service_status.just_change_status(ServiceStatus::Running);
    loop {
        // Always derived, never conditioned on there being a chamber: the stage
        // that counts what the egress cannot carry is the evidence for whether the
        // remedy is worth having, so switching the remedy off must not switch the
        // measurement off with it.
        let desired =
            match probe_mtu_chamber(&iface.iface_name, config.mtu_chamber.as_ref(), config.clamp_size).await {
                Ok(probe) => Some(probe),
                Err(e) => {
                    if last_error.as_deref() != Some(e.as_str()) {
                        tracing::error!(
                            "cannot derive the MTU stage's shape for {}: {e}; the \
                             oversize counters are blind and nothing is diverted",
                            iface.iface_name
                        );
                        last_error = Some(e);
                    }
                    None
                }
            };
        if desired.is_some() && last_error.take().is_some() {
            tracing::info!("the MTU chamber's shape is readable again for {}", iface.iface_name);
        }

        if mounted.as_ref().map(|m| &m.probe) != desired.as_ref() {
            // Dropping first is what makes the rebuild safe: the divert is
            // switched off and the gate and its namespace removed before the
            // stage that decides is detached and rebuilt. The gap is covered by
            // the old behaviour, which is a drop.
            drop(mounted.take());
            mounted = mount_mtu_chamber(
                &iface.iface_name,
                iface.ifindex as i32,
                iface.has_mac(),
                &mtu_chamber_dataplane,
                desired,
                &config.mtu_chamber,
            )
            .await;
        }

        // Bound to a local so the borrow outlives the wait: a `cancelled()` on a
        // temporary inside `select!` is dropped before the future is polled.
        let stop = service_status.stop_token();
        tokio::select! {
            _ = stop.cancelled() => break,
            _ = tokio::time::sleep(MTU_CHAMBER_RECONCILE) => {}
        }
    }
    tracing::info!("Received external stop signal");

    // Everything comes down in one statement so the order is the type's, and the
    // type's order is the one that never leaves the divert pointing at a veth
    // nothing validates: divert off, gate, namespace, then the stage.
    drop(mounted);
    drop(mss_clamp);

    service_status.just_change_status(ServiceStatus::Stop);
}
