//! The map behind the unclassified-destination policy.
//!
//! Mirrors `route/route_unclassified.h`. The datapath applies the policy in
//! `route4_flow_verdict` / `route6_flow_verdict`, on the verdict, which is the
//! point where "nothing classified this destination" is still knowable: a
//! destination a rule sent direct carries `Direct` in its mark, while one nothing
//! claimed carries `KeepGoing` with flow 0.

use std::{mem::size_of, path::Path};

use libbpf_rs::{MapCore, MapHandle, MapType};
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{MapCreateSpec, ensure_pinned_map};
use landscape_common::flow::dataplane::UnclassifiedPolicy;

/// Pin file name = the C map symbol in `route_unclassified.h`.
pub(crate) const ROUTE_UNCLASSIFIED_PIN: &str = "route_unclassified_cfg_map";
pub(crate) const ROUTE_UNCLASSIFIED_STATS_PIN: &str = "route_unclassified_stats_map";

/// Number of `route_unclassified_stat` slots; keep in step with the C enum.
pub(crate) const ROUTE_UNCLASSIFIED_STAT_MAX: u32 = 6;

/// `struct route_unclassified_cfg`: two flags, explicit padding, then the tier.
/// The padding is spelled out because `IntoBytes` rejects implicit padding.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RouteUnclassifiedCfg {
    pub enabled: u8,
    /// `ROUTE_UNCLASSIFIED_*` from the C header.
    pub action: u8,
    pub _pad: u16,
    pub flow_id: u32,
}

impl RouteUnclassifiedCfg {
    /// The action byte for a policy. Kept here so the C constants have exactly
    /// one Rust counterpart.
    pub(crate) const PASSTHROUGH: u8 = 0;
    pub(crate) const DROP: u8 = 1;
    pub(crate) const FLOW: u8 = 2;

    pub(crate) fn from_policy(policy: UnclassifiedPolicy) -> Self {
        match policy {
            UnclassifiedPolicy::Passthrough => Self {
                enabled: 0,
                action: Self::PASSTHROUGH,
                _pad: 0,
                flow_id: 0,
            },
            UnclassifiedPolicy::Drop => Self {
                enabled: 1,
                action: Self::DROP,
                _pad: 0,
                flow_id: 0,
            },
            UnclassifiedPolicy::ProxyTier { flow_id } => {
                Self { enabled: 1, action: Self::FLOW, _pad: 0, flow_id }
            }
        }
    }
}

/// `route_unclassified_cfg_map`: one `BPF_MAP_TYPE_ARRAY` entry.
pub(crate) const ROUTE_UNCLASSIFIED_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Array,
    name: ROUTE_UNCLASSIFIED_PIN,
    key_size: size_of::<u32>() as u32,
    value_size: size_of::<RouteUnclassifiedCfg>() as u32,
    max_entries: 1,
    map_flags: 0,
    inner: None,
};

/// Create or reuse the pinned policy map.
pub fn init_route_unclassified_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&ROUTE_UNCLASSIFIED_MAP_SPEC, path)
}

/// `route_unclassified_stats_map`: per-family reason counters, `u64` each.
pub(crate) const ROUTE_UNCLASSIFIED_STATS_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Array,
    name: ROUTE_UNCLASSIFIED_STATS_PIN,
    key_size: size_of::<u32>() as u32,
    value_size: size_of::<u64>() as u32,
    max_entries: ROUTE_UNCLASSIFIED_STAT_MAX,
    map_flags: 0,
    inner: None,
};

pub fn init_route_unclassified_stats_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&ROUTE_UNCLASSIFIED_STATS_MAP_SPEC, path)
}

/// Re-exported so callers name one type: the shape lives in `landscape-common`
/// with the other state that crosses the crate boundary.
pub use landscape_common::flow::dataplane::UnclassifiedStats;

pub fn read_route_unclassified_stats(
    paths: &crate::LandscapeMapPath,
) -> Result<UnclassifiedStats, String> {
    let map = MapHandle::from_pinned_path(&paths.route_unclassified_stats).map_err(|e| {
        format!("open route_unclassified_stats_map ({:?}): {e}", paths.route_unclassified_stats)
    })?;
    let at = |index: u32| -> u64 {
        map.lookup(&index.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
            .ok()
            .flatten()
            .filter(|value| value.len() >= 8)
            .map(|value| u64::from_ne_bytes(value[..8].try_into().unwrap_or_default()))
            .unwrap_or(0)
    };
    Ok(UnclassifiedStats {
        fallback_v4: at(0),
        fallback_v6: at(1),
        refused_policy_v4: at(2),
        refused_policy_v6: at(3),
        dropped_no_target_v4: at(4),
        dropped_no_target_v6: at(5),
    })
}

/// Programme the policy, and invalidate the verdict cache it invalidates.
///
/// The invalidation is not optional: every cached verdict is the outcome of the
/// policy that was in force when it was written, so a cache left in place keeps
/// serving the previous decision for each destination already resolved. That is
/// the difference between "the policy is set" and "the policy is in effect".
pub fn apply_unclassified_policy(
    paths: &crate::LandscapeMapPath,
    policy: UnclassifiedPolicy,
) -> Result<(), String> {
    let map = MapHandle::from_pinned_path(&paths.route_unclassified_cfg).map_err(|e| {
        format!("open route_unclassified_cfg_map ({:?}): {e}", paths.route_unclassified_cfg)
    })?;
    let key = 0u32;
    let value = RouteUnclassifiedCfg::from_policy(policy);
    map.update(&key.to_ne_bytes(), value.as_bytes(), libbpf_rs::MapFlags::ANY)
        .map_err(|e| format!("write route_unclassified_cfg_map: {e}"))?;

    super::cache::recreate_route_lan_cache_inner_map(paths);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_config_is_one_word_of_flags_plus_the_tier() {
        // The C struct has two bytes of explicit padding, so the layout must be
        // 8 bytes with the tier at offset 4.
        assert_eq!(size_of::<RouteUnclassifiedCfg>(), 8);
        assert_eq!(std::mem::offset_of!(RouteUnclassifiedCfg, flow_id), 4);
    }

    #[test]
    fn passthrough_is_the_off_switch() {
        // Off is represented by the enabled byte, and the action byte stays
        // PASSTHROUGH rather than naming a tier: a disabled policy must not look
        // like an active one when the map is read by hand.
        let off = RouteUnclassifiedCfg::from_policy(UnclassifiedPolicy::Passthrough);
        assert_eq!(off.enabled, 0);
        assert_eq!(off.action, RouteUnclassifiedCfg::PASSTHROUGH);

        let drop = RouteUnclassifiedCfg::from_policy(UnclassifiedPolicy::Drop);
        assert_eq!(drop.enabled, 1);
        assert_eq!(drop.action, RouteUnclassifiedCfg::DROP);

        let tier = RouteUnclassifiedCfg::from_policy(UnclassifiedPolicy::ProxyTier { flow_id: 14 });
        assert_eq!(tier.enabled, 1);
        assert_eq!(tier.action, RouteUnclassifiedCfg::FLOW);
        assert_eq!(tier.flow_id, 14);
    }
}
