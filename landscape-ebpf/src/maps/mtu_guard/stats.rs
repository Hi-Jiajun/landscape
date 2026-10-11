//! Map creation and reading for the WAN MTU oversize counters.

use std::{mem::size_of, path::Path};

use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{MapCreateSpec, ensure_pinned_map};

/// Pin file name = the C map symbol in `mtu_guard.h`.
pub(crate) const MTU_GUARD_STATS_PIN: &str = "mtu_guard_stats_map";
/// Number of `mtu_guard_stat` slots; keep in step with the C enum.
pub(crate) const MTU_GUARD_STAT_MAX: u32 = 4;

/// `mtu_guard_stats_map`: four `u64` counters.
pub(crate) const MTU_GUARD_STATS_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Array,
    name: MTU_GUARD_STATS_PIN,
    key_size: size_of::<u32>() as u32,
    value_size: size_of::<u64>() as u32,
    max_entries: MTU_GUARD_STAT_MAX,
    map_flags: 0,
    inner: None,
};

pub fn init_mtu_guard_stats_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&MTU_GUARD_STATS_MAP_SPEC, path)
}

/// Re-exported so callers name one type: the shape lives in `landscape-common`
/// with the rest of the state that crosses the crate boundary.
pub use landscape_common::wan_service::mss_clamp::MtuGuardStats;

pub fn read_mtu_guard_stats(paths: &crate::LandscapeMapPath) -> Result<MtuGuardStats, String> {
    let map = MapHandle::from_pinned_path(&paths.mtu_guard_stats)
        .map_err(|e| format!("open mtu_guard_stats_map ({:?}): {e}", paths.mtu_guard_stats))?;
    let at = |index: u32| -> u64 {
        map.lookup(&index.to_ne_bytes(), MapFlags::ANY)
            .ok()
            .flatten()
            .filter(|value| value.len() >= 8)
            .map(|value| u64::from_ne_bytes(value[..8].try_into().unwrap_or_default()))
            .unwrap_or(0)
    };
    Ok(MtuGuardStats {
        oversized_v6: at(0),
        oversized_v4_df: at(1),
        oversized_v4_fragmentable: at(2),
        gso_skipped: at(3),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_oversize_counters_are_violations() {
        // A segmentation aggregate is the normal case, not a fault, so it must not
        // make the report look like traffic is being dropped.
        let only_gso = MtuGuardStats { gso_skipped: 5_000, ..Default::default() };
        assert!(!only_gso.has_violations());

        let dropped = MtuGuardStats { oversized_v6: 1, ..Default::default() };
        assert!(dropped.has_violations());
        let v4 = MtuGuardStats { oversized_v4_fragmentable: 1, ..Default::default() };
        assert!(v4.has_violations());
        let df = MtuGuardStats { oversized_v4_df: 1, ..Default::default() };
        assert!(df.has_violations());
    }
}
