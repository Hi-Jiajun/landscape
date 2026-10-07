//! The chamber's configuration and its counters.

use std::{mem::size_of, path::Path};

use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{MapCreateSpec, ensure_pinned_map};

/// The wiring shape is shared with the service that builds it; only the C-facing
/// encoding lives here.
pub use landscape_common::wan_service::mtu_chamber::{MTU_CHAMBER_CFG_SIZE, MtuChamberWiring};

/// Pin file names = the C map symbols in `mtu_guard/mtu_chamber.h`.
pub(crate) const MTU_CHAMBER_CFG_PIN: &str = "mtu_chamber_cfg_map";
pub(crate) const MTU_CHAMBER_STATS_PIN: &str = "mtu_chamber_stats_map";
/// `mtu_chamber_stat` slots; keep in step with the C enum.
pub(crate) const MTU_CHAMBER_STAT_COUNT: u32 = 16;

pub(crate) const MTU_CHAMBER_CFG_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Array,
    name: MTU_CHAMBER_CFG_PIN,
    key_size: size_of::<u32>() as u32,
    value_size: MTU_CHAMBER_CFG_SIZE as u32,
    max_entries: 1,
    map_flags: 0,
    inner: None,
};

pub(crate) const MTU_CHAMBER_STATS_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Array,
    name: MTU_CHAMBER_STATS_PIN,
    key_size: size_of::<u32>() as u32,
    value_size: size_of::<u64>() as u32,
    max_entries: MTU_CHAMBER_STAT_COUNT,
    map_flags: 0,
    inner: None,
};

pub fn init_mtu_chamber_cfg_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&MTU_CHAMBER_CFG_MAP_SPEC, path)
}

pub fn init_mtu_chamber_stats_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&MTU_CHAMBER_STATS_MAP_SPEC, path)
}

fn open_cfg(paths: &crate::LandscapeMapPath) -> Result<MapHandle, String> {
    MapHandle::from_pinned_path(&paths.mtu_chamber_cfg)
        .map_err(|e| format!("open mtu_chamber_cfg_map ({:?}): {e}", paths.mtu_chamber_cfg))
}

/// Turn the divert on with the given wiring.
///
/// Written as one map update, so the datapath never sees a half-applied shape:
/// it either has the previous config or the new one, and both are internally
/// consistent.
pub fn write_mtu_chamber_wiring(
    paths: &crate::LandscapeMapPath,
    wiring: &MtuChamberWiring,
) -> Result<(), String> {
    let map = open_cfg(paths)?;
    map.update(&0u32.to_ne_bytes(), &wiring.encode(), MapFlags::ANY)
        .map_err(|e| format!("write mtu_chamber_cfg_map: {e}"))
}

/// Turn the divert off, leaving the counters and the admission table alone.
///
/// This is what a failure to keep the chamber healthy must end in: the packets
/// that would have been diverted go back to being dropped in silence, which is
/// the pre-existing behaviour, rather than to a chamber that is not there.
pub fn disable_mtu_chamber(paths: &crate::LandscapeMapPath) -> Result<(), String> {
    write_mtu_chamber_wiring(paths, &MtuChamberWiring::default())
}

pub fn read_mtu_chamber_wiring(
    paths: &crate::LandscapeMapPath,
) -> Result<MtuChamberWiring, String> {
    let map = open_cfg(paths)?;
    let raw = map
        .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)
        .map_err(|e| format!("read mtu_chamber_cfg_map: {e}"))?
        .ok_or_else(|| "mtu_chamber_cfg_map has no slot 0".to_string())?;
    MtuChamberWiring::decode(&raw).ok_or_else(|| format!("short cfg value: {} bytes", raw.len()))
}

pub use landscape_common::wan_service::mtu_chamber::MtuChamberStats;

pub fn read_mtu_chamber_stats(paths: &crate::LandscapeMapPath) -> Result<MtuChamberStats, String> {
    let map = MapHandle::from_pinned_path(&paths.mtu_chamber_stats)
        .map_err(|e| format!("open mtu_chamber_stats_map ({:?}): {e}", paths.mtu_chamber_stats))?;
    let at = |index: u32| -> u64 {
        map.lookup(&index.to_ne_bytes(), MapFlags::ANY)
            .ok()
            .flatten()
            .filter(|value| value.len() >= 8)
            .map(|value| u64::from_ne_bytes(value[..8].try_into().unwrap_or_default()))
            .unwrap_or(0)
    };
    Ok(MtuChamberStats {
        diverted: at(0),
        skipped_disabled: at(1),
        skipped_npt: at(2),
        skipped_exthdr: at(3),
        skipped_fragment: at(4),
        skipped_l4: at(5),
        skipped_budget: at(6),
        state_full: at(7),
        divert_failed: at(8),
        ptb_returned: at(9),
        ptb_rejected: at(10),
        ptb_no_mac: at(11),
        ptb_expired: at(12),
        diverted_v4: at(13),
        frag_needed_returned: at(14),
        frag_needed_rejected: at(15),
    })
}
