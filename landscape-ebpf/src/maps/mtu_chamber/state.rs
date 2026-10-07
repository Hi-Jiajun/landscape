//! The chamber's admission table and per-source budget.

use std::{mem::size_of, path::Path};

use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{MapCreateSpec, ensure_pinned_map};

pub(crate) const MTU_CHAMBER_STATE_PIN: &str = "mtu_chamber_state_map";
pub(crate) const MTU_CHAMBER_BUDGET_PIN: &str = "mtu_chamber_budget_map";

/// `struct mtu_chamber_key`: two 16-byte addresses, a `u32` identity, a protocol
/// byte and padding.
pub(crate) const MTU_CHAMBER_KEY_SIZE: u32 = 40;
/// `struct mtu_chamber_value`: `u32` interface, `u16` MTU, padding, `u64` time.
pub(crate) const MTU_CHAMBER_VALUE_SIZE: u32 = 16;

pub(crate) const MTU_CHAMBER_STATE_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LruHash,
    name: MTU_CHAMBER_STATE_PIN,
    key_size: MTU_CHAMBER_KEY_SIZE,
    value_size: MTU_CHAMBER_VALUE_SIZE,
    max_entries: 4096,
    map_flags: 0,
    inner: None,
};

pub(crate) const MTU_CHAMBER_BUDGET_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LruHash,
    name: MTU_CHAMBER_BUDGET_PIN,
    key_size: size_of::<[u8; 16]>() as u32,
    value_size: size_of::<[u64; 2]>() as u32,
    max_entries: 1024,
    map_flags: 0,
    inner: None,
};

pub fn init_mtu_chamber_state_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&MTU_CHAMBER_STATE_MAP_SPEC, path)
}

pub fn init_mtu_chamber_budget_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&MTU_CHAMBER_BUDGET_MAP_SPEC, path)
}

/// How many admissions are waiting for an error to answer them.
///
/// Worth reading next to the counters: entries that keep piling up mean errors
/// that never came back, and the map being an LRU is what bounds the memory if
/// they ever did.
pub fn read_mtu_chamber_pending(paths: &crate::LandscapeMapPath) -> Result<u64, String> {
    let map = MapHandle::from_pinned_path(&paths.mtu_chamber_state)
        .map_err(|e| format!("open mtu_chamber_state_map ({:?}): {e}", paths.mtu_chamber_state))?;
    let mut count = 0u64;
    for key in map.keys() {
        if map.lookup(&key, MapFlags::ANY).ok().flatten().is_some() {
            count += 1;
        }
    }
    Ok(count)
}
