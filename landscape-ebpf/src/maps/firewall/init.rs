//! Startup creation/pinning of the firewall maps.
//!
//! Creation parameters mirror the C `SEC(".maps")` definitions in
//! `src/bpf/firewall/firewall_share.h`. Passing the pin paths explicitly lets
//! tests create the maps under an isolated (temporary) bpffs directory.

use std::mem::size_of;
use std::path::Path;

use libbpf_rs::{MapCore, MapHandle, MapType, libbpf_sys};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{MapCreateSpec, ensure_pinned_map};

use super::types::{FirewallAction, Ipv4LpmKey, Ipv6LpmKey};

const FIREWALL_BLOCK_MAX_ENTRIES: u32 = 65535;

/// Pin 文件名 = C map 符号名（见 `firewall_share.h`）。
pub(crate) const FIREWALL_BLOCK_IP4_MAP_PIN: &str = "firewall_block_ip4_map";
pub(crate) const FIREWALL_BLOCK_IP6_MAP_PIN: &str = "firewall_block_ip6_map";
pub(crate) const FIREWALL_CONN_METRIC_EVENTS_PIN: &str = "firewall_conn_metric_events";
pub(crate) const FIREWALL_CONFIG_PIN: &str = "firewall_config_map";
pub(crate) const FIREWALL_ALLOW_PORTS_PIN: &str = "firewall_allow_ports_map";
pub(crate) const FIREWALL_STATE4_PIN: &str = "firewall_state4_map";
pub(crate) const FIREWALL_STATE6_PIN: &str = "firewall_state6_map";
pub(crate) const FIREWALL_RATELIMIT4_PIN: &str = "firewall_ratelimit4_map";
pub(crate) const FIREWALL_RATELIMIT6_PIN: &str = "firewall_ratelimit6_map";

/// `firewall_block_ip4_map`: `BPF_MAP_TYPE_LPM_TRIE`, key `ipv4_lpm_key` (8),
/// value `firewall_action` (4), 65535 entries, `BPF_F_NO_PREALLOC`.
pub(crate) const FIREWALL_BLOCK_IP4_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LpmTrie,
    name: FIREWALL_BLOCK_IP4_MAP_PIN,
    key_size: size_of::<Ipv4LpmKey>() as u32,
    value_size: size_of::<FirewallAction>() as u32,
    max_entries: FIREWALL_BLOCK_MAX_ENTRIES,
    map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
    inner: None,
};

/// `firewall_block_ip6_map`: `BPF_MAP_TYPE_LPM_TRIE`, key `ipv6_lpm_key` (20),
/// value `firewall_action` (4), 65535 entries, `BPF_F_NO_PREALLOC`.
pub(crate) const FIREWALL_BLOCK_IP6_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LpmTrie,
    name: FIREWALL_BLOCK_IP6_MAP_PIN,
    key_size: size_of::<Ipv6LpmKey>() as u32,
    value_size: size_of::<FirewallAction>() as u32,
    max_entries: FIREWALL_BLOCK_MAX_ENTRIES,
    map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
    inner: None,
};

/// `firewall_conn_metric_events`: `BPF_MAP_TYPE_RINGBUF`, `1 << 24` bytes.
pub(crate) const FIREWALL_CONN_METRIC_EVENTS_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::RingBuf,
    name: FIREWALL_CONN_METRIC_EVENTS_PIN,
    key_size: 0,
    value_size: 0,
    max_entries: 1 << 24,
    map_flags: 0,
    inner: None,
};

/// `firewall_config_map`: `BPF_MAP_TYPE_ARRAY`, key `u32` (4),
/// value `firewall_global_cfg` (8), 1 entry.
pub(crate) const FIREWALL_CONFIG_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Array,
    name: FIREWALL_CONFIG_PIN,
    key_size: size_of::<u32>() as u32,
    value_size: 8,
    max_entries: 1,
    map_flags: 0,
    inner: None,
};

/// `firewall_allow_ports_map`: `BPF_MAP_TYPE_HASH`, key `port_allow_key` (4),
/// value `u8` (1), 1024 entries.
pub(crate) const FIREWALL_ALLOW_PORTS_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Hash,
    name: FIREWALL_ALLOW_PORTS_PIN,
    key_size: size_of::<super::setting::PortAllowKey>() as u32,
    value_size: 1,
    max_entries: super::setting::FIREWALL_ALLOW_PORTS_MAX_ENTRIES as u32,
    map_flags: 0,
    inner: None,
};

/// Create or reuse the pinned `firewall_block_ip4_map` at `path`.
pub fn init_firewall_block_ip4_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&FIREWALL_BLOCK_IP4_MAP_SPEC, path)
}

/// Create or reuse the pinned `firewall_block_ip6_map` at `path`.
pub fn init_firewall_block_ip6_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&FIREWALL_BLOCK_IP6_MAP_SPEC, path)
}

/// Create or reuse the pinned `firewall_conn_metric_events` ringbuf at `path`.
pub fn init_firewall_conn_metric_events(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&FIREWALL_CONN_METRIC_EVENTS_SPEC, path)
}

/// Create or reuse the pinned `firewall_config_map` at `path`.
///
/// The default switch values are written only when the pin did not exist yet
/// (fresh boot / first run). Re-attaching the firewall program must not reset
/// operator choices, so this is deliberately not re-seeded on every attach.
pub fn init_firewall_config_map(path: &Path) -> LdEbpfResult<MapHandle> {
    let is_new = !path.exists();
    let map = ensure_pinned_map(&FIREWALL_CONFIG_MAP_SPEC, path)?;
    if is_new {
        let key = 0u32;
        // allow_wan_ping = 1, syn_flood_protect = 1
        let default_val = [1u8, 1u8, 0, 0, 0, 0, 0, 0];
        let _ = map.update(&key.to_ne_bytes(), &default_val, libbpf_rs::MapFlags::ANY);
    }
    Ok(map)
}

/// Create or reuse the pinned `firewall_allow_ports_map` at `path`.
///
/// The map content is fully derived (management ports + static NAT mappings),
/// so seeding it here reconciles the management ports of both address families.
///
/// Only a **freshly created** map is reset to "management ports only" — that is
/// the correct starting state before any service owns the map. When an existing
/// pin is reused (a daemon restart keeps pins alive, and the firewall program
/// may still be running), resetting would revoke the static-NAT authorizations
/// the NAT service owns, so the additive variant is used instead.
pub fn init_firewall_allow_ports_map(path: &Path) -> LdEbpfResult<MapHandle> {
    let existed = path.exists();
    let map = ensure_pinned_map(&FIREWALL_ALLOW_PORTS_MAP_SPEC, path)?;
    // A reused map is left as-is (plus the management ports); a newly created or
    // recreated one starts from the management ports only.
    let seeded = if existed {
        super::setting::ensure_firewall_management_ports_on(&map)
    } else {
        super::setting::reset_firewall_allowed_ports_on(&map)
    };
    if let Err(e) = seeded {
        tracing::warn!("failed to seed firewall management ports: {e:?}");
    }
    Ok(map)
}

// ── Connection tracking and rate limiting ────────────────────────────────
//
// These four are the tables the firewall keeps between packets. They are created
// here rather than left to libbpf's name-based pinning for two reasons, both of
// which were real failures on the live router:
//
//   * a name-pinned map that no loader gives a path to is pinned at the bpffs
//     root, so it escapes the map space: two spaces then share one instance, and
//     a map from an earlier build with a different key layout makes the next load
//     fail with `EINVAL` instead of being replaced. That is exactly how the WAN
//     firewall came to never load at all (the rate-limit key gained a traffic
//     class, the old root pin still had the 4-byte key, and libbpf refused to
//     reuse it);
//   * creating them here means a layout change is detected and the map is
//     recreated, instead of silently mismatching or refusing to load.
//
// Their content survives a program reload, which is the point: losing the
// connection table on a stage change would make established inbound flows look
// like unsolicited traffic and drop them.

/// `firewall_state4_map`: `BPF_MAP_TYPE_LRU_HASH`, key `ct_tuple4`, value
/// `ct_entry`, 262144 entries.
pub(crate) const FIREWALL_STATE4_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LruHash,
    name: FIREWALL_STATE4_PIN,
    key_size: size_of::<super::types::CtTuple4>() as u32,
    value_size: size_of::<super::types::CtEntry>() as u32,
    max_entries: 262_144,
    map_flags: 0,
    inner: None,
};

/// `firewall_state6_map`: as above with the IPv6 tuple.
pub(crate) const FIREWALL_STATE6_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LruHash,
    name: FIREWALL_STATE6_PIN,
    key_size: size_of::<super::types::CtTuple6>() as u32,
    value_size: size_of::<super::types::CtEntry>() as u32,
    max_entries: 262_144,
    map_flags: 0,
    inner: None,
};

/// `firewall_ratelimit4_map`: `LRU_HASH`, key `ratelimit_key4`, 16384 entries.
pub(crate) const FIREWALL_RATELIMIT4_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LruHash,
    name: FIREWALL_RATELIMIT4_PIN,
    key_size: size_of::<super::types::RatelimitKey4>() as u32,
    value_size: size_of::<super::types::RatelimitEntry>() as u32,
    max_entries: 16_384,
    map_flags: 0,
    inner: None,
};

/// `firewall_ratelimit6_map`: as above with the IPv6 key.
pub(crate) const FIREWALL_RATELIMIT6_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LruHash,
    name: FIREWALL_RATELIMIT6_PIN,
    key_size: size_of::<super::types::RatelimitKey6>() as u32,
    value_size: size_of::<super::types::RatelimitEntry>() as u32,
    max_entries: 16_384,
    map_flags: 0,
    inner: None,
};

pub fn init_firewall_state4_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&FIREWALL_STATE4_MAP_SPEC, path)
}

pub fn init_firewall_state6_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&FIREWALL_STATE6_MAP_SPEC, path)
}

pub fn init_firewall_ratelimit4_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&FIREWALL_RATELIMIT4_MAP_SPEC, path)
}

pub fn init_firewall_ratelimit6_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&FIREWALL_RATELIMIT6_MAP_SPEC, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stages::firewall::xdp_firewall_skel::XdpFirewallSkelBuilder;
    use libbpf_rs::skel::SkelBuilder as _;

    #[test]
    fn firewall_map_params_match_skel() {
        let mut obj = std::mem::MaybeUninit::uninit();
        let open = XdpFirewallSkelBuilder::default().open(&mut obj).expect("open anchor skel");
        crate::maps::assert_skel_map_matches(
            &open.maps.firewall_block_ip4_map,
            &FIREWALL_BLOCK_IP4_MAP_SPEC,
        );
        crate::maps::assert_skel_map_matches(
            &open.maps.firewall_block_ip6_map,
            &FIREWALL_BLOCK_IP6_MAP_SPEC,
        );
        crate::maps::assert_skel_map_matches(
            &open.maps.firewall_conn_metric_events,
            &FIREWALL_CONN_METRIC_EVENTS_SPEC,
        );
        // The four state tables are named in both firewall skeletons; their
        // creation parameters come from the same C declarations.
        crate::maps::assert_skel_map_matches(
            &open.maps.firewall_state4_map,
            &FIREWALL_STATE4_MAP_SPEC,
        );
        crate::maps::assert_skel_map_matches(
            &open.maps.firewall_state6_map,
            &FIREWALL_STATE6_MAP_SPEC,
        );
        crate::maps::assert_skel_map_matches(
            &open.maps.firewall_ratelimit4_map,
            &FIREWALL_RATELIMIT4_MAP_SPEC,
        );
        crate::maps::assert_skel_map_matches(
            &open.maps.firewall_ratelimit6_map,
            &FIREWALL_RATELIMIT6_MAP_SPEC,
        );
    }
}
