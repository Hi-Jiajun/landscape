//! Startup creation/pinning of the managed-DNS guard maps.
//!
//! Creation parameters mirror the `SEC(".maps")` definitions in
//! `src/bpf/dns_guard/dns_guard.h`. Passing the pin paths in explicitly lets
//! tests stand the same maps up under a temporary bpffs directory.

use std::{mem::size_of, path::Path};

use libbpf_rs::{MapHandle, MapType, libbpf_sys};

use crate::bpf_error::LdEbpfResult;
use crate::maps::firewall::types::{Ipv4LpmKey, Ipv6LpmKey};
use crate::maps::{MapCreateSpec, ensure_pinned_map};

use super::types::{DnsGuardConfig, DnsGuardExemptKey};

/// Pin file name = the C map symbol in `dns_guard.h`.
pub(crate) const DNS_GUARD_CONFIG_PIN: &str = "dns_guard_config_map";
pub(crate) const DNS_GUARD_DOH4_PIN: &str = "dns_guard_doh4_map";
pub(crate) const DNS_GUARD_DOH6_PIN: &str = "dns_guard_doh6_map";
pub(crate) const DNS_GUARD_EXEMPT_PIN: &str = "dns_guard_exempt_map";
pub(crate) const DNS_GUARD_STATS_PIN: &str = "dns_guard_stats_map";

/// Number of `dns_guard_stat` slots; keep in step with the C enum.
pub(crate) const DNS_GUARD_STAT_MAX: u32 = 8;

/// `dns_guard_config_map`: `BPF_MAP_TYPE_ARRAY`, key `u32`, value
/// `dns_guard_config` (8), a single entry.
pub(crate) const DNS_GUARD_CONFIG_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Array,
    name: DNS_GUARD_CONFIG_PIN,
    key_size: size_of::<u32>() as u32,
    value_size: size_of::<DnsGuardConfig>() as u32,
    max_entries: 1,
    map_flags: 0,
    inner: None,
};

/// `dns_guard_doh4_map`: `BPF_MAP_TYPE_LPM_TRIE`, key `ipv4_lpm_key` (8), value
/// `u8`, `BPF_F_NO_PREALLOC`.
pub(crate) const DNS_GUARD_DOH4_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LpmTrie,
    name: DNS_GUARD_DOH4_PIN,
    key_size: size_of::<Ipv4LpmKey>() as u32,
    value_size: 1,
    max_entries: 4096,
    map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
    inner: None,
};

/// `dns_guard_doh6_map`: `BPF_MAP_TYPE_LPM_TRIE`, key `ipv6_lpm_key` (20), value
/// `u8`, `BPF_F_NO_PREALLOC`.
pub(crate) const DNS_GUARD_DOH6_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LpmTrie,
    name: DNS_GUARD_DOH6_PIN,
    key_size: size_of::<Ipv6LpmKey>() as u32,
    value_size: 1,
    max_entries: 4096,
    map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
    inner: None,
};

/// `dns_guard_exempt_map`: `BPF_MAP_TYPE_HASH`, key `dns_guard_exempt_key` (40),
/// value `u8`.
pub(crate) const DNS_GUARD_EXEMPT_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Hash,
    name: DNS_GUARD_EXEMPT_PIN,
    key_size: size_of::<DnsGuardExemptKey>() as u32,
    value_size: 1,
    max_entries: 1024,
    map_flags: 0,
    inner: None,
};

/// `dns_guard_stats_map`: `BPF_MAP_TYPE_ARRAY`, key `u32`, value `u64`.
pub(crate) const DNS_GUARD_STATS_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Array,
    name: DNS_GUARD_STATS_PIN,
    key_size: size_of::<u32>() as u32,
    value_size: size_of::<u64>() as u32,
    max_entries: DNS_GUARD_STAT_MAX,
    map_flags: 0,
    inner: None,
};

pub fn init_dns_guard_config_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&DNS_GUARD_CONFIG_MAP_SPEC, path)
}

pub fn init_dns_guard_doh4_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&DNS_GUARD_DOH4_MAP_SPEC, path)
}

pub fn init_dns_guard_doh6_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&DNS_GUARD_DOH6_MAP_SPEC, path)
}

pub fn init_dns_guard_exempt_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&DNS_GUARD_EXEMPT_MAP_SPEC, path)
}

/// Create or reuse the pinned statistics array.
///
/// Counters are deliberately preserved across a restart (`ensure_pinned_map`),
/// except when the layout changes, when the map is recreated and starts at zero.
pub fn init_dns_guard_stats_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&DNS_GUARD_STATS_MAP_SPEC, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_guard_config_value_size_is_eight() {
        // Guards against an accidental layout change on either side: the C
        // struct has one byte of explicit padding and no implicit padding.
        assert_eq!(size_of::<DnsGuardConfig>(), 8);
        assert_eq!(size_of::<DnsGuardExemptKey>(), 40);
    }
}
