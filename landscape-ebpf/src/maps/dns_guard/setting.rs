//! Runtime content of the managed-DNS guard maps.
//!
//! All three content maps are declared-state maps: the caller passes the whole
//! desired set and the map is reconciled against it, so a removal in
//! configuration really removes the entry. Nothing here keeps private state, so
//! applying the same configuration twice is a no-op.

use std::net::IpAddr;

use libbpf_rs::{MapCore, MapFlags, MapHandle};
use zerocopy::IntoBytes;

use crate::bpf_error::LdEbpfResult;
use crate::maps::firewall::types::{Ipv4LpmKey, Ipv6LpmKey};
use crate::maps::{RawEbpfMapEntries, apply_raw_map_diff, diff_raw_map, snapshot_raw_map};

use super::init::DNS_GUARD_STAT_MAX;
use super::types::{DnsGuardConfig, DnsGuardExemptKey};

// Counter slot order must match the `dns_guard_stat` enum in
// `bpf/dns_guard/dns_guard.h`; the constants below are the only place the two
// are tied together on the Rust side.
const STAT_HANDOFF_53: usize = 0;
const STAT_HANDOFF_DOT: usize = 1;
const STAT_HANDOFF_DOH: usize = 2;
const STAT_EXEMPT: usize = 3;
const STAT_FRAGMENT_DROPPED: usize = 4;
const STAT_FRAGMENT_PASSED: usize = 5;
const STAT_PARSE_FAILED: usize = 6;
const STAT_LAN_DESTINATION: usize = 7;
const STAT_PLAINTEXT_TCP_LEFT: usize = 8;

/// One authorised exception: this client may use this service on this
/// destination without being handed to the guard.
///
/// Identity is the source address plus the service, never the flow: the flow a
/// packet lands in is chosen by its destination, so it carries no identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsGuardExemption {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// 6 (TCP) or 17 (UDP).
    pub l4_protocol: u8,
    pub port: u16,
}

fn family_of(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 0,
        IpAddr::V6(_) => 1,
    }
}

fn addr_bytes(addr: &IpAddr) -> [u8; 16] {
    let mut out = [0u8; 16];
    match addr {
        IpAddr::V4(v4) => out[..4].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => out.copy_from_slice(&v6.octets()),
    }
    out
}

impl DnsGuardExemption {
    fn raw_key(self) -> Vec<u8> {
        let key = DnsGuardExemptKey {
            family: family_of(&self.src),
            l4_protocol: self.l4_protocol,
            dport: self.port.to_be_bytes(),
            _pad: [0; 4],
            src: addr_bytes(&self.src),
            dst: addr_bytes(&self.dst),
        };
        key.as_bytes().to_vec()
    }
}

/// Write the guard switch.
///
/// A single entry, so this is a plain update rather than a reconcile: the value
/// is the whole state.
pub(crate) fn set_dns_guard_config(map: &MapHandle, config: DnsGuardConfig) -> LdEbpfResult<()> {
    let key = 0u32;
    map.update(&key.to_ne_bytes(), config.as_bytes(), MapFlags::ANY)?;
    Ok(())
}

/// Reconcile the DoH address sets to exactly `entries`.
///
/// Addresses are inserted as host prefixes (/32, /128); the maps are LPM tries
/// so a future prefix form can widen that without changing the guard.
pub fn set_dns_guard_doh(
    map4: &MapHandle,
    map6: &MapHandle,
    entries: &[IpAddr],
) -> LdEbpfResult<()> {
    let mut desired4 = RawEbpfMapEntries::new();
    let mut desired6 = RawEbpfMapEntries::new();
    for addr in entries {
        match addr {
            IpAddr::V4(v4) => {
                let key = Ipv4LpmKey { prefixlen: 32, addr: v4.to_bits().to_be() };
                desired4.insert(key.as_bytes().to_vec(), vec![1u8]);
            }
            IpAddr::V6(v6) => {
                let key = Ipv6LpmKey { prefixlen: 128, addr: v6.octets() };
                desired6.insert(key.as_bytes().to_vec(), vec![1u8]);
            }
        }
    }

    apply_raw_map_diff(map4, diff_raw_map(&snapshot_raw_map(map4)?, &desired4))?;
    apply_raw_map_diff(map6, diff_raw_map(&snapshot_raw_map(map6)?, &desired6))?;
    Ok(())
}

/// Reconcile the trust list to exactly `entries`.
pub fn set_dns_guard_exempt(map: &MapHandle, entries: &[DnsGuardExemption]) -> LdEbpfResult<()> {
    let mut desired = RawEbpfMapEntries::new();
    for entry in entries {
        desired.insert(entry.raw_key(), vec![1u8]);
    }
    apply_raw_map_diff(map, diff_raw_map(&snapshot_raw_map(map)?, &desired))?;
    Ok(())
}

/// Read the guard counters as one array indexed by the C `dns_guard_stat` enum.
///
/// These are per packet, while the netfilter counters are per rule match, so a
/// nonzero handoff count here with an unchanged DROP count below is a signal
/// that the receive side is missing rather than that no traffic was guarded.
pub fn read_dns_guard_stats(map: &MapHandle) -> LdEbpfResult<Vec<u64>> {
    let mut out = Vec::with_capacity(DNS_GUARD_STAT_MAX as usize);
    for idx in 0..DNS_GUARD_STAT_MAX {
        let key = idx.to_ne_bytes();
        let value = map.lookup(&key, MapFlags::ANY)?.unwrap_or_else(|| vec![0u8; 8]);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&value[..8]);
        out.push(u64::from_ne_bytes(bytes));
    }
    Ok(out)
}

/// Programme both halves of the datapath for one [`DnsGuardSpec`].
///
/// Opening the pinned maps fails when the datapath is not running; that is
/// reported as an error rather than swallowed, because "the datapath half is
/// missing" means direct flows are not guarded at all.
pub fn apply_dns_guard(
    paths: &crate::LandscapeMapPath,
    spec: &landscape_common::proxy::dataplane::DnsGuardSpec,
) -> Result<(), String> {
    let open = |path: &std::path::Path, what: &str| {
        MapHandle::from_pinned_path(path).map_err(|e| format!("open {what} ({path:?}): {e}"))
    };

    let config_map = open(&paths.dns_guard_config, "dns_guard_config_map")?;
    let doh4 = open(&paths.dns_guard_doh4, "dns_guard_doh4_map")?;
    let doh6 = open(&paths.dns_guard_doh6, "dns_guard_doh6_map")?;
    let exempt = open(&paths.dns_guard_exempt, "dns_guard_exempt_map")?;

    set_dns_guard_config(
        &config_map,
        DnsGuardConfig {
            enabled: u8::from(spec.enabled),
            plaintext_tcp: u8::from(spec.plaintext_tcp),
            drop_fragments: u8::from(spec.drop_fragments),
            drop_unclassified: u8::from(spec.drop_unclassified),
            // A stamp the operator can use to tell one apply from the next when
            // reading the map by hand.
            generation: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0),
        },
    )
    .map_err(|e| format!("write dns_guard_config_map: {e}"))?;

    set_dns_guard_doh(&doh4, &doh6, &spec.doh_block)
        .map_err(|e| format!("write dns_guard DoH sets: {e}"))?;

    let entries: Vec<DnsGuardExemption> = spec
        .exempt
        .iter()
        .flat_map(|entry| {
            entry.protocol.as_l4_protocols().into_iter().map(move |proto| DnsGuardExemption {
                src: entry.client,
                dst: entry.destination,
                l4_protocol: proto,
                port: entry.port,
            })
        })
        .collect();
    set_dns_guard_exempt(&exempt, &entries)
        .map_err(|e| format!("write dns_guard_exempt_map: {e}"))?;

    Ok(())
}

/// Read the datapath counters, named.
pub fn dns_guard_counters(
    paths: &crate::LandscapeMapPath,
) -> Result<landscape_common::proxy::DnsGuardCounters, String> {
    let map = MapHandle::from_pinned_path(&paths.dns_guard_stats)
        .map_err(|e| format!("open dns_guard_stats_map ({:?}): {e}", paths.dns_guard_stats))?;
    let raw = read_dns_guard_stats(&map).map_err(|e| format!("read dns_guard_stats_map: {e}"))?;
    let at = |idx: usize| raw.get(idx).copied().unwrap_or(0);
    Ok(landscape_common::proxy::DnsGuardCounters {
        handoff_plaintext: at(STAT_HANDOFF_53),
        handoff_dot: at(STAT_HANDOFF_DOT),
        handoff_doh: at(STAT_HANDOFF_DOH),
        exempted: at(STAT_EXEMPT),
        fragments_refused: at(STAT_FRAGMENT_DROPPED),
        fragments_passed: at(STAT_FRAGMENT_PASSED),
        unclassified_passed: at(STAT_PARSE_FAILED),
        lan_destination: at(STAT_LAN_DESTINATION),
        plaintext_tcp_left: at(STAT_PLAINTEXT_TCP_LEFT),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn exemption_keys_are_family_scoped_and_zero_padded() {
        let v4 = DnsGuardExemption {
            src: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 201)),
            dst: IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
            l4_protocol: 6,
            port: 853,
        };
        let bytes = v4.raw_key();
        assert_eq!(bytes.len(), 40);
        assert_eq!(bytes[0], 0, "family byte for IPv4");
        assert_eq!(bytes[1], 6, "protocol");
        assert_eq!(&bytes[2..4], &853u16.to_be_bytes());
        assert_eq!(&bytes[4..8], &[0u8; 4]);
        assert_eq!(&bytes[8..12], &[192u8, 168, 1, 201]);
        assert_eq!(&bytes[12..24], &[0u8; 12], "IPv4 tail stays zeroed");
        assert_eq!(&bytes[24..28], &[223u8, 5, 5, 5]);
        assert_eq!(&bytes[28..40], &[0u8; 12], "IPv4 tail stays zeroed");

        let v6 = DnsGuardExemption {
            src: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dst: IpAddr::V6(Ipv6Addr::LOCALHOST),
            l4_protocol: 17,
            port: 53,
        };
        assert_eq!(v6.raw_key()[0], 1, "family byte for IPv6");
    }
}
