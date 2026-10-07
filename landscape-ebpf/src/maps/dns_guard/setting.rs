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
