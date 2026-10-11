//! Firewall blacklist maps (`firewall_block_ip4_map` / `firewall_block_ip6_map`):
//! sync IP/prefix blacklist entries from config in batch.

use std::{collections::HashSet, net::IpAddr};

use landscape_common::flow::ip_mark::IpConfig;
use libbpf_rs::{MapCore, MapFlags};
use zerocopy::IntoBytes;

use crate::maps::LandscapeMapPath;

use super::types::{FirewallAction, Ipv4LpmKey, Ipv6LpmKey};

pub fn sync_firewall_blacklist(
    paths: &LandscapeMapPath,
    new_ips: Vec<IpConfig>,
    old_ips: Vec<IpConfig>,
) {
    let new_set: HashSet<IpConfig> = new_ips.into_iter().collect();
    let old_set: HashSet<IpConfig> = old_ips.into_iter().collect();

    let to_add: Vec<&IpConfig> = new_set.difference(&old_set).collect();
    let to_del: Vec<&IpConfig> = old_set.difference(&new_set).collect();

    // Split into IPv4 and IPv6
    let (add_v4, add_v6): (Vec<&IpConfig>, Vec<&IpConfig>) =
        to_add.into_iter().partition(|ip| ip.ip.is_ipv4());
    let (del_v4, del_v6): (Vec<&IpConfig>, Vec<&IpConfig>) =
        to_del.into_iter().partition(|ip| ip.ip.is_ipv4());

    // IPv4 block map
    if !add_v4.is_empty() || !del_v4.is_empty() {
        match libbpf_rs::MapHandle::from_pinned_path(&paths.firewall_ipv4_block) {
            Ok(map) => {
                if !del_v4.is_empty()
                    && let Err(e) = delete_blacklist_ipv4(&map, &del_v4)
                {
                    tracing::error!("del firewall blacklist ipv4: {e:?}");
                }
                if !add_v4.is_empty()
                    && let Err(e) = add_blacklist_ipv4(&map, &add_v4)
                {
                    tracing::error!("add firewall blacklist ipv4: {e:?}");
                }
            }
            Err(e) => {
                tracing::error!(
                    "open pinned firewall_ipv4_block ({:?}) failed, skip ipv4 blacklist sync: {e}",
                    paths.firewall_ipv4_block
                );
            }
        }
    }

    // IPv6 block map
    if !add_v6.is_empty() || !del_v6.is_empty() {
        match libbpf_rs::MapHandle::from_pinned_path(&paths.firewall_ipv6_block) {
            Ok(map) => {
                if !del_v6.is_empty()
                    && let Err(e) = delete_blacklist_ipv6(&map, &del_v6)
                {
                    tracing::error!("del firewall blacklist ipv6: {e:?}");
                }
                if !add_v6.is_empty()
                    && let Err(e) = add_blacklist_ipv6(&map, &add_v6)
                {
                    tracing::error!("add firewall blacklist ipv6: {e:?}");
                }
            }
            Err(e) => {
                tracing::error!(
                    "open pinned firewall_ipv6_block ({:?}) failed, skip ipv6 blacklist sync: {e}",
                    paths.firewall_ipv6_block
                );
            }
        }
    }
}

fn add_blacklist_ipv4<T: MapCore>(map: &T, ips: &[&IpConfig]) -> libbpf_rs::Result<()> {
    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let mut values = vec![];
    let count = ips.len() as u32;

    for ip in ips {
        if let IpAddr::V4(addr) = ip.ip {
            let key = Ipv4LpmKey { prefixlen: ip.prefix, addr: addr.to_bits().to_be() };
            let value = FirewallAction { mark: 0 };
            keys.extend_from_slice(key.as_bytes());
            values.extend_from_slice(value.as_bytes());
        }
    }

    map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)
}

fn delete_blacklist_ipv4<T: MapCore>(map: &T, ips: &[&IpConfig]) -> libbpf_rs::Result<()> {
    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let count = ips.len() as u32;

    for ip in ips {
        if let IpAddr::V4(addr) = ip.ip {
            let key = Ipv4LpmKey { prefixlen: ip.prefix, addr: addr.to_bits().to_be() };
            keys.extend_from_slice(key.as_bytes());
        }
    }

    map.delete_batch(&keys, count, MapFlags::ANY, MapFlags::ANY)
}

fn add_blacklist_ipv6<T: MapCore>(map: &T, ips: &[&IpConfig]) -> libbpf_rs::Result<()> {
    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let mut values = vec![];
    let count = ips.len() as u32;

    for ip in ips {
        if let IpAddr::V6(addr) = ip.ip {
            let mut key = Ipv6LpmKey { prefixlen: ip.prefix, addr: [0u8; 16] };
            key.addr.copy_from_slice(&addr.octets());
            let value = FirewallAction { mark: 0 };
            keys.extend_from_slice(key.as_bytes());
            values.extend_from_slice(value.as_bytes());
        }
    }

    map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)
}

fn delete_blacklist_ipv6<T: MapCore>(map: &T, ips: &[&IpConfig]) -> libbpf_rs::Result<()> {
    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let count = ips.len() as u32;

    for ip in ips {
        if let IpAddr::V6(addr) = ip.ip {
            let mut key = Ipv6LpmKey { prefixlen: ip.prefix, addr: [0u8; 16] };
            key.addr.copy_from_slice(&addr.octets());
            keys.extend_from_slice(key.as_bytes());
        }
    }

    map.delete_batch(&keys, count, MapFlags::ANY, MapFlags::ANY)
}

/// Inbound port authorization key. Mirrors `struct port_allow_key` in
/// `firewall_share.h`: port/protocol scoped to one address family, so an IPv4
/// static-NAT authorization can never authorize the same port on IPv6.
#[repr(C)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Immutable,
)]
pub struct PortAllowKey {
    /// Big-endian (network byte order) port.
    pub port: u16,
    /// 0 = any protocol, 6 = TCP, 17 = UDP.
    pub protocol: u8,
    /// `FW_PORT_FAMILY_V4` / `FW_PORT_FAMILY_V6`.
    pub family: u8,
}

/// Mirrors `FW_PORT_FAMILY_V4` in `firewall_share.h`.
pub const FW_PORT_FAMILY_V4: u8 = 4;
/// Mirrors `FW_PORT_FAMILY_V6` in `firewall_share.h`.
pub const FW_PORT_FAMILY_V6: u8 = 6;
/// Mirrors `FW_PORT_ALL`: "every port in this family" sentinel.
pub const FW_PORT_ALL: u16 = 0;

/// Ports that must stay reachable for management regardless of NAT config:
/// 6443 (Landscape Web UI), 6300, 80 and 443 (nginx in front of the UI).
///
/// These used to be hard-coded inside `tc_firewall.bpf.c`; they are seeded
/// through the map instead so that revoking an authorization really revokes it.
pub const FIREWALL_MANAGEMENT_PORTS: [(u16, u8); 4] = [(80, 6), (443, 6), (6443, 6), (6300, 6)];

/// Must match `max_entries` of `firewall_allow_ports_map` in `firewall_share.h`.
pub const FIREWALL_ALLOW_PORTS_MAX_ENTRIES: usize = 1024;

/// Desired content of `firewall_allow_ports_map` for one address family.
fn desired_port_keys(family: u8, ports: &[(u16, u8)]) -> Vec<PortAllowKey> {
    let mut keys: Vec<PortAllowKey> = FIREWALL_MANAGEMENT_PORTS
        .iter()
        .chain(ports.iter())
        .map(|(port, protocol)| PortAllowKey { port: port.to_be(), protocol: *protocol, family })
        .collect();
    keys.sort_unstable_by_key(|key| key.as_bytes().to_vec());
    keys.dedup();
    keys
}

/// Reconcile the inbound port authorizations of one address family.
///
/// The map is fully derived from configuration (management ports + static NAT
/// mappings), so this is a reconcile rather than an append: authorizations that
/// disappeared from the configuration are removed again. Only entries of the
/// given `family` are considered, therefore synchronizing IPv4 can never drop
/// IPv6 authorizations (and vice versa).
pub fn sync_firewall_allowed_ports_on<M: MapCore>(
    map: &M,
    family: u8,
    ports: &[(u16, u8)],
) -> crate::bpf_error::LdEbpfResult<usize> {
    let desired_keys = desired_port_keys(family, ports);
    if desired_keys.len() > FIREWALL_ALLOW_PORTS_MAX_ENTRIES {
        return Err(std::io::Error::other(format!(
            "firewall_allow_ports_map overflow: {} authorizations for family {family} exceed the {FIREWALL_ALLOW_PORTS_MAX_ENTRIES} entry limit",
            desired_keys.len()
        ))
        .into());
    }

    let mut desired = crate::maps::RawEbpfMapEntries::new();
    for key in &desired_keys {
        desired.insert(key.as_bytes().to_vec(), vec![1u8]);
    }

    let mut current = crate::maps::snapshot_raw_map(map)?;
    // Entries carrying a family this code no longer understands (including the
    // legacy `_pad = 0` layout) can never match the BPF lookup any more, so
    // they are dropped instead of lingering invisibly.
    for key in current.keys() {
        if key.len() == std::mem::size_of::<PortAllowKey>() {
            let family_byte = key[std::mem::size_of::<PortAllowKey>() - 1];
            if family_byte != FW_PORT_FAMILY_V4 && family_byte != FW_PORT_FAMILY_V6 {
                let _ = map.delete(key);
            }
        }
    }
    current.retain(|key, _| {
        key.len() == std::mem::size_of::<PortAllowKey>()
            && key[std::mem::size_of::<PortAllowKey>() - 1] == family
    });

    let before = current.len();
    let diff = crate::maps::diff_raw_map(&current, &desired);
    let removed = diff.delete_keys.len();
    crate::maps::apply_raw_map_diff(map, diff)?;

    tracing::debug!(
        family,
        kept = before,
        desired = desired_keys.len(),
        removed,
        "reconciled firewall inbound port authorizations"
    );
    Ok(removed)
}

/// Same as [`sync_firewall_allowed_ports_on`], opening the pinned map by path.
pub fn sync_firewall_allowed_ports(
    paths: &LandscapeMapPath,
    family: u8,
    ports: &[(u16, u8)],
) -> crate::bpf_error::LdEbpfResult<usize> {
    let map = libbpf_rs::MapHandle::from_pinned_path(&paths.firewall_allow_ports)?;
    sync_firewall_allowed_ports_on(&map, family, ports)
}

/// Reset the map to "management ports only" for both address families.
///
/// Only correct when the map has just been (re)created, or when the caller
/// knows the complete desired set. It **deletes** every other entry, so it must
/// not be used on a live, co-owned map — see
/// [`ensure_firewall_management_ports_on`].
pub fn reset_firewall_allowed_ports_on<M: MapCore>(map: &M) -> crate::bpf_error::LdEbpfResult<()> {
    sync_firewall_allowed_ports_on(map, FW_PORT_FAMILY_V4, &[])?;
    sync_firewall_allowed_ports_on(map, FW_PORT_FAMILY_V6, &[])?;
    Ok(())
}

/// Make sure the management ports exist, **without** removing anything else.
///
/// This is what the attach path uses. The map is co-owned: the management ports
/// are a constant, while the per-family static-NAT authorizations are owned by
/// `EbpfNatDataplane::sync_static_nat4/6` — the only place that knows the
/// complete desired set. Reconciling here with an empty NAT list would silently
/// revoke every NAT authorization until the next NAT sync, and when the
/// firewall is re-attached on its own (e.g. an interface flap) that revoke
/// would be permanent.
pub fn ensure_firewall_management_ports_on<M: MapCore>(
    map: &M,
) -> crate::bpf_error::LdEbpfResult<()> {
    for family in [FW_PORT_FAMILY_V4, FW_PORT_FAMILY_V6] {
        for (port, protocol) in FIREWALL_MANAGEMENT_PORTS {
            let key = PortAllowKey { port: port.to_be(), protocol, family };
            map.update(key.as_bytes(), &[1u8], MapFlags::ANY)?;
        }
    }
    Ok(())
}

/// Overwrite the global firewall switches (`allow_wan_ping`, `syn_flood_protect`).
pub fn set_firewall_global_config(
    paths: &LandscapeMapPath,
    allow_wan_ping: bool,
    syn_flood_protect: bool,
) -> crate::bpf_error::LdEbpfResult<()> {
    let map = libbpf_rs::MapHandle::from_pinned_path(&paths.firewall_config)?;
    let key = 0u32;
    let value = [u8::from(allow_wan_ping), u8::from(syn_flood_protect), 0, 0, 0, 0, 0, 0];
    map.update(&key.to_ne_bytes(), &value, MapFlags::ANY)?;
    Ok(())
}

#[cfg(test)]
mod allow_ports_tests {
    //! The inbound authorization map is co-owned: management ports come from
    //! this module, per-family static-NAT authorizations come from the NAT
    //! datapath. These tests pin both halves of that contract, because getting
    //! it wrong silently revokes port forwards.

    use super::*;
    use libbpf_rs::{MapHandle, MapType, libbpf_sys};

    fn create_allow_ports_map() -> MapHandle {
        crate::test_support::ensure_bpffs();
        #[allow(clippy::needless_update)]
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };
        MapHandle::create(
            MapType::Hash,
            Option::<&str>::None,
            std::mem::size_of::<PortAllowKey>() as u32,
            std::mem::size_of::<u8>() as u32,
            FIREWALL_ALLOW_PORTS_MAX_ENTRIES as u32,
            &opts,
        )
        .expect("create firewall_allow_ports test map")
    }

    fn key(port: u16, protocol: u8, family: u8) -> PortAllowKey {
        PortAllowKey { port: port.to_be(), protocol, family }
    }

    fn contains(map: &MapHandle, key: &PortAllowKey) -> bool {
        map.lookup(key.as_bytes(), MapFlags::ANY).ok().flatten().is_some()
    }

    fn keys_of_family(map: &MapHandle, family: u8) -> usize {
        map.keys()
            .filter(|raw| raw.len() == std::mem::size_of::<PortAllowKey>())
            .filter(|raw| raw[std::mem::size_of::<PortAllowKey>() - 1] == family)
            .count()
    }

    /// The regression astra found: attaching the firewall program used to
    /// reconcile the map with an empty NAT list, revoking every static-NAT
    /// authorization (e.g. the DHCP client ports 68/546, or any port forward)
    /// until the next NAT sync — permanently, if the firewall was re-attached
    /// on its own after an interface flap.
    #[test]
    fn attach_keeps_static_nat_authorizations() {
        let map = create_allow_ports_map();

        // The NAT datapath owns the per-family authorizations and reconciles
        // with the complete desired set (management ports + its own mappings).
        sync_firewall_allowed_ports_on(&map, FW_PORT_FAMILY_V4, &[(68, 17)]).unwrap();
        sync_firewall_allowed_ports_on(&map, FW_PORT_FAMILY_V6, &[(546, 17)]).unwrap();
        assert!(contains(&map, &key(68, 17, FW_PORT_FAMILY_V4)));
        assert!(contains(&map, &key(546, 17, FW_PORT_FAMILY_V6)));

        // ... a later firewall attach must not take them away.
        ensure_firewall_management_ports_on(&map).unwrap();
        assert!(
            contains(&map, &key(68, 17, FW_PORT_FAMILY_V4)),
            "attach revoked the IPv4 static-NAT authorization"
        );
        assert!(
            contains(&map, &key(546, 17, FW_PORT_FAMILY_V6)),
            "attach revoked the IPv6 static-NAT authorization"
        );

        // Management ports are present in both families, NAT ports only in
        // their own: 4 management + 1 NAT per family.
        assert_eq!(keys_of_family(&map, FW_PORT_FAMILY_V4), 5);
        assert_eq!(keys_of_family(&map, FW_PORT_FAMILY_V6), 5);
        // The NAT-only port never appears in the other family.
        assert!(!contains(&map, &key(68, 17, FW_PORT_FAMILY_V6)));
        assert!(!contains(&map, &key(546, 17, FW_PORT_FAMILY_V4)));
    }

    /// The authoritative reconcile (NAT sync) must still revoke authorizations
    /// that disappeared from the configuration, and must only touch its own
    /// family.
    #[test]
    fn nat_reconcile_revokes_only_its_own_family() {
        let map = create_allow_ports_map();

        sync_firewall_allowed_ports_on(&map, FW_PORT_FAMILY_V4, &[(68, 17), (8080, 6)]).unwrap();
        sync_firewall_allowed_ports_on(&map, FW_PORT_FAMILY_V6, &[(546, 17)]).unwrap();
        assert!(contains(&map, &key(8080, 6, FW_PORT_FAMILY_V4)));

        // The port forward is removed from the configuration: the next IPv4
        // reconcile drops it ...
        let removed = sync_firewall_allowed_ports_on(&map, FW_PORT_FAMILY_V4, &[(68, 17)]).unwrap();
        assert_eq!(removed, 1, "expected exactly the stale port forward to be revoked");
        assert!(!contains(&map, &key(8080, 6, FW_PORT_FAMILY_V4)));
        assert!(contains(&map, &key(68, 17, FW_PORT_FAMILY_V4)));

        // ... while the IPv6 authorization is untouched by an IPv4 reconcile.
        assert!(contains(&map, &key(546, 17, FW_PORT_FAMILY_V6)));
        assert_eq!(keys_of_family(&map, FW_PORT_FAMILY_V6), 5);
    }

    /// An entry written by an older layout (the padding byte used to be zero)
    /// can never match the BPF lookup any more, so it is cleaned up rather than
    /// left to occupy a slot invisibly.
    #[test]
    fn legacy_entries_are_swept() {
        let map = create_allow_ports_map();
        let legacy = PortAllowKey { port: 8080u16.to_be(), protocol: 6, family: 0 };
        map.update(legacy.as_bytes(), &[1u8], MapFlags::ANY).unwrap();
        assert!(contains(&map, &legacy));

        sync_firewall_allowed_ports_on(&map, FW_PORT_FAMILY_V4, &[(68, 17)]).unwrap();
        assert!(!contains(&map, &legacy), "legacy-layout entry survived the reconcile");
    }
}
