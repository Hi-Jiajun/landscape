use std::collections::HashMap;
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd};

use landscape_common::flow::{
    FlowMarkInfo,
    mark::{FlowMark, FlowMarkAction},
};
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType, libbpf_sys};
use zerocopy::{FromBytes, IntoBytes};

use crate::maps::{
    FlowDnsMatchKeyV4, FlowDnsMatchKeyV6, FlowDnsMatchValueV4, FlowDnsMatchValueV6,
    LandscapeMapPath, LdEbpfResult,
};

const DNS_MATCH_MAX_ENTRIES: u32 = 10240;

/// Whether a stored DNS mark sends the traffic natively out of the WAN.
///
/// The inner map is keyed by destination address only, so two different DNS
/// rules that happen to resolve to the same shared address (a direct domain and
/// a proxied domain behind one CDN edge, or two different proxy tiers) collide
/// on a single slot. `Direct` (`0x0100`) is the only action that ignores the
/// flow configuration and sends the packet natively, so it must never win such
/// a collision: silently widening direct access is exactly the leak this map
/// has to prevent.
fn is_direct_mark(mark: u32) -> bool {
    FlowMark::from(mark).action() == FlowMarkAction::Direct
}

/// `true` when the two marks select different routing classes, i.e. when
/// arbitration really had to choose between two rules. Priority-only or
/// redirect-target-only differences are not routing conflicts.
fn routing_conflict(existing_mark: u32, new_mark: u32) -> bool {
    FlowMark::from(existing_mark).action() != FlowMark::from(new_mark).action()
}

/// Log a shared-address collision that arbitration resolved. The requirement is
/// that the losing rule must not be dropped silently, so every arbitration that
/// changes the outcome emits one line with both candidates.
fn warn_shared_address_conflict(
    addr: IpAddr,
    kept_mark: u32,
    kept_priority: u16,
    dropped_mark: u32,
    dropped_priority: u16,
) {
    tracing::warn!(
        "shared address {addr} is claimed by two DNS rules with different routing classes; \
         keeping mark={kept_mark:#06x} (priority {kept_priority}) instead of \
         mark={dropped_mark:#06x} (priority {dropped_priority})"
    );
}

/// Decide whether `new` may replace `existing` for the same address.
///
/// * A `Direct` candidate never displaces a non-direct entry, and a non-direct
///   candidate always displaces a `Direct` one — a shared address must not flip
///   from "proxied/blocked" to "native WAN" just because another rule answered
///   later.
/// * Within the same class the smaller `priority` wins, which is the ordering
///   the datapath itself applies (`dns_rule_value->priority <= priority`); the
///   priority carries the DNS rule's order in the flow configuration.
/// * Ties prefer the incoming value, so editing a rule in place still reaches
///   the map instead of being pinned by the entry written by the previous
///   configuration generation.
fn new_mark_wins(
    existing_mark: u32,
    existing_priority: u16,
    new_mark: u32,
    new_priority: u16,
) -> bool {
    match (is_direct_mark(existing_mark), is_direct_mark(new_mark)) {
        (false, true) => return false,
        (true, false) => return true,
        _ => {}
    }
    new_priority <= existing_priority
}

/// Fold one candidate into the per-address winner table of a single update.
///
/// `ips` is a `HashSet` upstream, so a batch can itself contain two rules for
/// the same address; without this fold the outcome of `update_batch` would
/// depend on iteration order.
fn arbitrate_batch_entry(
    winners: &mut HashMap<IpAddr, (u32, u16)>,
    addr: IpAddr,
    mark: u32,
    priority: u16,
) {
    match winners.get(&addr).copied() {
        None => {
            winners.insert(addr, (mark, priority));
        }
        Some((kept_mark, kept_priority)) => {
            let conflict = routing_conflict(kept_mark, mark);
            if new_mark_wins(kept_mark, kept_priority, mark, priority) {
                if conflict {
                    warn_shared_address_conflict(addr, mark, priority, kept_mark, kept_priority);
                }
                winners.insert(addr, (mark, priority));
            } else if conflict {
                warn_shared_address_conflict(addr, kept_mark, kept_priority, mark, priority);
            }
        }
    }
}

/// 相当于刷新现有的所有记录
pub fn refreash_flow_dns_inner_map(
    paths: &LandscapeMapPath,
    flow_id: u32,
    data: Vec<FlowMarkInfo>,
) {
    if let Ok(flow_dns_match_map) = libbpf_rs::MapHandle::from_pinned_path(&paths.flow4_dns_map) {
        create_flow_dns_inner_map_v4(&flow_dns_match_map, flow_id, &data);
    }

    if let Ok(flow_dns_match_map) = libbpf_rs::MapHandle::from_pinned_path(&paths.flow6_dns_map) {
        create_flow_dns_inner_map_v6(&flow_dns_match_map, flow_id, &data);
    }
}

// ==================
// IPv4
//

pub(crate) fn create_flow_dns_inner_map_v4<T>(
    flow_dns_outer_map: &T,
    flow_id: u32,
    data: &[FlowMarkInfo],
) where
    T: MapCore,
{
    #[allow(clippy::needless_update)]
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    let key_size = size_of::<FlowDnsMatchKeyV4>() as u32;
    let value_size = size_of::<FlowDnsMatchValueV4>() as u32;

    let map = match MapHandle::create(
        MapType::LruHash,
        Some(format!("flow4_dns_{}", flow_id)),
        key_size,
        value_size,
        DNS_MATCH_MAX_ENTRIES,
        &opts,
    ) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("failed to create inner flow4_dns map for flow {flow_id}: {e:?}");
            return;
        }
    };

    // Fresh inner map: there is no state to arbitrate against, only the
    // conflicts inside this batch.
    if let Err(e) = apply_flow_dns_rules_v4(&map, data, false) {
        // Do not publish a half-populated table: the previous inner map (if
        // any) stays in the outer slot, so the datapath keeps its last known
        // good rules instead of silently falling back to "no rule".
        tracing::error!(
            "failed to populate flow4_dns rules for flow {flow_id}: {e:?}; keeping the previous inner map"
        );
        return;
    }
    tracing::debug!("put data in map");

    let map_fd = map.as_fd().as_raw_fd();

    let key_value = flow_id.as_bytes();
    let value_value = map_fd.as_bytes();

    if let Err(e) = flow_dns_outer_map.update(key_value, value_value, MapFlags::ANY) {
        let last_os_error = std::io::Error::last_os_error();
        tracing::error!("Last OS error: {:?}", last_os_error);
        tracing::error!("Last OS error: {e:?}");
    }
}

#[allow(clippy::field_reassign_with_default)]
fn update_flow_dns_rules_v4<T>(map: &T, ips: &[FlowMarkInfo]) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    apply_flow_dns_rules_v4(map, ips, true)
}

/// Apply DNS marks to a per-flow inner map.
///
/// When `check_existing` is set the entries already stored for a reused inner
/// map are arbitrated against first; a freshly created map is known to be empty
/// and skips those lookups.
#[allow(clippy::field_reassign_with_default)]
fn apply_flow_dns_rules_v4<T>(
    map: &T,
    ips: &[FlowMarkInfo],
    check_existing: bool,
) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    if ips.is_empty() {
        return Ok(());
    }

    let mut winners: HashMap<IpAddr, (u32, u16)> = HashMap::new();
    for FlowMarkInfo { ip, mark, priority } in ips.iter() {
        if matches!(ip, IpAddr::V4(_)) {
            arbitrate_batch_entry(&mut winners, *ip, *mark, *priority);
        }
    }

    let mut keys = vec![];
    let mut values = vec![];
    let mut count = 0;

    for (addr, (mark, priority)) in winners.iter() {
        let mut key = FlowDnsMatchKeyV4::default();
        match addr {
            IpAddr::V4(ipv4_addr) => {
                key.addr = ipv4_addr.to_bits().to_be();
            }
            IpAddr::V6(_) => {
                continue;
            }
        };

        // An earlier answer may already occupy this slot, so compare against
        // the live entry as well instead of overwriting it blindly.
        let stored = if check_existing {
            map.lookup(key.as_bytes(), MapFlags::ANY)
                .ok()
                .flatten()
                .and_then(|bytes| FlowDnsMatchValueV4::read_from_bytes(&bytes).ok())
        } else {
            None
        };
        if let Some(stored) = stored {
            let conflict = routing_conflict(stored.mark, *mark);
            if new_mark_wins(stored.mark, stored.priority, *mark, *priority) {
                if conflict {
                    warn_shared_address_conflict(
                        *addr,
                        *mark,
                        *priority,
                        stored.mark,
                        stored.priority,
                    );
                }
            } else {
                if conflict {
                    warn_shared_address_conflict(
                        *addr,
                        stored.mark,
                        stored.priority,
                        *mark,
                        *priority,
                    );
                }
                continue;
            }
        }

        let mut value = FlowDnsMatchValueV4::default();
        value.mark = *mark;
        value.priority = *priority;

        keys.extend_from_slice(key.as_bytes());
        values.extend_from_slice(value.as_bytes());
        count += 1;
    }
    if count > 0 {
        map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)?;
    }
    Ok(())
}

// ==================
// IPv6
//

pub(crate) fn create_flow_dns_inner_map_v6<T>(
    flow_dns_outer_map: &T,
    flow_id: u32,
    data: &[FlowMarkInfo],
) where
    T: MapCore,
{
    #[allow(clippy::needless_update)]
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    let key_size = size_of::<FlowDnsMatchKeyV6>() as u32;
    let value_size = size_of::<FlowDnsMatchValueV6>() as u32;

    let map = match MapHandle::create(
        MapType::LruHash,
        Some(format!("flow6_dns_{}", flow_id)),
        key_size,
        value_size,
        DNS_MATCH_MAX_ENTRIES,
        &opts,
    ) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("failed to create inner flow6_dns map for flow {flow_id}: {e:?}");
            return;
        }
    };

    // See the IPv4 branch: freshly created map, batch-internal arbitration only.
    if let Err(e) = apply_flow_dns_rules_v6(&map, data, false) {
        // See the IPv4 branch: never publish a partially populated map.
        tracing::error!(
            "failed to populate flow6_dns rules for flow {flow_id}: {e:?}; keeping the previous inner map"
        );
        return;
    }
    tracing::debug!("put data in map");

    let map_fd = map.as_fd().as_raw_fd();

    let key_value = flow_id.as_bytes();
    let value_value = map_fd.as_bytes();

    if let Err(e) = flow_dns_outer_map.update(key_value, value_value, MapFlags::ANY) {
        let last_os_error = std::io::Error::last_os_error();
        tracing::error!("Last OS error: {:?}", last_os_error);
        tracing::error!("Last OS error: {e:?}");
    }
}

#[allow(clippy::field_reassign_with_default)]
fn update_flow_dns_rules_v6<T>(map: &T, ips: &[FlowMarkInfo]) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    apply_flow_dns_rules_v6(map, ips, true)
}

/// IPv6 counterpart of [`apply_flow_dns_rules_v4`].
#[allow(clippy::field_reassign_with_default)]
fn apply_flow_dns_rules_v6<T>(
    map: &T,
    ips: &[FlowMarkInfo],
    check_existing: bool,
) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    if ips.is_empty() {
        return Ok(());
    }

    let mut winners: HashMap<IpAddr, (u32, u16)> = HashMap::new();
    for FlowMarkInfo { ip, mark, priority } in ips.iter() {
        if matches!(ip, IpAddr::V6(_)) {
            arbitrate_batch_entry(&mut winners, *ip, *mark, *priority);
        }
    }

    let mut keys = vec![];
    let mut values = vec![];
    let mut count = 0;

    for (addr, (mark, priority)) in winners.iter() {
        let mut key = FlowDnsMatchKeyV6::default();
        match addr {
            IpAddr::V4(_) => {
                continue;
            }
            IpAddr::V6(ipv6_addr) => {
                key.addr = ipv6_addr.to_bits().to_be_bytes();
            }
        };

        // An earlier answer may already occupy this slot, so compare against
        // the live entry as well instead of overwriting it blindly.
        let stored = if check_existing {
            map.lookup(key.as_bytes(), MapFlags::ANY)
                .ok()
                .flatten()
                .and_then(|bytes| FlowDnsMatchValueV6::read_from_bytes(&bytes).ok())
        } else {
            None
        };
        if let Some(stored) = stored {
            let conflict = routing_conflict(stored.mark, *mark);
            if new_mark_wins(stored.mark, stored.priority, *mark, *priority) {
                if conflict {
                    warn_shared_address_conflict(
                        *addr,
                        *mark,
                        *priority,
                        stored.mark,
                        stored.priority,
                    );
                }
            } else {
                if conflict {
                    warn_shared_address_conflict(
                        *addr,
                        stored.mark,
                        stored.priority,
                        *mark,
                        *priority,
                    );
                }
                continue;
            }
        }

        let mut value = FlowDnsMatchValueV6::default();
        value.mark = *mark;
        value.priority = *priority;

        keys.extend_from_slice(key.as_bytes());
        values.extend_from_slice(value.as_bytes());
        count += 1;
    }
    if count > 0 {
        map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)?;
    }
    Ok(())
}

/// 只更新部分 DNS 指定的规则
pub fn update_flow_dns_rule(paths: &LandscapeMapPath, flow_id: u32, data: Vec<FlowMarkInfo>) {
    if let Ok(flow_dns_match_map) = libbpf_rs::MapHandle::from_pinned_path(&paths.flow4_dns_map) {
        let key_value = flow_id.as_bytes();
        if let Ok(Some(fd_id_arr)) = flow_dns_match_map.lookup(key_value, MapFlags::ANY) {
            if let Ok(fd) = i32::read_from_bytes(&fd_id_arr) {
                if let Ok(map) = libbpf_rs::MapHandle::from_map_id(fd as u32) {
                    if let Err(e) = update_flow_dns_rules_v4(&map, &data) {
                        tracing::error!(
                            "failed to apply incremental flow4_dns rules for flow {flow_id}: {e:?}"
                        );
                    }
                } else {
                    create_flow_dns_inner_map_v4(&flow_dns_match_map, flow_id, &data);
                }
            }
        } else {
            create_flow_dns_inner_map_v4(&flow_dns_match_map, flow_id, &data);
        }
    }

    if let Ok(flow_dns_match_map) = libbpf_rs::MapHandle::from_pinned_path(&paths.flow6_dns_map) {
        let key_value = flow_id.as_bytes();
        if let Ok(Some(fd_id_arr)) = flow_dns_match_map.lookup(key_value, MapFlags::ANY) {
            if let Ok(fd) = i32::read_from_bytes(&fd_id_arr) {
                if let Ok(map) = libbpf_rs::MapHandle::from_map_id(fd as u32) {
                    if let Err(e) = update_flow_dns_rules_v6(&map, &data) {
                        tracing::error!(
                            "failed to apply incremental flow6_dns rules for flow {flow_id}: {e:?}"
                        );
                    }
                } else {
                    create_flow_dns_inner_map_v6(&flow_dns_match_map, flow_id, &data);
                }
            }
        } else {
            create_flow_dns_inner_map_v6(&flow_dns_match_map, flow_id, &data);
        }
    }
}

pub fn delete_flow_dns(paths: &LandscapeMapPath, flow_id: u32) -> LdEbpfResult<()> {
    let key = flow_id.to_ne_bytes();
    let map4 = libbpf_rs::MapHandle::from_pinned_path(&paths.flow4_dns_map)?;
    delete_flow_dns_slot(&map4, &key, flow_id)?;
    let map6 = libbpf_rs::MapHandle::from_pinned_path(&paths.flow6_dns_map)?;
    delete_flow_dns_slot(&map6, &key, flow_id)?;
    Ok(())
}

/// Delete an outer slot, treating "no such entry" as success and reporting
/// every other failure to the caller.
fn delete_flow_dns_slot<T: MapCore>(map: &T, key: &[u8], flow_id: u32) -> LdEbpfResult<()> {
    match map.delete(key) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == libbpf_rs::ErrorKind::NotFound => Ok(()),
        Err(e) => {
            tracing::error!("failed to delete flow_dns slot for flow {flow_id}: {e:?}");
            Err(e.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const DIRECT: u32 = 0x0100;
    const DROP: u32 = 0x0200;
    /// `Redirect` to flow 5 (the AI tier in the production rules).
    const REDIRECT_AI: u32 = 0x0305;
    /// `Redirect` to flow 7 (a different proxy tier).
    const REDIRECT_MEDIA: u32 = 0x0307;

    #[test]
    fn direct_never_displaces_a_proxied_entry() {
        // A direct rule answers later for an address another rule proxies: the
        // proxied mark must survive, even though its priority is worse.
        assert!(!new_mark_wins(REDIRECT_AI, 200, DIRECT, 100));
        // Same for a blocked address.
        assert!(!new_mark_wins(DROP, 200, DIRECT, 100));
    }

    #[test]
    fn proxied_entry_displaces_a_direct_one() {
        assert!(new_mark_wins(DIRECT, 100, REDIRECT_AI, 200));
        assert!(new_mark_wins(DIRECT, 100, DROP, 200));
    }

    #[test]
    fn same_class_is_ordered_by_priority() {
        assert!(new_mark_wins(REDIRECT_AI, 900, REDIRECT_AI, 100));
        assert!(!new_mark_wins(REDIRECT_AI, 100, REDIRECT_AI, 900));
        // Different proxy tiers are not a routing conflict, only an order.
        assert!(!routing_conflict(REDIRECT_AI, REDIRECT_MEDIA));
    }

    #[test]
    fn tie_prefers_the_incoming_value() {
        // Same rule order but a different flow: an in-place rule edit has to
        // reach the map instead of being pinned by the previous generation.
        assert!(new_mark_wins(REDIRECT_AI, 100, REDIRECT_MEDIA, 100));
        // And an idempotent re-answer is still allowed to write the same value.
        assert!(new_mark_wins(REDIRECT_AI, 100, REDIRECT_AI, 100));
    }

    #[test]
    fn routing_conflict_tracks_the_action_only() {
        assert!(routing_conflict(DIRECT, REDIRECT_AI));
        assert!(!routing_conflict(DIRECT, DIRECT));
        // The reuse-port bit and the flow id do not change the routing class.
        assert!(!routing_conflict(DIRECT, 0x8100));
    }

    #[test]
    fn batch_arbitration_is_order_independent_for_shared_addresses() {
        let shared = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        let mut direct_first: HashMap<IpAddr, (u32, u16)> = HashMap::new();
        arbitrate_batch_entry(&mut direct_first, shared, DIRECT, 100);
        arbitrate_batch_entry(&mut direct_first, shared, REDIRECT_AI, 200);

        let mut proxy_first: HashMap<IpAddr, (u32, u16)> = HashMap::new();
        arbitrate_batch_entry(&mut proxy_first, shared, REDIRECT_AI, 200);
        arbitrate_batch_entry(&mut proxy_first, shared, DIRECT, 100);

        assert_eq!(direct_first.get(&shared), Some(&(REDIRECT_AI, 200)));
        assert_eq!(proxy_first.get(&shared), Some(&(REDIRECT_AI, 200)));
    }
}
