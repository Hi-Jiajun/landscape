use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::{
    Mutex, MutexGuard, OnceLock,
    atomic::{AtomicU64, Ordering as AtomicOrdering},
};

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

/// Upper bound on the remembered conflict identities that back the log dedup
/// below; the set is dropped wholesale when it fills up so memory stays bounded.
const CONFLICT_LOG_MEMORY: usize = 4096;

/// How often a deduplicated (suppressed) conflict is summarised in the log.
const SUPPRESSED_CONFLICT_REPORT_EVERY: u64 = 1000;

type ConflictId = (u8, [u8; 16], u32, u32);

/// One arbitration decision that changed the outcome for a shared address.
struct Conflict {
    addr: IpAddr,
    kept_mark: u32,
    kept_priority: u16,
    dropped_mark: u32,
    dropped_priority: u16,
}

/// Serialises every user-space update of the per-flow DNS maps.
///
/// The inner map holds exactly one mark per address, so arbitration is a
/// `lookup` followed by `update_batch`. That pair is not atomic on its own: two
/// DNS answers racing inside this process could otherwise write a `Direct` entry
/// on top of a proxied entry that appeared in between, which is precisely the
/// leak the arbitration exists to prevent. Every writer lives in this process,
/// so a single lock makes the read-decide-write sequence atomic.
static FLOW_DNS_WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Conflict identities already reported, so a conflict re-observed on every DNS
/// answer is logged once instead of on every answer.
static REPORTED_CONFLICTS: OnceLock<Mutex<HashSet<ConflictId>>> = OnceLock::new();

/// Number of conflict observations suppressed by the dedup above.
static SUPPRESSED_CONFLICTS: AtomicU64 = AtomicU64::new(0);

fn lock_flow_dns_writes() -> MutexGuard<'static, ()> {
    FLOW_DNS_WRITE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// How strongly a stored mark constrains the traffic, from widest to strictest.
///
/// The inner map holds one mark per address, so arbitration has to choose. This
/// order is deliberately *not* the datapath's own comparison: that one only
/// ranks a DNS answer against the per-flow IP rules. Here the question is which
/// of two rules may speak for a shared address, and the answer must never widen
/// access.
///
/// * `Direct` is the widest: the packet ignores the flow configuration and
///   leaves natively through the WAN.
/// * `KeepGoing` defers to the current flow's own policy. That is usually
///   narrower than `Direct` but cannot be proven so, and in the datapath it can
///   also override an earlier per-flow IP `Drop`/`Redirect` decision, so it must
///   not be treated as a proxy/block guarantee.
/// * `Redirect` keeps the traffic inside a managed proxy tier.
/// * `Drop` is the strictest: the traffic is refused outright, so a rule that
///   demands it always wins over a rule that would merely redirect.
fn preference_order(mark: u32) -> u8 {
    match FlowMark::from(mark).action() {
        FlowMarkAction::Direct => 0,
        FlowMarkAction::KeepGoing => 1,
        FlowMarkAction::Redirect => 2,
        FlowMarkAction::Drop => 3,
    }
}

/// The routing decision a mark represents, ignoring bookkeeping bits such as
/// `allow_reuse_port`.
///
/// Two marks with different identities send the traffic to different places,
/// which is what "conflict" means here. Two different proxy tiers count: they
/// are not interchangeable just because both are `Redirect`.
fn routing_identity(mark: u32) -> (u8, u8) {
    let mark = FlowMark::from(mark);
    (mark.action().into(), mark.flow_id())
}

fn is_conflict(existing_mark: u32, new_mark: u32) -> bool {
    routing_identity(existing_mark) != routing_identity(new_mark)
}

/// Total order used to fold several candidates for one address inside a single
/// update: stricter class first, then the smaller rule priority, then the
/// smaller raw mark.
///
/// The upstream call site hands over a `HashSet`, so a batch can itself contain
/// two rules for the same address; without a total order the winner of
/// `update_batch` would depend on iteration order.
fn fold_prefers(candidate: (u32, u16), incumbent: (u32, u16)) -> bool {
    let (candidate_mark, candidate_priority) = candidate;
    let (incumbent_mark, incumbent_priority) = incumbent;

    match preference_order(candidate_mark).cmp(&preference_order(incumbent_mark)) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => {
            (candidate_priority, candidate_mark) < (incumbent_priority, incumbent_mark)
        }
    }
}

/// Decide whether the incoming candidate may replace the entry already stored
/// for the same address.
///
/// * A stricter class always wins, so a shared address cannot flip to a wider
///   class just because another rule answered later.
/// * Within one class the smaller `priority` (the rule's order in the flow
///   configuration) wins, and equal priorities fall back to the smaller raw
///   mark — a total order, so the result never depends on arrival order.
///
/// An exact tie keeps the stored entry. Two rules only share a priority when
/// they are the same rule, so a class-equal, priority-equal, identity-different
/// pair means the same rule produced different marks in different configuration
/// generations; that case is resolved by the refresh path, which rebuilds the
/// inner map from scratch. Ordering cannot substitute for generation tracking,
/// which belongs to the DNS↔eBPF lifecycle work.
fn live_candidate_wins(
    existing_mark: u32,
    existing_priority: u16,
    new_mark: u32,
    new_priority: u16,
) -> bool {
    if (existing_mark, existing_priority) == (new_mark, new_priority) {
        return true;
    }

    match preference_order(new_mark).cmp(&preference_order(existing_mark)) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => (new_priority, new_mark) < (existing_priority, existing_mark),
    }
}

/// Fold one candidate into the per-address winner table of a single update,
/// recording the arbitration when it had to choose between two identities.
fn fold_candidate(
    winners: &mut HashMap<IpAddr, (u32, u16)>,
    addr: IpAddr,
    mark: u32,
    priority: u16,
) -> Option<Conflict> {
    match winners.get(&addr).copied() {
        None => {
            winners.insert(addr, (mark, priority));
            None
        }
        Some((kept_mark, kept_priority)) => {
            let conflict = is_conflict(kept_mark, mark);
            if fold_prefers((mark, priority), (kept_mark, kept_priority)) {
                winners.insert(addr, (mark, priority));
                conflict.then_some(Conflict {
                    addr,
                    kept_mark: mark,
                    kept_priority: priority,
                    dropped_mark: kept_mark,
                    dropped_priority: kept_priority,
                })
            } else {
                conflict.then_some(Conflict {
                    addr,
                    kept_mark,
                    kept_priority,
                    dropped_mark: mark,
                    dropped_priority: priority,
                })
            }
        }
    }
}

fn conflict_id(addr: &IpAddr, kept_mark: u32, dropped_mark: u32) -> ConflictId {
    match addr {
        IpAddr::V4(v4) => {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&v4.octets());
            (4, bytes, kept_mark, dropped_mark)
        }
        IpAddr::V6(v6) => (6, v6.octets(), kept_mark, dropped_mark),
    }
}

/// Report the arbitrations that changed the outcome for a shared address.
///
/// Called only after the batch has been committed, so "keeping" is a statement
/// about state that is actually in the map. Each conflict identity is logged
/// once: a conflict that keeps recurring is counted and summarised instead of
/// being repeated line per DNS answer.
fn report_conflicts(flow_id: u32, conflicts: &[Conflict]) {
    if conflicts.is_empty() {
        return;
    }

    let reported = REPORTED_CONFLICTS.get_or_init(|| Mutex::new(HashSet::new()));
    let mut reported = reported.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    for conflict in conflicts {
        let id = conflict_id(&conflict.addr, conflict.kept_mark, conflict.dropped_mark);
        if reported.len() >= CONFLICT_LOG_MEMORY {
            reported.clear();
        }
        if reported.insert(id) {
            tracing::warn!(
                flow_id,
                addr = %conflict.addr,
                kept_mark = conflict.kept_mark,
                kept_priority = conflict.kept_priority,
                dropped_mark = conflict.dropped_mark,
                dropped_priority = conflict.dropped_priority,
                "shared address claimed by two DNS rules with different routing; keeping the \
                 stricter/higher-precedence mark, the other rule is recorded but not applied"
            );
        } else {
            let suppressed = SUPPRESSED_CONFLICTS.fetch_add(1, AtomicOrdering::Relaxed) + 1;
            if suppressed.is_multiple_of(SUPPRESSED_CONFLICT_REPORT_EVERY) {
                tracing::warn!(
                    suppressed_conflicts = suppressed,
                    "shared-address arbitration keeps resolving conflicts; \
                     only the first occurrence of each pair is logged individually"
                );
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
    // Rebuilding the outer slots has to be mutually exclusive with the
    // incremental path too, otherwise an answer could be applied to the inner
    // map that is being replaced.
    let _guard = lock_flow_dns_writes();

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
    if let Err(e) = apply_flow_dns_rules_v4(&map, flow_id, data, false) {
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

fn update_flow_dns_rules_v4<T>(map: &T, flow_id: u32, ips: &[FlowMarkInfo]) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    apply_flow_dns_rules_v4(map, flow_id, ips, true)
}

/// Apply DNS marks to a per-flow inner map.
///
/// When `check_existing` is set the entries already stored for a reused inner
/// map are arbitrated against first; a freshly created map is known to be empty
/// and skips those lookups.
///
/// The caller must hold [`FLOW_DNS_WRITE_LOCK`] so that the `lookup`/decide/
/// `update_batch` sequence below cannot interleave with another writer.
fn apply_flow_dns_rules_v4<T>(
    map: &T,
    flow_id: u32,
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
    let mut conflicts = vec![];
    for FlowMarkInfo { ip, mark, priority } in ips.iter() {
        if matches!(ip, IpAddr::V4(_))
            && let Some(conflict) = fold_candidate(&mut winners, *ip, *mark, *priority)
        {
            conflicts.push(conflict);
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
            match map.lookup(key.as_bytes(), MapFlags::ANY) {
                Ok(value) => {
                    value.and_then(|bytes| FlowDnsMatchValueV4::read_from_bytes(&bytes).ok())
                }
                Err(e) => {
                    // The stored value is unknown, and guessing "absent" here
                    // could replace a proxied entry with a direct one. Fail
                    // closed: leave the address exactly as the datapath has it.
                    tracing::error!(
                        flow_id,
                        addr = %addr,
                        "cannot read the stored DNS mark ({e:?}); leaving the address unchanged"
                    );
                    continue;
                }
            }
        } else {
            None
        };
        if let Some(stored) = stored {
            if !live_candidate_wins(stored.mark, stored.priority, *mark, *priority) {
                if is_conflict(stored.mark, *mark) {
                    conflicts.push(Conflict {
                        addr: *addr,
                        kept_mark: stored.mark,
                        kept_priority: stored.priority,
                        dropped_mark: *mark,
                        dropped_priority: *priority,
                    });
                }
                continue;
            }
            if is_conflict(stored.mark, *mark) {
                conflicts.push(Conflict {
                    addr: *addr,
                    kept_mark: *mark,
                    kept_priority: *priority,
                    dropped_mark: stored.mark,
                    dropped_priority: stored.priority,
                });
            }
        }

        let value = FlowDnsMatchValueV4 { mark: *mark, priority: *priority, _pad: [0; 2] };

        keys.extend_from_slice(key.as_bytes());
        values.extend_from_slice(value.as_bytes());
        count += 1;
    }
    if count > 0 {
        map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)?;
    }
    // Reported only once the batch is committed, so the message describes the
    // state that is actually in the map.
    report_conflicts(flow_id, &conflicts);
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
    if let Err(e) = apply_flow_dns_rules_v6(&map, flow_id, data, false) {
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

fn update_flow_dns_rules_v6<T>(map: &T, flow_id: u32, ips: &[FlowMarkInfo]) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    apply_flow_dns_rules_v6(map, flow_id, ips, true)
}

/// IPv6 counterpart of [`apply_flow_dns_rules_v4`].
fn apply_flow_dns_rules_v6<T>(
    map: &T,
    flow_id: u32,
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
    let mut conflicts = vec![];
    for FlowMarkInfo { ip, mark, priority } in ips.iter() {
        if matches!(ip, IpAddr::V6(_))
            && let Some(conflict) = fold_candidate(&mut winners, *ip, *mark, *priority)
        {
            conflicts.push(conflict);
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
            match map.lookup(key.as_bytes(), MapFlags::ANY) {
                Ok(value) => {
                    value.and_then(|bytes| FlowDnsMatchValueV6::read_from_bytes(&bytes).ok())
                }
                Err(e) => {
                    // See the IPv4 branch: an unreadable entry is not an absent
                    // one, so leave the address untouched.
                    tracing::error!(
                        flow_id,
                        addr = %addr,
                        "cannot read the stored DNS mark ({e:?}); leaving the address unchanged"
                    );
                    continue;
                }
            }
        } else {
            None
        };
        if let Some(stored) = stored {
            if !live_candidate_wins(stored.mark, stored.priority, *mark, *priority) {
                if is_conflict(stored.mark, *mark) {
                    conflicts.push(Conflict {
                        addr: *addr,
                        kept_mark: stored.mark,
                        kept_priority: stored.priority,
                        dropped_mark: *mark,
                        dropped_priority: *priority,
                    });
                }
                continue;
            }
            if is_conflict(stored.mark, *mark) {
                conflicts.push(Conflict {
                    addr: *addr,
                    kept_mark: *mark,
                    kept_priority: *priority,
                    dropped_mark: stored.mark,
                    dropped_priority: stored.priority,
                });
            }
        }

        let value = FlowDnsMatchValueV6 { mark: *mark, priority: *priority, _pad: [0; 2] };

        keys.extend_from_slice(key.as_bytes());
        values.extend_from_slice(value.as_bytes());
        count += 1;
    }
    if count > 0 {
        map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)?;
    }
    report_conflicts(flow_id, &conflicts);
    Ok(())
}

/// 只更新部分 DNS 指定的规则
pub fn update_flow_dns_rule(paths: &LandscapeMapPath, flow_id: u32, data: Vec<FlowMarkInfo>) {
    let _guard = lock_flow_dns_writes();

    if let Ok(flow_dns_match_map) = libbpf_rs::MapHandle::from_pinned_path(&paths.flow4_dns_map) {
        let key_value = flow_id.as_bytes();
        if let Ok(Some(fd_id_arr)) = flow_dns_match_map.lookup(key_value, MapFlags::ANY) {
            if let Ok(fd) = i32::read_from_bytes(&fd_id_arr) {
                if let Ok(map) = libbpf_rs::MapHandle::from_map_id(fd as u32) {
                    if let Err(e) = update_flow_dns_rules_v4(&map, flow_id, &data) {
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
                    if let Err(e) = update_flow_dns_rules_v6(&map, flow_id, &data) {
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
    let _guard = lock_flow_dns_writes();

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
    const KEEP_GOING: u32 = 0x0000;
    /// `Redirect` to flow 5 (the AI tier in the production rules).
    const REDIRECT_AI: u32 = 0x0305;
    /// `Redirect` to flow 7 (a different proxy tier).
    const REDIRECT_MEDIA: u32 = 0x0307;

    #[test]
    fn wider_classes_never_displace_stricter_ones() {
        // A direct rule answers later for an address another rule proxies: the
        // proxied mark must survive, even though its priority is worse.
        assert!(!live_candidate_wins(REDIRECT_AI, 200, DIRECT, 100));
        // Same for a blocked address.
        assert!(!live_candidate_wins(DROP, 200, DIRECT, 100));
        // `KeepGoing` defers to the flow's own policy and can still end up
        // natively out, so it must not displace a managed tier either.
        assert!(!live_candidate_wins(REDIRECT_AI, 200, KEEP_GOING, 100));
        // A rule that demands blocking outranks a rule that would only redirect.
        assert!(!live_candidate_wins(DROP, 900, REDIRECT_AI, 100));
    }

    #[test]
    fn stricter_classes_displace_wider_ones() {
        assert!(live_candidate_wins(DIRECT, 100, REDIRECT_AI, 200));
        assert!(live_candidate_wins(DIRECT, 100, DROP, 200));
        assert!(live_candidate_wins(KEEP_GOING, 100, REDIRECT_AI, 200));
        assert!(live_candidate_wins(REDIRECT_AI, 100, DROP, 200));
        // `KeepGoing` is never wider than an explicit `Direct`.
        assert!(live_candidate_wins(DIRECT, 100, KEEP_GOING, 200));
    }

    #[test]
    fn same_class_is_ordered_by_priority_then_mark() {
        assert!(live_candidate_wins(REDIRECT_AI, 900, REDIRECT_AI, 100));
        assert!(!live_candidate_wins(REDIRECT_AI, 100, REDIRECT_AI, 900));
        // Same priority, different tier: deterministic, smaller mark wins, and
        // the arbitration is reported instead of passing silently.
        assert!(is_conflict(REDIRECT_AI, REDIRECT_MEDIA));
        assert!(live_candidate_wins(REDIRECT_MEDIA, 100, REDIRECT_AI, 100));
        assert!(!live_candidate_wins(REDIRECT_AI, 100, REDIRECT_MEDIA, 100));
    }

    #[test]
    fn identical_candidates_are_a_no_op() {
        assert!(live_candidate_wins(REDIRECT_AI, 100, REDIRECT_AI, 100));
        assert!(!is_conflict(REDIRECT_AI, 0x8305));
    }

    #[test]
    fn conflicts_cover_actions_and_redirect_targets() {
        assert!(is_conflict(DIRECT, REDIRECT_AI));
        assert!(is_conflict(KEEP_GOING, DIRECT));
        assert!(is_conflict(REDIRECT_AI, REDIRECT_MEDIA));
        assert!(!is_conflict(DIRECT, DIRECT));
        // The reuse-port bit does not change where the traffic goes.
        assert!(!is_conflict(DIRECT, 0x8100));
    }

    #[test]
    fn batch_arbitration_is_order_independent_for_shared_addresses() {
        let shared = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        let mut direct_first: HashMap<IpAddr, (u32, u16)> = HashMap::new();
        fold_candidate(&mut direct_first, shared, DIRECT, 100);
        fold_candidate(&mut direct_first, shared, REDIRECT_AI, 200);

        let mut proxy_first: HashMap<IpAddr, (u32, u16)> = HashMap::new();
        fold_candidate(&mut proxy_first, shared, REDIRECT_AI, 200);
        fold_candidate(&mut proxy_first, shared, DIRECT, 100);

        assert_eq!(direct_first.get(&shared), Some(&(REDIRECT_AI, 200)));
        assert_eq!(proxy_first.get(&shared), Some(&(REDIRECT_AI, 200)));

        // Two proxy tiers at the same priority: still order independent.
        let mut ai_first: HashMap<IpAddr, (u32, u16)> = HashMap::new();
        fold_candidate(&mut ai_first, shared, REDIRECT_AI, 100);
        fold_candidate(&mut ai_first, shared, REDIRECT_MEDIA, 100);

        let mut media_first: HashMap<IpAddr, (u32, u16)> = HashMap::new();
        fold_candidate(&mut media_first, shared, REDIRECT_MEDIA, 100);
        fold_candidate(&mut media_first, shared, REDIRECT_AI, 100);

        assert_eq!(ai_first.get(&shared), Some(&(REDIRECT_AI, 100)));
        assert_eq!(media_first.get(&shared), Some(&(REDIRECT_AI, 100)));
    }

    #[test]
    fn batch_fold_reports_the_losing_rule() {
        let shared = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let mut winners: HashMap<IpAddr, (u32, u16)> = HashMap::new();

        assert!(fold_candidate(&mut winners, shared, DIRECT, 100).is_none());
        let conflict = fold_candidate(&mut winners, shared, REDIRECT_AI, 200)
            .expect("a direct and a proxied rule for one address is a conflict");
        assert_eq!(conflict.kept_mark, REDIRECT_AI);
        assert_eq!(conflict.dropped_mark, DIRECT);

        // Same identity again is not a conflict, only a repeated answer.
        assert!(fold_candidate(&mut winners, shared, REDIRECT_AI, 200).is_none());
    }
}
