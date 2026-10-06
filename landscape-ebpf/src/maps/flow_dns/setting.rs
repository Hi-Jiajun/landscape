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

/// Address family tag used in [`FlowDnsWriteError`] so one message covers both
/// inner maps.
const FAMILY_V4: &str = "4";
const FAMILY_V6: &str = "6";

/// A `(ip, mark)` association could not be written into the datapath.
///
/// This is not a cosmetic failure: the DNS layer refuses to hand an answer to
/// the client when the mark it carries is the only thing keeping the traffic in
/// a managed scope, so the reason for the failure has to survive up to that
/// decision.
#[derive(Debug, thiserror::Error)]
pub enum FlowDnsWriteError {
    #[error("cannot open the pinned flow{family}_dns outer map: {source}")]
    OuterMap {
        family: &'static str,
        #[source]
        source: libbpf_rs::Error,
    },

    #[error("flow{family}_dns inner map for flow {flow_id} is unavailable: {reason}")]
    InnerMap { family: &'static str, flow_id: u32, reason: String },

    #[error("writing flow{family}_dns marks for flow {flow_id} failed: {source}")]
    Write {
        family: &'static str,
        flow_id: u32,
        #[source]
        source: libbpf_rs::Error,
    },

    /// The answer belongs to a rule generation a rebuild has already replaced.
    ///
    /// It was produced under rules that no longer exist, so its mark must not be
    /// installed: doing so would re-apply the configuration the change replaced,
    /// for that address, for as long as the entry lives.
    #[error(
        "flow {flow_id}: answer belongs to rule generation {answer_generation}, \
         but generation {published_generation} is already in effect"
    )]
    Superseded { flow_id: u32, answer_generation: u64, published_generation: u64 },
}

/// Upper bound on the remembered conflict identities that back the log dedup
/// below; the set is dropped wholesale when it fills up so memory stays bounded.
const CONFLICT_LOG_MEMORY: usize = 4096;

/// How often a deduplicated (suppressed) conflict is summarised in the log.
const SUPPRESSED_CONFLICT_REPORT_EVERY: u64 = 1000;

type ConflictId = (u8, [u8; 16], u32, u32);

/// One arbitration decision that changed the outcome for a shared address.
struct Conflict {
    addr: IpAddr,
    /// The claim that was applied.
    kept: Candidate,
    /// The claim that was left out.
    dropped: Candidate,
    /// True when both claims are equally strict, so the strictness ladder did
    /// not decide this: only the policy did. These are the pairs that need the
    /// rules reconciled — under the default policy the address is refused.
    equipollent: bool,
}

/// The `Drop` mark written when two rules that would send the traffic to
/// different places claim one address.
///
/// Choosing either rule would hand one of the two domains a tier it did not ask
/// for, so the address is refused instead: no managed traffic leaves natively
/// and neither tier is silently picked. `0x0200` is `FlowMarkAction::Drop`; the
/// flow id is not encoded for `Drop`, so every block carries the same mark.
const SYNTHESIZED_BLOCK_MARK: u32 = 0x0200;

/// What to do when two equally strict rules claim one address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ConflictPolicy {
    /// Refuse the address. Neither rule may be preferred and both are equally
    /// strong, so the address is blocked; the conflict is reported either way.
    Block,
    /// Keep the deterministic winner and only report the conflict. Used to
    /// measure the blast radius of [`ConflictPolicy::Block`] on a live gateway
    /// before it starts refusing addresses.
    ReportOnly,
}

/// Policy selection, read once from `LANDSCAPE_FLOW_DNS_CONFLICT_POLICY`.
///
/// `block` is the default because a shared address that two rules disagree
/// about cannot be routed correctly for both. `report` exists so the same code
/// can run on a production gateway in observation mode first: it logs exactly
/// which addresses *would* be blocked, without refusing them.
fn conflict_policy() -> ConflictPolicy {
    static POLICY: OnceLock<ConflictPolicy> = OnceLock::new();
    *POLICY.get_or_init(|| {
        let raw = std::env::var("LANDSCAPE_FLOW_DNS_CONFLICT_POLICY").unwrap_or_default();
        match raw.trim().to_ascii_lowercase().as_str() {
            "report" | "report-only" | "report_only" | "observe" => {
                tracing::warn!(
                    "flow-dns conflict policy is 'report': conflicting shared addresses are \
                     logged but not blocked"
                );
                ConflictPolicy::ReportOnly
            }
            "block" | "" => ConflictPolicy::Block,
            other => {
                tracing::error!(
                    "unknown LANDSCAPE_FLOW_DNS_CONFLICT_POLICY '{other}'; using 'block'"
                );
                ConflictPolicy::Block
            }
        }
    })
}

/// `_pad[0]` of a stored value: set when the entry is a synthesized block, so a
/// later full rebuild (which recomputes every address from the whole cache) can
/// tell a refused address apart from a rule that genuinely asks for `Drop`.
/// The datapath reads only `mark`/`priority`, so the value layout is unchanged.
const VALUE_FLAG_SYNTHESIZED_BLOCK: u8 = 1;

/// One rule's claim on an address: its mark, the order of the rule it came from,
/// and whether this is the synthesized block instead of a rule's own mark.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Candidate {
    mark: u32,
    priority: u16,
    synthesized_block: bool,
}

impl Candidate {
    fn from_rule(mark: u32, priority: u16) -> Self {
        Self { mark, priority, synthesized_block: false }
    }

    fn from_stored(mark: u32, priority: u16, pad: u8) -> Self {
        Self {
            mark,
            priority,
            synthesized_block: pad & VALUE_FLAG_SYNTHESIZED_BLOCK != 0,
        }
    }

    fn block(priority: u16) -> Self {
        Self {
            mark: SYNTHESIZED_BLOCK_MARK,
            priority,
            synthesized_block: true,
        }
    }
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

/// Rule generation each flow's mark table currently reflects.
///
/// A query keeps the runtime snapshot it started with, so it can finish after a
/// rule change already rebuilt and published the table. Admitting only writes
/// that match the published generation keeps the replaced rules from being
/// re-applied to one address.
///
/// The check runs **inside** [`FLOW_DNS_WRITE_LOCK`] together with the write it
/// guards. Checking and writing as two separate steps would leave exactly the
/// window this exists to close: an answer could pass the check, the rebuild
/// could publish, and the answer would then write the old mark over the new one.
static PUBLISHED_GENERATION: OnceLock<Mutex<HashMap<u32, u64>>> = OnceLock::new();

fn published_generations() -> &'static Mutex<HashMap<u32, u64>> {
    PUBLISHED_GENERATION.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Conflict identities already reported, so a conflict re-observed on every DNS
/// answer is logged once instead of on every answer.
static REPORTED_CONFLICTS: OnceLock<Mutex<HashSet<ConflictId>>> = OnceLock::new();

/// Number of conflict observations suppressed by the dedup above.
static SUPPRESSED_CONFLICTS: AtomicU64 = AtomicU64::new(0);

fn lock_flow_dns_writes() -> MutexGuard<'static, ()> {
    FLOW_DNS_WRITE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The generation currently published for a flow, if any.
pub fn published_generation(flow_id: u32) -> Option<u64> {
    published_generations()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&flow_id)
        .copied()
}

/// Admit an incremental write that belongs to `generation`.
///
/// Only the published generation is accepted. An answer from a different
/// generation cannot be evaluated against the live rules — it may be older (the
/// rules it used are gone) or newer (it was produced by a rebuild that has not
/// published yet, so installing it would put part of an unpublished
/// configuration into the live table).
fn admit_generation(flow_id: u32, generation: u64) -> Result<(), FlowDnsWriteError> {
    let mut published =
        published_generations().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    match published.get(&flow_id) {
        Some(current) if *current == generation => Ok(()),
        Some(current) => Err(FlowDnsWriteError::Superseded {
            flow_id,
            answer_generation: generation,
            published_generation: *current,
        }),
        // No generation published yet for this flow: the writer ran before any
        // rebuild, so its answer is the only information available.
        None => {
            published.insert(flow_id, generation);
            Ok(())
        }
    }
}

/// Publish `generation` as the one the flow's table now reflects.
///
/// Called by the rebuild path, which is authoritative: it recomputes every mark
/// from the whole cache, and it advances the generation even when the table it
/// publishes is empty (an empty table means the new rules removed the marks, so
/// an answer from the old generation must not put them back).
fn publish_generation(flow_id: u32, generation: u64) {
    published_generations()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(flow_id, generation);
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
    let action: u8 = mark.action().into();
    match mark.action() {
        // Only a redirect encodes a target flow; everything else resolves
        // against the packet's own flow, so stray low bits must not look like a
        // second identity.
        FlowMarkAction::Redirect => (action, mark.flow_id()),
        _ => (action, 0),
    }
}

/// Order two candidates: stricter class first, then the smaller rule priority,
/// then the smaller raw mark, and finally a real rule over a synthesized block.
///
/// The upstream call site hands over a `HashSet`, so a batch can itself contain
/// two rules for the same address; without a total order the winner of
/// `update_batch` would depend on iteration order.
fn candidate_better(candidate: &Candidate, incumbent: &Candidate) -> bool {
    match preference_order(candidate.mark).cmp(&preference_order(incumbent.mark)) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => match candidate.priority.cmp(&incumbent.priority) {
            Ordering::Less => true,
            Ordering::Greater => false,
            Ordering::Equal => match candidate.mark.cmp(&incumbent.mark) {
                Ordering::Less => true,
                Ordering::Greater => false,
                // Same outcome either way; prefer the rule's own mark so a real
                // `Drop` rule is not relabelled as a synthesized block.
                Ordering::Equal => !candidate.synthesized_block && incumbent.synthesized_block,
            },
        },
    }
}

/// Fold one candidate into `by_address`, keeping the best claim per routing
/// identity so that a later scan can tell a decided conflict (different
/// strictness) from one the arbitration has to refuse (same strictness).
fn fold_candidate(
    by_address: &mut HashMap<IpAddr, Vec<Candidate>>,
    addr: IpAddr,
    candidate: Candidate,
) {
    let claims = by_address.entry(addr).or_default();
    let identity = routing_identity(candidate.mark);
    match claims.iter_mut().find(|kept| routing_identity(kept.mark) == identity) {
        Some(kept) => {
            if candidate_better(&candidate, kept) {
                *kept = candidate;
            }
        }
        None => claims.push(candidate),
    }
}

/// Turn the claims on one address into the value to store, plus the conflict to
/// report when more than one rule spoke for it.
///
/// * One claim: store it.
/// * Several claims with different strictness: the stricter one wins, which is
///   a decision (a direct rule cannot overrule a proxied one, `Drop` outranks
///   `Redirect`, and so on).
/// * Several claims that are equally strict but incompatible — the two
///   different proxy tiers are the real case: neither may be preferred, so the
///   address is blocked instead. `priority` is the smallest of the claims so the
///   block is at least as strong as the strictest rule that asked for it.
fn settle_claims(
    addr: IpAddr,
    claims: &[Candidate],
    policy: ConflictPolicy,
) -> (Candidate, Option<Conflict>) {
    let mut claims = claims.iter();
    let first = *claims.next().expect("an address is only tracked once a claim exists");
    let mut best = first;
    let mut rival: Option<Candidate> = None;

    for claim in claims {
        if routing_identity(claim.mark) == routing_identity(best.mark) {
            if candidate_better(claim, &best) {
                best = *claim;
            }
            continue;
        }
        if candidate_better(claim, &best) {
            rival = Some(best);
            best = *claim;
        } else if rival.is_none_or(|kept| candidate_better(claim, &kept)) {
            rival = Some(*claim);
        }
    }

    let Some(rival) = rival else {
        return (best, None);
    };

    let block = preference_order(rival.mark) == preference_order(best.mark);
    if block && policy == ConflictPolicy::Block {
        let priority = best.priority.min(rival.priority);
        // Neither claim may be preferred, so refuse the address. Report the
        // weaker claim as the dropped one so the log names the rule that would
        // have lost the deterministic tie-break.
        let dropped = if candidate_better(&best, &rival) { rival } else { best };
        (
            Candidate::block(priority),
            Some(Conflict {
                addr,
                kept: Candidate::block(priority),
                dropped,
                equipollent: true,
            }),
        )
    } else {
        // Either the strictness ladder decided this, or the policy is set to
        // report only. `rival` is reported as the losing claim; `equipollent`
        // keeps the report-only case distinguishable from a decision, so the log
        // still says which pairs the default policy would refuse.
        (
            best,
            Some(Conflict {
                addr,
                kept: best,
                dropped: rival,
                equipollent: block,
            }),
        )
    }
}

/// Settle the claims known for one address together with the claim the datapath
/// already holds for it.
///
/// A reused inner map still carries the decision of an earlier answer, and that
/// decision is only meaningful for the claims that existed then. Joining it with
/// the claims known now means an address that was refused because two tiers
/// claimed it stays refused until a full rebuild recomputes it from the whole
/// cache — one tier answering again must not silently take the address over.
fn settle_with_stored(
    addr: IpAddr,
    claims: &[Candidate],
    stored: Option<Candidate>,
    policy: ConflictPolicy,
) -> (Candidate, Option<Conflict>) {
    let Some(stored) = stored else {
        return settle_claims(addr, claims, policy);
    };

    let mut union: HashMap<IpAddr, Vec<Candidate>> = HashMap::new();
    for claim in claims {
        fold_candidate(&mut union, addr, *claim);
    }
    fold_candidate(&mut union, addr, stored);
    settle_claims(addr, &union[&addr], policy)
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
fn report_conflicts(flow_id: u32, conflicts: &[Conflict], policy: ConflictPolicy) {
    if conflicts.is_empty() {
        return;
    }

    let reported = REPORTED_CONFLICTS.get_or_init(|| Mutex::new(HashSet::new()));
    let mut reported = reported.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    for conflict in conflicts {
        let id = conflict_id(&conflict.addr, conflict.kept.mark, conflict.dropped.mark);
        if reported.len() >= CONFLICT_LOG_MEMORY {
            reported.clear();
        }
        if reported.insert(id) {
            if conflict.kept.synthesized_block {
                tracing::warn!(
                    flow_id,
                    addr = %conflict.addr,
                    blocked_priority = conflict.kept.priority,
                    refused_mark = conflict.dropped.mark,
                    refused_priority = conflict.dropped.priority,
                    "shared address is claimed by two DNS rules with different routing at equal \
                     strictness; blocking the address instead of silently choosing one tier"
                );
            } else if conflict.equipollent && policy == ConflictPolicy::ReportOnly {
                tracing::warn!(
                    flow_id,
                    addr = %conflict.addr,
                    kept_mark = conflict.kept.mark,
                    kept_priority = conflict.kept.priority,
                    dropped_mark = conflict.dropped.mark,
                    dropped_priority = conflict.dropped.priority,
                    "shared address is claimed by two DNS rules with different routing at equal \
                     strictness; report-only policy keeps the higher-precedence rule (this address \
                     would be blocked under the default policy)"
                );
            } else {
                tracing::warn!(
                    flow_id,
                    addr = %conflict.addr,
                    kept_mark = conflict.kept.mark,
                    kept_priority = conflict.kept.priority,
                    dropped_mark = conflict.dropped.mark,
                    dropped_priority = conflict.dropped.priority,
                    "shared address claimed by two DNS rules with different routing; keeping the \
                     stricter/higher-precedence mark, the other rule is recorded but not applied"
                );
            }
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
///
/// Returns the first failure of either family. A partial refresh is not rolled
/// back: the family that did get written holds the freshly computed state, which
/// is the state the caller derived, while the family that failed keeps its
/// previous inner map (see `create_flow_dns_inner_map_*`).
pub fn refreash_flow_dns_inner_map(
    paths: &LandscapeMapPath,
    flow_id: u32,
    generation: u64,
    data: Vec<FlowMarkInfo>,
) -> Result<(), FlowDnsWriteError> {
    // Rebuilding the outer slots has to be mutually exclusive with the
    // incremental path too, otherwise an answer could be applied to the inner
    // map that is being replaced.
    let _guard = lock_flow_dns_writes();
    // The rebuild is authoritative: publishing its generation under the same
    // lock means no incremental write can slip between "the table is rebuilt"
    // and "the generation changed".
    publish_generation(flow_id, generation);

    let v4 = match libbpf_rs::MapHandle::from_pinned_path(&paths.flow4_dns_map) {
        Ok(outer) => create_flow_dns_inner_map_v4(&outer, flow_id, &data),
        Err(source) => Err(FlowDnsWriteError::OuterMap { family: FAMILY_V4, source }),
    };
    let v6 = match libbpf_rs::MapHandle::from_pinned_path(&paths.flow6_dns_map) {
        Ok(outer) => create_flow_dns_inner_map_v6(&outer, flow_id, &data),
        Err(source) => Err(FlowDnsWriteError::OuterMap { family: FAMILY_V6, source }),
    };

    v4.and(v6)
}

// ==================
// IPv4
//

pub(crate) fn create_flow_dns_inner_map_v4<T>(
    flow_dns_outer_map: &T,
    flow_id: u32,
    data: &[FlowMarkInfo],
) -> Result<(), FlowDnsWriteError>
where
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
            return Err(FlowDnsWriteError::InnerMap {
                family: FAMILY_V4,
                flow_id,
                reason: format!("cannot create the inner map: {e:?}"),
            });
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
        return Err(FlowDnsWriteError::Write { family: FAMILY_V4, flow_id, source: e });
    }
    tracing::debug!("put data in map");

    let map_fd = map.as_fd().as_raw_fd();

    let key_value = flow_id.as_bytes();
    let value_value = map_fd.as_bytes();

    if let Err(e) = flow_dns_outer_map.update(key_value, value_value, MapFlags::ANY) {
        let last_os_error = std::io::Error::last_os_error();
        tracing::error!("Last OS error: {:?}", last_os_error);
        tracing::error!("failed to publish flow4_dns inner map for flow {flow_id}: {e:?}");
        return Err(FlowDnsWriteError::Write { family: FAMILY_V4, flow_id, source: e });
    }

    Ok(())
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

    let mut claims: HashMap<IpAddr, Vec<Candidate>> = HashMap::new();
    for FlowMarkInfo { ip, mark, priority } in ips.iter() {
        if matches!(ip, IpAddr::V4(_)) {
            fold_candidate(&mut claims, *ip, Candidate::from_rule(*mark, *priority));
        }
    }

    let mut keys = vec![];
    let mut values = vec![];
    let mut count = 0;
    let mut conflicts = vec![];
    let policy = conflict_policy();

    for (addr, claims) in claims.iter() {
        let mut key = FlowDnsMatchKeyV4::default();
        match addr {
            IpAddr::V4(ipv4_addr) => {
                key.addr = ipv4_addr.to_bits().to_be();
            }
            IpAddr::V6(_) => {
                continue;
            }
        };

        // A reused inner map may already hold a claim for this address; the
        // settled value is only valid for the claims that exist now, so the
        // stored one joins them and the arbitration runs over the union.
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

        let stored_candidate = stored
            .map(|stored| Candidate::from_stored(stored.mark, stored.priority, stored._pad[0]));
        let (settled, conflict) = settle_with_stored(*addr, claims, stored_candidate, policy);

        let unchanged = stored_candidate.is_some_and(|stored| {
            stored.mark == settled.mark
                && stored.priority == settled.priority
                && stored.synthesized_block == settled.synthesized_block
        });
        if unchanged {
            // The datapath already holds this decision, so there is nothing to
            // write and nothing new to report.
            continue;
        }

        let pad = [if settled.synthesized_block { VALUE_FLAG_SYNTHESIZED_BLOCK } else { 0 }, 0];
        let value = FlowDnsMatchValueV4 {
            mark: settled.mark,
            priority: settled.priority,
            _pad: pad,
        };

        keys.extend_from_slice(key.as_bytes());
        values.extend_from_slice(value.as_bytes());
        count += 1;

        if let Some(conflict) = conflict {
            conflicts.push(conflict);
        }
    }
    if count > 0 {
        map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)?;
    }
    // Reported only once the batch is committed, so the message describes the
    // state that is actually in the map.
    report_conflicts(flow_id, &conflicts, policy);
    Ok(())
}

// ==================
// IPv6
//

pub(crate) fn create_flow_dns_inner_map_v6<T>(
    flow_dns_outer_map: &T,
    flow_id: u32,
    data: &[FlowMarkInfo],
) -> Result<(), FlowDnsWriteError>
where
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
            return Err(FlowDnsWriteError::InnerMap {
                family: FAMILY_V6,
                flow_id,
                reason: format!("cannot create the inner map: {e:?}"),
            });
        }
    };

    // See the IPv4 branch: freshly created map, batch-internal arbitration only.
    if let Err(e) = apply_flow_dns_rules_v6(&map, flow_id, data, false) {
        // See the IPv4 branch: never publish a partially populated map.
        tracing::error!(
            "failed to populate flow6_dns rules for flow {flow_id}: {e:?}; keeping the previous inner map"
        );
        return Err(FlowDnsWriteError::Write { family: FAMILY_V6, flow_id, source: e });
    }
    tracing::debug!("put data in map");

    let map_fd = map.as_fd().as_raw_fd();

    let key_value = flow_id.as_bytes();
    let value_value = map_fd.as_bytes();

    if let Err(e) = flow_dns_outer_map.update(key_value, value_value, MapFlags::ANY) {
        let last_os_error = std::io::Error::last_os_error();
        tracing::error!("Last OS error: {:?}", last_os_error);
        tracing::error!("failed to publish flow6_dns inner map for flow {flow_id}: {e:?}");
        return Err(FlowDnsWriteError::Write { family: FAMILY_V6, flow_id, source: e });
    }

    Ok(())
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

    let mut claims: HashMap<IpAddr, Vec<Candidate>> = HashMap::new();
    for FlowMarkInfo { ip, mark, priority } in ips.iter() {
        if matches!(ip, IpAddr::V6(_)) {
            fold_candidate(&mut claims, *ip, Candidate::from_rule(*mark, *priority));
        }
    }

    let mut keys = vec![];
    let mut values = vec![];
    let mut count = 0;
    let mut conflicts = vec![];
    let policy = conflict_policy();

    for (addr, claims) in claims.iter() {
        let mut key = FlowDnsMatchKeyV6::default();
        match addr {
            IpAddr::V4(_) => {
                continue;
            }
            IpAddr::V6(ipv6_addr) => {
                key.addr = ipv6_addr.to_bits().to_be_bytes();
            }
        };

        // See the IPv4 branch: the stored claim joins the ones known now, and
        // arbitration runs over the union.
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

        let stored_candidate = stored
            .map(|stored| Candidate::from_stored(stored.mark, stored.priority, stored._pad[0]));
        let (settled, conflict) = settle_with_stored(*addr, claims, stored_candidate, policy);

        let unchanged = stored_candidate.is_some_and(|stored| {
            stored.mark == settled.mark
                && stored.priority == settled.priority
                && stored.synthesized_block == settled.synthesized_block
        });
        if unchanged {
            continue;
        }

        let pad = [if settled.synthesized_block { VALUE_FLAG_SYNTHESIZED_BLOCK } else { 0 }, 0];
        let value = FlowDnsMatchValueV6 {
            mark: settled.mark,
            priority: settled.priority,
            _pad: pad,
        };

        keys.extend_from_slice(key.as_bytes());
        values.extend_from_slice(value.as_bytes());
        count += 1;

        if let Some(conflict) = conflict {
            conflicts.push(conflict);
        }
    }
    if count > 0 {
        map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)?;
    }
    report_conflicts(flow_id, &conflicts, policy);
    Ok(())
}

/// 只更新部分 DNS 指定的规则
/// Register the marks of one freshly resolved answer.
///
/// Returns an error when the association could not be installed: the answer's
/// route mark is what keeps a proxied or blocked address from being sent out
/// natively by a device whose own flow is direct, so the caller must not treat
/// a failure here as "no marks were needed".
pub fn update_flow_dns_rule(
    paths: &LandscapeMapPath,
    flow_id: u32,
    generation: u64,
    data: Vec<FlowMarkInfo>,
) -> Result<(), FlowDnsWriteError> {
    let _guard = lock_flow_dns_writes();
    // Checked and applied under one lock: see `admit_generation`.
    admit_generation(flow_id, generation)?;

    let v4 = apply_family_v4(paths, flow_id, &data);
    let v6 = apply_family_v6(paths, flow_id, &data);
    v4.and(v6)
}

fn apply_family_v4(
    paths: &LandscapeMapPath,
    flow_id: u32,
    data: &[FlowMarkInfo],
) -> Result<(), FlowDnsWriteError> {
    let outer = libbpf_rs::MapHandle::from_pinned_path(&paths.flow4_dns_map)
        .map_err(|source| FlowDnsWriteError::OuterMap { family: FAMILY_V4, source })?;

    let key_value = flow_id.as_bytes();
    if let Ok(Some(fd_id_arr)) = outer.lookup(key_value, MapFlags::ANY)
        && let Ok(fd) = i32::read_from_bytes(&fd_id_arr)
        && let Ok(map) = libbpf_rs::MapHandle::from_map_id(fd as u32)
    {
        return update_flow_dns_rules_v4(&map, flow_id, data)
            .map_err(|source| FlowDnsWriteError::Write { family: FAMILY_V4, flow_id, source });
    }

    create_flow_dns_inner_map_v4(&outer, flow_id, data)
}

fn apply_family_v6(
    paths: &LandscapeMapPath,
    flow_id: u32,
    data: &[FlowMarkInfo],
) -> Result<(), FlowDnsWriteError> {
    let outer = libbpf_rs::MapHandle::from_pinned_path(&paths.flow6_dns_map)
        .map_err(|source| FlowDnsWriteError::OuterMap { family: FAMILY_V6, source })?;

    let key_value = flow_id.as_bytes();
    if let Ok(Some(fd_id_arr)) = outer.lookup(key_value, MapFlags::ANY)
        && let Ok(fd) = i32::read_from_bytes(&fd_id_arr)
        && let Ok(map) = libbpf_rs::MapHandle::from_map_id(fd as u32)
    {
        return update_flow_dns_rules_v6(&map, flow_id, data)
            .map_err(|source| FlowDnsWriteError::Write { family: FAMILY_V6, flow_id, source });
    }

    create_flow_dns_inner_map_v6(&outer, flow_id, data)
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

    fn shared_addr() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))
    }

    fn rule(mark: u32, priority: u16) -> Candidate {
        Candidate::from_rule(mark, priority)
    }

    /// Fold the claims the way a batch does, then settle them into the value
    /// that would be stored.
    fn settle(addr: IpAddr, candidates: &[Candidate]) -> (Candidate, Option<Conflict>) {
        settle_with_policy(addr, candidates, ConflictPolicy::Block)
    }

    fn settle_with_policy(
        addr: IpAddr,
        candidates: &[Candidate],
        policy: ConflictPolicy,
    ) -> (Candidate, Option<Conflict>) {
        let mut claims: HashMap<IpAddr, Vec<Candidate>> = HashMap::new();
        for candidate in candidates {
            fold_candidate(&mut claims, addr, *candidate);
        }
        let claims = &claims[&addr];
        settle_claims(addr, claims, policy)
    }

    #[test]
    fn wider_classes_never_displace_stricter_ones() {
        let shared = shared_addr();
        // A direct rule answers later for an address another rule proxies: the
        // proxied mark must survive, even though its priority is worse.
        let (settled, conflict) = settle(shared, &[rule(REDIRECT_AI, 200), rule(DIRECT, 100)]);
        assert_eq!(settled.mark, REDIRECT_AI);
        assert_eq!(conflict.expect("a decided conflict is still reported").kept.mark, REDIRECT_AI);

        // `KeepGoing` defers to the flow's own policy and can still end up
        // natively out, so it must not displace a managed tier either.
        let (settled, _) = settle(shared, &[rule(REDIRECT_AI, 200), rule(KEEP_GOING, 100)]);
        assert_eq!(settled.mark, REDIRECT_AI);

        // A rule that demands blocking outranks a rule that would only redirect.
        let (settled, _) = settle(shared, &[rule(DROP, 900), rule(REDIRECT_AI, 100)]);
        assert_eq!(settled.mark, DROP);
    }

    #[test]
    fn stricter_classes_displace_wider_ones() {
        let shared = shared_addr();
        let (settled, _) = settle(shared, &[rule(DIRECT, 100), rule(REDIRECT_AI, 200)]);
        assert_eq!(settled.mark, REDIRECT_AI);

        let (settled, _) = settle(shared, &[rule(KEEP_GOING, 100), rule(REDIRECT_AI, 200)]);
        assert_eq!(settled.mark, REDIRECT_AI);

        let (settled, _) = settle(shared, &[rule(REDIRECT_AI, 100), rule(DROP, 200)]);
        assert_eq!(settled.mark, DROP);

        // `KeepGoing` is never wider than an explicit `Direct`.
        let (settled, _) = settle(shared, &[rule(DIRECT, 100), rule(KEEP_GOING, 200)]);
        assert_eq!(settled.mark, KEEP_GOING);
    }

    #[test]
    fn one_rule_per_address_is_stored_as_is() {
        let shared = shared_addr();
        let (settled, conflict) = settle(shared, &[rule(REDIRECT_AI, 100)]);
        assert_eq!(settled.mark, REDIRECT_AI);
        assert_eq!(settled.priority, 100);
        assert!(!settled.synthesized_block);
        assert!(conflict.is_none());
    }

    #[test]
    fn equally_strict_tiers_block_the_address_instead_of_picking_one() {
        let shared = shared_addr();
        // Two proxy tiers: neither may be preferred, so the address is refused
        // at the strictest priority that asked for it.
        let (settled, conflict) =
            settle(shared, &[rule(REDIRECT_AI, 100), rule(REDIRECT_MEDIA, 400)]);
        assert!(settled.synthesized_block);
        assert_eq!(settled.mark, SYNTHESIZED_BLOCK_MARK);
        assert_eq!(settled.priority, 100);

        let conflict = conflict.expect("the block is a reported conflict");
        assert!(conflict.kept.synthesized_block);
        assert_eq!(conflict.dropped.mark, REDIRECT_MEDIA);
    }

    #[test]
    fn two_direct_rules_are_not_a_conflict() {
        let shared = shared_addr();
        // Both rules ask for the same routing class; `0x8100` only differs in
        // the reuse-port bit, which does not change where traffic goes.
        let (settled, conflict) = settle(shared, &[rule(DIRECT, 100), rule(0x8100, 900)]);
        assert_eq!(settled.mark, DIRECT);
        assert!(conflict.is_none());
    }

    #[test]
    fn a_decided_conflict_is_ordered_by_rule_priority() {
        let shared = shared_addr();
        // Same action, different target flow, different strictness order is not
        // involved: this is a tie, so it blocks. But `Drop` vs `Redirect` is a
        // decision, and the smaller priority only breaks ties inside a class.
        let (settled, _) = settle(shared, &[rule(REDIRECT_AI, 900), rule(DIRECT, 100)]);
        assert_eq!(settled.mark, REDIRECT_AI);
        assert_eq!(settled.priority, 900);
    }

    #[test]
    fn fold_keeps_the_best_claim_per_routing_identity() {
        let shared = shared_addr();
        let mut claims: HashMap<IpAddr, Vec<Candidate>> = HashMap::new();
        fold_candidate(&mut claims, shared, rule(REDIRECT_AI, 900));
        fold_candidate(&mut claims, shared, rule(REDIRECT_AI, 100));
        fold_candidate(&mut claims, shared, rule(REDIRECT_AI, 500));

        let claims = &claims[&shared];
        assert_eq!(claims.len(), 1, "one identity keeps one claim");
        assert_eq!(claims[0].priority, 100);
    }

    #[test]
    fn fold_is_order_independent_for_shared_addresses() {
        let shared = shared_addr();

        let settle_in_order = |order: [Candidate; 3]| {
            let mut claims: HashMap<IpAddr, Vec<Candidate>> = HashMap::new();
            for candidate in order {
                fold_candidate(&mut claims, shared, candidate);
            }
            let claims = claims[&shared].clone();
            settle_claims(shared, &claims, ConflictPolicy::Block)
        };

        // A direct rule, an AI-tier rule and a media-tier rule all claim one
        // address. Whatever order they arrive in, the direct claim loses and the
        // two equipollent proxy tiers block the address.
        let a =
            settle_in_order([rule(DIRECT, 100), rule(REDIRECT_AI, 200), rule(REDIRECT_MEDIA, 300)]);
        let b =
            settle_in_order([rule(REDIRECT_MEDIA, 300), rule(DIRECT, 100), rule(REDIRECT_AI, 200)]);
        let c =
            settle_in_order([rule(REDIRECT_AI, 200), rule(REDIRECT_MEDIA, 300), rule(DIRECT, 100)]);

        for (settled, _) in [&a, &b, &c] {
            assert!(settled.synthesized_block);
            assert_eq!(settled.priority, 200);
        }
    }

    #[test]
    fn a_real_drop_rule_is_not_relabelled_as_a_synthesized_block() {
        let shared = shared_addr();
        // A genuine `Drop` rule equals the synthesized block on class, priority
        // and mark; the stored value must stay the rule's own so a later rebuild
        // can tell the two apart and release an address that was only blocked
        // because of arbitration.
        let (settled, _) = settle(shared, &[rule(DROP, 100)]);
        assert_eq!(settled.mark, DROP);
        assert!(!settled.synthesized_block);

        // Same claim stored as a synthesized block: the real rule takes over.
        let mut claims: HashMap<IpAddr, Vec<Candidate>> = HashMap::new();
        fold_candidate(&mut claims, shared, Candidate::block(100));
        fold_candidate(&mut claims, shared, rule(DROP, 100));
        let claims = claims[&shared].clone();
        let (settled, conflict) = settle_claims(shared, &claims, ConflictPolicy::Block);
        assert_eq!(settled.mark, DROP);
        assert!(!settled.synthesized_block);
        assert!(conflict.is_none());
    }

    #[test]
    fn stored_block_joins_the_union_so_a_new_tier_keeps_it_blocked() {
        let shared = shared_addr();
        // The address was refused because two tiers claimed it. A later answer
        // for one of the tiers must not quietly take the address over: only a
        // full rebuild over the whole cache may decide again.
        let mut claims: HashMap<IpAddr, Vec<Candidate>> = HashMap::new();
        fold_candidate(&mut claims, shared, rule(REDIRECT_AI, 200));
        fold_candidate(&mut claims, shared, Candidate::from_stored(SYNTHESIZED_BLOCK_MARK, 200, 1));
        let claims = claims[&shared].clone();

        let (settled, conflict) = settle_claims(shared, &claims, ConflictPolicy::Block);
        assert!(settled.synthesized_block);
        assert!(conflict.expect("still a conflict").kept.synthesized_block);
    }

    #[test]
    fn a_synthesized_block_persists_for_the_incremental_path() {
        let shared = shared_addr();
        // A device answers with one of the two tiers that made the block. The
        // stored block joins the union, so the address stays refused: a single
        // tier's answer is not evidence that the other tier stopped claiming it.
        let mut claims: HashMap<IpAddr, Vec<Candidate>> = HashMap::new();
        fold_candidate(&mut claims, shared, Candidate::from_stored(SYNTHESIZED_BLOCK_MARK, 200, 1));
        fold_candidate(&mut claims, shared, rule(REDIRECT_AI, 500));
        let claims = claims[&shared].clone();

        let (settled, _) = settle_claims(shared, &claims, ConflictPolicy::Block);
        assert!(settled.synthesized_block);
    }

    #[test]
    fn a_rebuild_releases_a_block_that_is_no_longer_justified() {
        let shared = shared_addr();
        // The rebuild path starts from an empty inner map and recomputes every
        // address from the whole cache, so the stored block is gone and the one
        // remaining claim takes the address over. This is the release path the
        // rules-only change / manual refresh goes through.
        let (settled, conflict) = settle(shared, &[rule(REDIRECT_AI, 500)]);
        assert_eq!(settled.mark, REDIRECT_AI);
        assert!(!settled.synthesized_block);
        assert!(conflict.is_none());
    }

    #[test]
    fn report_only_policy_keeps_the_winner_and_still_reports() {
        let shared = shared_addr();
        let (settled, conflict) = settle_with_policy(
            shared,
            &[rule(REDIRECT_AI, 100), rule(REDIRECT_MEDIA, 400)],
            ConflictPolicy::ReportOnly,
        );
        // Observation mode must not change what the datapath does.
        assert!(!settled.synthesized_block);
        assert_eq!(settled.mark, REDIRECT_AI);
        let conflict = conflict.expect("the conflict is still reported");
        assert_eq!(conflict.dropped.mark, REDIRECT_MEDIA);
        // ... and it must be told apart from a ladder decision, otherwise the
        // log cannot say which addresses the default policy would refuse.
        assert!(conflict.equipollent);
    }

    #[test]
    fn a_decided_conflict_is_not_marked_as_equipollent() {
        let shared = shared_addr();
        let (_, conflict) = settle(shared, &[rule(DIRECT, 100), rule(REDIRECT_AI, 900)]);
        let conflict = conflict.expect("a proxied rule over a direct one is reported");
        assert!(!conflict.equipollent);
        assert_eq!(conflict.kept.mark, REDIRECT_AI);
    }

    #[test]
    fn routing_identity_ignores_bookkeeping_bits() {
        assert_eq!(routing_identity(DIRECT), routing_identity(0x8100));
        assert_ne!(routing_identity(REDIRECT_AI), routing_identity(REDIRECT_MEDIA));
        assert_ne!(routing_identity(DIRECT), routing_identity(REDIRECT_AI));
        assert_ne!(routing_identity(KEEP_GOING), routing_identity(DIRECT));
    }

    // The generation gate is process-global, so every test below owns its own
    // flow id: sharing one would make these tests race each other.
    #[test]
    fn the_first_writer_sets_the_published_generation() {
        assert!(admit_generation(9101, 7).is_ok());
        assert_eq!(published_generation(9101), Some(7));
    }

    #[test]
    fn answers_of_the_published_generation_are_admitted_repeatedly() {
        publish_generation(9102, 3);
        // One generation serves many answers.
        assert!(admit_generation(9102, 3).is_ok());
        assert!(admit_generation(9102, 3).is_ok());
        assert_eq!(published_generation(9102), Some(3));
    }

    #[test]
    fn an_answer_from_a_replaced_generation_is_refused() {
        publish_generation(9103, 5);
        // The rebuild moved on; this answer still describes the old rules.
        let err = admit_generation(9103, 4).expect_err("a stale answer must be refused");
        match err {
            FlowDnsWriteError::Superseded { answer_generation, published_generation, .. } => {
                assert_eq!(answer_generation, 4);
                assert_eq!(published_generation, 5);
            }
            other => panic!("expected Superseded, got {other:?}"),
        }
        // ... and it must not drag the published generation backwards.
        assert_eq!(published_generation(9103), Some(5));
    }

    #[test]
    fn an_answer_from_an_unpublished_generation_is_refused() {
        publish_generation(9104, 9);
        // A generation newer than the published one means a rebuild is in
        // flight; installing it would publish part of a configuration that has
        // not been announced yet.
        assert!(admit_generation(9104, 10).is_err());
        assert_eq!(published_generation(9104), Some(9));
    }

    #[test]
    fn generations_are_tracked_per_flow() {
        publish_generation(9105, 2);
        // A neighbouring flow's generation is unrelated.
        assert!(admit_generation(9106, 1).is_ok());
        assert_eq!(published_generation(9105), Some(2));
        assert_eq!(published_generation(9106), Some(1));
    }
}
