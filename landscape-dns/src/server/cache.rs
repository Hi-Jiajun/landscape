use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use hickory_proto::{
    op::ResponseCode,
    rr::{Record, RecordType},
};
use moka::future::Cache;
use uuid::Uuid;

use landscape_common::{
    dns::rule::FilterResult,
    flow::{DnsMarkInstallError, DnsResultSink, DnsRuntimeMarkInfo, FlowMarkInfo},
};

use crate::{
    CacheDNSItem, DNSCache,
    domain::ParsedDomain,
    server::{CacheRuntimeConfig, rule::DNSResolveRuntime},
};

/// Every valid claim on each destination address, across the whole cache.
///
/// The datapath table keeps one value per address, so a value that is lost — an
/// LRU eviction, or a rebuild that read the cache before an answer landed — takes
/// the only record of that claim with it, and a later weaker answer for the same
/// address would then be free to widen it. This index is the authoritative view
/// of "who claims this address" that the datapath cannot hold: it is maintained
/// alongside the cache, so an incremental answer arbitrates over every valid
/// claim instead of over the single value the table happens to contain.
///
/// It mirrors the cache's lifetime: claims are added when an entry becomes
/// cacheable and removed when the entry leaves (explicit invalidation, TTL or
/// capacity eviction), so a claim cannot outlive the answer that justifies it.
#[derive(Debug, Default)]
pub(crate) struct ClaimIndex {
    /// Reference-counted per claim. Two answers can hold the *same* claim for an
    /// address (two domains behind one CDN edge on the same tier), and one of
    /// them leaving must not drop the claim the other still justifies. Counting
    /// also makes the order between "an entry replaced" and "its replacement
    /// registered" irrelevant.
    claims: std::sync::Mutex<HashMap<IpAddr, HashMap<FlowMarkInfo, usize>>>,
    /// Addresses whose claim set shrank, so the datapath may still hold a value
    /// nothing asks for any more.
    ///
    /// An entry can leave for reasons nobody asked for — its TTL, or capacity
    /// pressure — and the notification for that can arrive while moka holds its
    /// own locks. Rewriting the datapath from there would take the flow write lock
    /// underneath it, so the addresses are queued instead and reconciled at the
    /// next write, which is already inside that lock.
    stale: std::sync::Mutex<HashSet<IpAddr>>,
}

impl ClaimIndex {
    fn add(&self, marks: &HashSet<FlowMarkInfo>) {
        if marks.is_empty() {
            return;
        }
        let mut claims = self.claims.lock().unwrap_or_else(|e| e.into_inner());
        for mark in marks {
            *claims.entry(mark.ip).or_default().entry(mark.clone()).or_insert(0) += 1;
        }
    }

    fn remove(&self, marks: &HashSet<FlowMarkInfo>) {
        if marks.is_empty() {
            return;
        }
        let mut stale = HashSet::new();
        let mut claims = self.claims.lock().unwrap_or_else(|e| e.into_inner());
        for mark in marks {
            if let Some(owners) = claims.get_mut(&mark.ip) {
                let emptied = match owners.get_mut(mark) {
                    Some(count) if *count > 1 => {
                        *count -= 1;
                        false
                    }
                    // A claim that was never registered cannot be removed, but the
                    // address still needs a look: it may hold a value whose claim
                    // left before it was ever counted.
                    Some(_) => {
                        owners.remove(mark);
                        true
                    }
                    None => true,
                };
                if owners.is_empty() {
                    claims.remove(&mark.ip);
                }
                if emptied {
                    stale.insert(mark.ip);
                }
            }
        }
        drop(claims);
        if !stale.is_empty() {
            self.stale.lock().unwrap_or_else(|e| e.into_inner()).extend(stale);
        }
    }

    /// Take the addresses queued since the last call.
    fn take_stale(&self) -> HashSet<IpAddr> {
        std::mem::take(&mut *self.stale.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Every claim on `address`, including the ones other answers registered.
    fn claims_for(&self, address: IpAddr) -> Vec<FlowMarkInfo> {
        self.claims
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&address)
            .map(|owners| owners.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// The claims on these addresses plus `candidates`, for arbitrating them.
    ///
    /// This is what an incremental answer needs: the claims other answers already
    /// hold for the same addresses, so the result matches what a rebuild over the
    /// whole cache would produce instead of depending on which single value the
    /// datapath happens to hold.
    fn claims_with(&self, candidates: &[FlowMarkInfo]) -> Vec<FlowMarkInfo> {
        let mut all = HashSet::new();
        for candidate in candidates {
            all.extend(self.claims_for(candidate.ip));
            all.insert(candidate.clone());
        }
        all.into_iter().collect()
    }
}

/// Data required to write (or update) one cache entry.
/// The lifetime to give a cache entry, as a pure decision.
///
/// Split out of `insert` so the rule is stated once and can be tested without a
/// live cache: a positive answer lives as long as its shortest record says, and a
/// negative answer lives as long as the upstream's SOA justified - capped by
/// configuration, never extended by it.
///
/// RFC 2308 §5 takes a negative lifetime from `min(SOA TTL, SOA.MINIMUM)`, which
/// the resolver computes and hands over as `negative_ttl`; it is `None` when the
/// answer carried no SOA. `SHOULD NOT` cache that case, so the configured
/// `negative_cache_ttl_without_soa` decides it explicitly - 0 meaning "do not
/// cache", which the insert path already honours by returning before the write.
fn entry_lifetime(
    rdatas: &[Record],
    negative_ttl: Option<u32>,
    config: &CacheRuntimeConfig,
) -> u32 {
    if rdatas.is_empty() {
        negative_ttl.unwrap_or(config.negative_cache_ttl_without_soa).min(config.negative_cache_ttl)
    } else {
        rdatas.iter().map(|r| r.ttl).min().unwrap_or(0)
    }
}

pub(crate) struct CacheEntry {
    pub(crate) domain_key: Arc<str>,
    pub(crate) query_type: RecordType,
    pub(crate) rdatas: Vec<Record>,
    pub(crate) response_code: ResponseCode,
    /// RFC 2308 §5's `min(SOA TTL, SOA.MINIMUM)`, from the answer that produced
    /// this entry. `None` when the answer carried no SOA, which is "the upstream
    /// justified no lifetime for this" rather than a value to invent.
    pub(crate) negative_ttl: Option<u32>,
    pub(crate) mark: DnsRuntimeMarkInfo,
    pub(crate) filter: FilterResult,
    pub(crate) matched_rule_id: Option<Uuid>,
    pub(crate) matched_rule_order: Option<u32>,
}

/// Cache operations shared by the resolution chain, admin APIs and runtime
/// swaps: lookup with TTL decrement, insert with datapath side effects and
/// invalidation.
pub(crate) struct CacheHandle {
    cache: DNSCache,
    runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
    flow_id: u32,
    sink: Arc<dyn DnsResultSink>,
    /// Rule generation this cache was built for. It is stamped on every answer
    /// the cache registers, so a query that finished after a rule change can be
    /// recognised as belonging to the replaced rules.
    generation: u64,
    /// Authoritative view of which addresses the cached answers claim; see
    /// [`ClaimIndex`].
    claims: Arc<ClaimIndex>,
}

impl std::fmt::Debug for CacheHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheHandle")
            .field("cache", &self.cache)
            .field("runtime_config", &self.runtime_config)
            .field("flow_id", &self.flow_id)
            .finish_non_exhaustive()
    }
}

impl CacheHandle {
    pub fn new(
        runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
        flow_id: u32,
        sink: Arc<dyn DnsResultSink>,
        generation: u64,
    ) -> Self {
        let claims = Arc::new(ClaimIndex::default());
        Self {
            cache: Self::build_cache(runtime_config.load().as_ref(), claims.clone()),
            claims,
            runtime_config,
            flow_id,
            sink,
            generation,
        }
    }

    fn build_cache(runtime_config: &CacheRuntimeConfig, claims: Arc<ClaimIndex>) -> DNSCache {
        Cache::builder()
            .max_capacity(runtime_config.cache_capacity as u64)
            .time_to_live(Duration::from_secs(runtime_config.cache_ttl as u64))
            // Whatever the reason an entry leaves — explicit invalidation, its TTL
            // expiring, or capacity pressure — its claims must leave with it, or a
            // later pass would keep enforcing a rule nothing asks for any more.
            // The listener must not touch the cache itself; it only updates the
            // index.
            .eviction_listener(move |_key, value: Arc<CacheDNSItem>, cause| {
                // `Replaced` is included deliberately: the entry that is leaving may
                // have claimed addresses its replacement does not, so those claims
                // have to go. The count above keeps this from removing a claim the
                // replacement also registered.
                let _ = cause;
                claims.remove(&value.get_update_rules());
            })
            .build()
    }

    /// Iterates over `(key, item)` pairs as owned `Arc`s, matching the
    /// underlying moka cache's iterator.
    pub fn iter(&self) -> moka::future::Iter<'_, (Arc<str>, RecordType), Arc<CacheDNSItem>> {
        self.cache.iter()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[cfg(test)]
    pub async fn get(&self, key: &(Arc<str>, RecordType)) -> Option<Arc<CacheDNSItem>> {
        self.cache.get(key).await
    }

    /// Direct insert for cache migration paths (no TTL computation, no eBPF
    /// side effects): the item keeps its original bookkeeping.
    pub async fn insert_raw(&self, key: (Arc<str>, RecordType), item: Arc<CacheDNSItem>) {
        // Migrated entries are cached answers too, so their claims belong in the
        // index for the same reason as any other answer's.
        self.claims.add(&item.get_update_rules());
        self.cache.insert(key, item).await;
    }

    pub async fn run_pending_tasks(&self) {
        self.cache.run_pending_tasks().await;
    }

    /// All (mark, ip) pairs held by cached records that must live in the
    /// eBPF flow-dns map.
    pub fn dns_mark_list(&self) -> HashSet<FlowMarkInfo> {
        let mut update_dns_mark_list = HashSet::new();
        for (_key, value) in self.cache.iter() {
            update_dns_mark_list.extend(value.get_update_rules());
        }
        update_dns_mark_list
    }

    /// Returns valid (TTL-decremented) records for a live entry, or `None`
    /// when the entry is missing or expired (lazy eviction).
    pub async fn lookup(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> Option<(Vec<Record>, FilterResult, ResponseCode)> {
        let key = (domain.raw_arc().clone(), query_type);
        if let Some(cache_item) = self.cache.get(&key).await {
            let CacheDNSItem {
                rdatas,
                response_code,
                insert_time,
                min_ttl,
                filter,
                ..
            } = &*cache_item;

            // 1. check expiry
            let insert_time_elapsed = insert_time.elapsed().as_secs() as u32;
            if insert_time_elapsed > *min_ttl {
                // expired: proactively evict the entry (lazy expiration)
                self.cache.invalidate(&key).await;
                return None;
            }

            // 2. build valid records (TTL decremented)
            // if rdatas is empty (negative cache), valid_records stays empty too
            let valid_records = rdatas
                .iter()
                .cloned()
                .map(|mut d| {
                    d.ttl = d.ttl.saturating_sub(insert_time_elapsed).max(1);
                    d
                })
                .collect();

            return Some((valid_records, filter.clone(), *response_code));
        }
        None
    }

    pub async fn invalidate(&self, domain: &ParsedDomain, query_type: RecordType) {
        self.cache.invalidate(&(domain.raw_arc().clone(), query_type)).await;
    }

    /// Invalidates the entry only when it exists; returns whether it did.
    pub async fn invalidate_if_present(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> bool {
        let key = (domain.raw_arc().clone(), query_type);
        if self.cache.get(&key).await.is_none() {
            return false;
        }

        self.cache.invalidate(&key).await;
        true
    }

    /// Inserts an answer and registers its route marks in the datapath.
    ///
    /// Returns an error when the marks could not be installed *and* the answer
    /// must not be served because of it. In that case nothing is cached either,
    /// and the caller must not hand the records to the client: the address would
    /// otherwise be sent out natively by any device whose own flow is direct,
    /// which is exactly the leak the marks exist to prevent.
    ///
    /// Answers that need no association (`Direct`, `KeepGoing`) are cached and
    /// served as usual, since a missing entry is what they ask for — except when
    /// the answer comes from a superseded rule generation, where its own mark
    /// cannot be trusted to describe the live rules.
    pub async fn insert(&self, entry: CacheEntry) -> Result<(), DnsMarkInstallError> {
        let CacheEntry {
            domain_key,
            query_type,
            rdatas,
            response_code,
            negative_ttl,
            mark,
            filter,
            matched_rule_id,
            matched_rule_order,
        } = entry;
        // A negative answer's lifetime is a property of the answer, not of
        // configuration: RFC 2308 §5 takes `min(SOA TTL, SOA.MINIMUM)`, which the
        // resolver hands over as `negative_ttl`. Configuration only caps it, so a
        // short upstream lifetime is never extended into a longer one.
        //
        // With no SOA the upstream justified no lifetime at all; RFC 2308 §5 says
        // SHOULD NOT cache, and `negative_cache_ttl_without_soa` is that decision
        // made explicit (0 = do not cache). It is the common case here, not an
        // edge: the carrier resolver answers names that do not exist with
        // `NOERROR` and no authority section.
        let min_ttl = {
            let config = self.runtime_config.load();
            entry_lifetime(&rdatas, negative_ttl, &config)
        };

        let cache_item = CacheDNSItem {
            rdatas,
            response_code,
            mark,
            insert_time: Instant::now(),
            min_ttl,
            filter,
            matched_rule_id,
            matched_rule_order,
        };
        let update_dns_mark_list = cache_item.get_update_rules();
        // Read what the failure handling needs before the value is moved into the
        // cache.
        let needs_association = cache_item.mark.mark.requires_route_association();
        // Arbitrate over every claim on these addresses, not just this answer's:
        // another domain's answer for the same address is the other half of a
        // shared-address conflict, and the datapath's single value cannot be
        // trusted to still represent it (an LRU eviction drops it).
        let all_claims: HashSet<FlowMarkInfo> = self
            .claims
            .claims_with(&update_dns_mark_list.iter().cloned().collect::<Vec<_>>())
            .into_iter()
            .collect();

        // Hand the marks to the datapath sink even if TTL is 0, and even when the
        // list is empty: the call is also how the sink checks that this answer
        // still belongs to the live rule generation, and an answer with no marks
        // (a `Direct`/`KeepGoing` one, or a negative answer) can be just as stale
        // as any other.
        //
        // The entry is cached only once this succeeded. Caching first would make
        // the address reachable through the cache before its mark exists, so a
        // concurrent query could serve it unprotected; and the failure path would
        // have to remove the entry again, without being able to tell its own entry
        // from one a later answer wrote under the same key. The rebuild side
        // cannot lose this answer's mark either, because it derives its list while
        // holding the same datapath write.
        if let Err(e) = self.sink.record_dns_answer(
            self.flow_id,
            self.generation,
            all_claims.iter().cloned().collect(),
        ) {
            // An answer from a superseded generation cannot be judged by its own
            // mark: the rules that produced it are gone, so the domain may have
            // been moved to `Redirect`/`Drop` since. Serving it "because it only
            // asked for Direct" would let the replaced rules decide this domain
            // again, so it is refused outright and the client retries under the
            // current rules.
            if e.superseded || needs_association {
                tracing::error!(
                    flow_id = self.flow_id,
                    domain = %domain_key,
                    superseded = e.superseded,
                    "refusing an answer whose route association could not be installed: {e}"
                );
                return Err(e);
            }
            // `Direct`/`KeepGoing` ask for native egress or for the flow's own
            // policy, which is what a missing entry already yields.
            tracing::warn!(
                flow_id = self.flow_id,
                domain = %domain_key,
                "route association could not be installed, but the answer needs none: {e}"
            );
        }

        if min_ttl == 0 {
            // A zero TTL answer is served once and never cached; its marks were
            // installed above, so the address stays covered.
            return Ok(());
        }

        // Register the claims *before* the entry becomes visible. A replacement's
        // notification arrives while `cache.insert` runs, and if the new claims
        // were not registered yet, that notification would find nothing to remove
        // and the old claim would then be re-added by this very call — a ghost
        // claim no answer justifies, kept until the cache is dropped.
        self.claims.add(&update_dns_mark_list);
        self.cache.insert((domain_key.clone(), query_type), Arc::new(cache_item)).await;

        // Run the marks through arbitration once more now that the answer is in
        // the cache. Installing them and caching the answer cannot be one step —
        // the install takes the datapath write while the cache commit is an
        // `await` — so a rebuild can collect the cache in between and publish a
        // table derived from an answer it could not see, deleting these marks.
        // Re-running the same arbitration covers both that hole and the shared
        // address now being claimed by two answers, which the first pass could
        // not see either.
        let claims_now: HashSet<FlowMarkInfo> = self
            .claims
            .claims_with(&update_dns_mark_list.iter().cloned().collect::<Vec<_>>())
            .into_iter()
            .collect();
        if let Err(e) = self.sink.record_dns_answer(
            self.flow_id,
            self.generation,
            claims_now.iter().cloned().collect(),
        ) {
            tracing::error!(
                flow_id = self.flow_id,
                domain = %domain_key,
                "could not re-apply the route marks after caching the answer: {e}"
            );
        }

        // Addresses whose claim set shrank while this answer was being processed
        // are re-arbitrated here, inside the same flow write: the winner changes
        // when the claim that won is the one that left, and keeping the old value
        // would enforce a decision the remaining claims do not support.
        self.reconcile_stale_claims();
        Ok(())
    }

    /// Re-arbitrate the addresses whose claim set changed.
    ///
    /// An address that still has claims is written from those claims, so the
    /// datapath follows the winner the live answers actually produce. An address
    /// left with no claim at all is deliberately **left as it is**: dropping the
    /// entry would let the address fall back to the flow's own policy, which can
    /// be `Direct`, and widening access is the one outcome this path exists to
    /// prevent. The stale entry is released by the next rebuild.
    fn reconcile_stale_claims(&self) {
        let stale = self.claims.take_stale();
        if stale.is_empty() {
            return;
        }
        let mut remaining = Vec::new();
        let mut unclaimed = 0usize;
        for address in stale {
            let claims = self.claims.claims_for(address);
            if claims.is_empty() {
                unclaimed += 1;
            } else {
                remaining.extend(claims);
            }
        }
        if unclaimed > 0 {
            // Kept on purpose; see above.
            tracing::debug!(
                flow_id = self.flow_id,
                addresses = unclaimed,
                "route marks are no longer claimed by a cached answer; they stay until the next \
                 rebuild rather than being dropped, which could widen direct access"
            );
        }
        if remaining.is_empty() {
            return;
        }
        if let Err(e) = self.sink.record_dns_answer(self.flow_id, self.generation, remaining) {
            tracing::error!(
                flow_id = self.flow_id,
                "could not re-arbitrate the addresses whose claims changed: {e}"
            );
        }
    }

    pub fn resolver_cache_entry(
        resolver: &DNSResolveRuntime,
        domain_key: &Arc<str>,
        query_type: RecordType,
        rdatas: Vec<Record>,
        response_code: ResponseCode,
        negative_ttl: Option<u32>,
    ) -> CacheEntry {
        CacheEntry {
            domain_key: domain_key.clone(),
            query_type,
            rdatas,
            response_code,
            negative_ttl,
            mark: resolver.mark().clone(),
            filter: resolver.filter_mode(),
            matched_rule_id: Some(resolver.get_config_id()),
            matched_rule_order: Some(resolver.order()),
        }
    }
}

#[cfg(test)]
mod entry_lifetime_tests {
    use super::*;

    fn record(ttl: u32) -> Record {
        use hickory_proto::rr::{Name, RData, RecordType, rdata::A};
        use std::str::FromStr;
        Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            ttl,
            RData::A(A::new(203, 0, 113, 1)),
        )
    }

    fn config() -> CacheRuntimeConfig {
        CacheRuntimeConfig {
            negative_cache_ttl: 120,
            negative_cache_ttl_without_soa: 10,
            ..Default::default()
        }
    }

    #[test]
    fn a_positive_answer_lives_as_long_as_its_shortest_record() {
        let records = vec![record(300), record(60)];
        assert_eq!(entry_lifetime(&records, None, &config()), 60);
    }

    #[test]
    fn a_negative_answer_uses_the_lifetime_the_upstream_justified() {
        // RFC 2308: the SOA-derived value, not a number of our choosing.
        assert_eq!(entry_lifetime(&[], Some(45), &config()), 45);
    }

    #[test]
    fn a_short_upstream_lifetime_is_never_extended_by_configuration() {
        // The ceiling caps; it must not become a floor. Extending an upstream's
        // 5 seconds to our 120 would keep a name that starts existing unreachable.
        assert_eq!(entry_lifetime(&[], Some(5), &config()), 5);
    }

    #[test]
    fn a_long_upstream_lifetime_is_capped() {
        assert_eq!(entry_lifetime(&[], Some(86_400), &config()), 120);
    }

    #[test]
    fn no_soa_means_the_configured_policy_decides() {
        // The common case on this network's carrier resolver: NODATA with no
        // authority section, so nothing was justified and the policy applies.
        assert_eq!(entry_lifetime(&[], None, &config()), 10);

        // ... and "do not cache" is expressible, which is what RFC 2308 §5 asks for.
        let strict = CacheRuntimeConfig { negative_cache_ttl_without_soa: 0, ..config() };
        assert_eq!(entry_lifetime(&[], None, &strict), 0);
    }

    #[test]
    fn a_zero_lifetime_from_the_upstream_is_not_cached() {
        // A zero is the upstream saying "do not reuse this"; the insert path treats
        // a zero lifetime by returning before the write.
        assert_eq!(entry_lifetime(&[], Some(0), &config()), 0);
    }
}

#[cfg(test)]
mod claim_index_tests {
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr},
    };

    use landscape_common::flow::FlowMarkInfo;

    use super::ClaimIndex;

    fn claim(mark: u32, last_octet: u8) -> FlowMarkInfo {
        FlowMarkInfo {
            mark,
            ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, last_octet)),
            priority: 100,
        }
    }

    /// The counterexample this index exists for: the datapath's single value for
    /// an address can be lost (LRU eviction, or a rebuild that read the cache
    /// early), and a later weaker answer for the same address must still be
    /// arbitrated against the claims that are still valid — not against an empty
    /// memory of them.
    #[test]
    fn a_claim_survives_losing_the_datapath_value() {
        let index = ClaimIndex::default();
        let blocker = claim(0x0200, 9); // the answering domain asked for Drop
        let weaker = claim(0x0305, 9); // a later answer routes the same address

        index.add(&HashSet::from([blocker.clone()]));

        // The datapath entry is gone, but the claim is still valid, so a later
        // answer must see it and arbitrate against it.
        let seen = index.claims_with(std::slice::from_ref(&weaker));
        assert!(seen.contains(&blocker), "the still-valid Drop claim must be seen");
        assert!(seen.contains(&weaker));
    }

    #[test]
    fn a_claim_leaves_when_its_answer_leaves() {
        let index = ClaimIndex::default();
        let claim = claim(0x0200, 9);
        index.add(&HashSet::from([claim.clone()]));
        assert_eq!(index.claims_for(claim.ip), vec![claim.clone()]);

        // The answer expired or was evicted, so nothing justifies the claim.
        index.remove(&HashSet::from([claim.clone()]));
        assert!(index.claims_for(claim.ip).is_empty());
    }

    #[test]
    fn two_answers_holding_the_same_claim_keep_it_until_both_leave() {
        let index = ClaimIndex::default();
        // Two domains on the same CDN edge with the same tier produce an
        // identical claim; one of them leaving must not drop it.
        let shared = claim(0x0305, 9);
        let holder = HashSet::from([shared.clone()]);
        index.add(&holder);
        index.add(&holder);

        index.remove(&holder);
        assert_eq!(index.claims_for(shared.ip), vec![shared.clone()]);

        index.remove(&holder);
        assert!(index.claims_for(shared.ip).is_empty());
    }

    #[test]
    fn removing_a_claim_that_was_never_added_is_harmless() {
        let index = ClaimIndex::default();
        index.remove(&HashSet::from([claim(0x0305, 9)]));
        assert!(index.claims_for(claim(0x0305, 9).ip).is_empty());
    }

    #[test]
    fn an_empty_answer_registers_nothing() {
        let index = ClaimIndex::default();
        index.add(&HashSet::new());
        assert!(index.claims_with(&[]).is_empty());
    }

    /// The ordering bug the index has to be careful about: a replacement's
    /// notification can arrive before the replacement's own claims are
    /// registered. Registering *before* the entry becomes visible means the
    /// notification always finds something to remove, so no claim survives whose
    /// answer is gone.
    #[test]
    fn an_entry_replaced_before_its_claims_were_registered_leaves_nothing() {
        let index = ClaimIndex::default();
        let old = HashSet::from([claim(0x0200, 9)]);
        let new = HashSet::from([claim(0x0305, 9)]);

        // Correct order: register, then let the replacement notify.
        index.add(&new);
        index.remove(&old);
        let seen = index.claims_for(claim(0, 9).ip);
        assert_eq!(seen, vec![claim(0x0305, 9)], "only the live answer's claim remains");
    }

    #[test]
    fn an_address_whose_last_claim_left_is_queued_for_reconciliation() {
        let index = ClaimIndex::default();
        let claim = claim(0x0200, 9);
        index.add(&HashSet::from([claim.clone()]));
        assert!(index.take_stale().is_empty(), "nothing is stale while it is claimed");

        index.remove(&HashSet::from([claim.clone()]));
        assert!(index.claims_for(claim.ip).is_empty());
        assert_eq!(
            index.take_stale(),
            HashSet::from([claim.ip]),
            "the address must be queued so its datapath value can be dropped"
        );
        // Taken once, not repeatedly.
        assert!(index.take_stale().is_empty());
    }

    #[test]
    fn an_address_still_claimed_by_another_answer_is_not_queued() {
        let index = ClaimIndex::default();
        let shared = claim(0x0305, 9);
        let holder = HashSet::from([shared.clone()]);
        index.add(&holder);
        index.add(&holder);

        index.remove(&holder);
        assert!(!index.claims_for(shared.ip).is_empty());
        assert!(index.take_stale().is_empty(), "a surviving claim keeps the value valid");
    }

    /// The reverse case: the claim that *won* left, another one remains. The
    /// address must be queued for re-arbitration — filtering on "has no claim at
    /// all" would skip it and keep enforcing the departed claim's decision.
    #[test]
    fn an_address_whose_winning_claim_left_is_queued_even_while_another_remains() {
        let index = ClaimIndex::default();
        let blocker = claim(0x0200, 9); // won: Drop is the strictest class
        let proxy = claim(0x0305, 9);
        index.add(&HashSet::from([blocker.clone(), proxy.clone()]));
        assert!(index.take_stale().is_empty());

        index.remove(&HashSet::from([blocker]));
        assert!(
            index.take_stale().contains(&proxy.ip),
            "the surviving claim must trigger a re-arbitration of this address"
        );
        assert_eq!(
            index.claims_for(proxy.ip),
            vec![proxy],
            "and the remaining claim is what the datapath should be written from"
        );
    }
}

/// The contract between an answer and the datapath: the marks go in first, and an
/// answer whose association could not be installed is refused rather than served.
///
/// This is the requirement stated as "a zero-TTL answer registers its route
/// association before anything else, and a failure to register is a refusal". It
/// had no test: the harness's sink accepts every mark, so the refusal branch was
/// unreachable from the existing cases - the one place the design is load-bearing
/// and nothing could fail if it were removed.
#[cfg(test)]
mod datapath_ordering_tests {
    use super::*;
    use landscape_common::flow::mark::{FlowMark, FlowMarkAction};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn record(ttl: u32) -> Record {
        use hickory_proto::rr::{Name, RData, rdata::A};
        use std::str::FromStr;
        Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            ttl,
            RData::A(A::new(203, 0, 113, 7)),
        )
    }

    fn runtime_config() -> Arc<ArcSwap<CacheRuntimeConfig>> {
        Arc::new(ArcSwap::from_pointee(CacheRuntimeConfig {
            negative_cache_ttl: 120,
            negative_cache_ttl_without_soa: 10,
            ..Default::default()
        }))
    }

    fn mark(action: FlowMarkAction) -> DnsRuntimeMarkInfo {
        DnsRuntimeMarkInfo {
            mark: FlowMark::new(action, 14, false),
            priority: 100,
        }
    }

    fn entry(domain: &str, ttl: u32, action: FlowMarkAction) -> CacheEntry {
        CacheEntry {
            domain_key: Arc::<str>::from(domain),
            query_type: RecordType::A,
            rdatas: vec![record(ttl)],
            response_code: ResponseCode::NoError,
            negative_ttl: None,
            mark: mark(action),
            filter: FilterResult::Unfilter,
            matched_rule_id: None,
            matched_rule_order: None,
        }
    }

    /// Counts the writes and can be told to refuse them, which is what makes the
    /// two behaviours below observable.
    struct CountingSink {
        writes: AtomicUsize,
        refuse: bool,
    }

    impl CountingSink {
        fn new(refuse: bool) -> Arc<Self> {
            Arc::new(Self { writes: AtomicUsize::new(0), refuse })
        }
    }

    impl DnsResultSink for CountingSink {
        fn record_dns_answer(
            &self,
            flow_id: u32,
            _generation: u64,
            _marks: Vec<FlowMarkInfo>,
        ) -> Result<(), DnsMarkInstallError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            if self.refuse {
                return Err(DnsMarkInstallError {
                    flow_id,
                    detail: "test sink refuses every write".into(),
                    superseded: false,
                });
            }
            Ok(())
        }

        fn refresh_dns_marks<'a>(
            &self,
            _flow_id: u32,
            _generation: u64,
            collect: Box<dyn FnOnce() -> Vec<FlowMarkInfo> + Send + 'a>,
        ) -> Result<(), DnsMarkInstallError> {
            let _ = collect();
            Ok(())
        }

        fn rebuild_route_cache(&self) {}
    }

    fn handle(sink: Arc<CountingSink>) -> CacheHandle {
        CacheHandle::new(runtime_config(), 14, sink, 1)
    }

    /// A zero-TTL answer is not cached, and its mark still reaches the datapath.
    /// Serving it while skipping the registration would leave the address
    /// unprotected for as long as the client keeps using it - which is the whole
    /// reason the registration happens before the cache decision.
    #[tokio::test]
    async fn a_zero_ttl_answer_registers_its_mark_and_is_not_cached() {
        let sink = CountingSink::new(false);
        let cache = handle(sink.clone());
        let domain = ParsedDomain::new("zero-ttl.example.").expect("a literal name");

        cache
            .insert(entry("zero-ttl.example.", 0, FlowMarkAction::Redirect))
            .await
            .expect("the sink accepts it");

        assert_eq!(
            sink.writes.load(Ordering::SeqCst),
            1,
            "the mark must be written even though the answer will not be cached"
        );
        assert!(
            cache.lookup(&domain, RecordType::A).await.is_none(),
            "a zero lifetime means it is not kept"
        );
    }

    /// The refusal: an answer that needs a route association and cannot get one is
    /// not served and not cached.
    #[tokio::test]
    async fn an_answer_needing_an_association_is_refused_when_the_write_fails() {
        let sink = CountingSink::new(true);
        let cache = handle(sink.clone());
        let domain = ParsedDomain::new("needs-association.example.").expect("a literal name");

        let result =
            cache.insert(entry("needs-association.example.", 300, FlowMarkAction::Redirect)).await;

        assert!(result.is_err(), "a redirect mark that cannot be installed must refuse the answer");
        assert!(
            cache.lookup(&domain, RecordType::A).await.is_none(),
            "and nothing may be cached under that name, or a later query would serve it unprotected"
        );
    }

    /// The other side of the same rule: an answer that asks for no association is
    /// served even when the datapath write fails, because a missing entry is
    /// exactly what it asked for.
    #[tokio::test]
    async fn a_direct_answer_is_served_even_when_the_write_fails() {
        let sink = CountingSink::new(true);
        let cache = handle(sink.clone());
        let domain = ParsedDomain::new("direct.example.").expect("a literal name");

        cache
            .insert(entry("direct.example.", 300, FlowMarkAction::Direct))
            .await
            .expect("a direct answer needs no association, so the failure is not fatal");

        assert!(
            cache.lookup(&domain, RecordType::A).await.is_some(),
            "it must still be served and cached"
        );
    }
}
