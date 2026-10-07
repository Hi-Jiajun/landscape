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

    /// Whether any claim still justifies a value for `address`.
    fn is_claimed(&self, address: IpAddr) -> bool {
        self.claims
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&address)
            .is_some_and(|owners| !owners.is_empty())
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
pub(crate) struct CacheEntry {
    pub(crate) domain_key: Arc<str>,
    pub(crate) query_type: RecordType,
    pub(crate) rdatas: Vec<Record>,
    pub(crate) response_code: ResponseCode,
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
            mark,
            filter,
            matched_rule_id,
            matched_rule_order,
        } = entry;
        let min_ttl = rdatas
            .iter()
            .map(|r| r.ttl)
            .min()
            .unwrap_or_else(|| self.runtime_config.load().negative_cache_ttl);

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
        // are reconciled here, inside the same flow write: entries no claim
        // justifies any more are dropped so the address falls back to the flow's
        // own policy instead of keeping a decision nothing supports.
        self.reconcile_unclaimed().await;
        Ok(())
    }

    /// Drop the datapath entries for addresses nothing claims any more.
    async fn reconcile_unclaimed(&self) {
        let stale = self.claims.take_stale();
        if stale.is_empty() {
            return;
        }
        let unclaimed: Vec<IpAddr> =
            stale.into_iter().filter(|address| !self.claims.is_claimed(*address)).collect();
        if unclaimed.is_empty() {
            return;
        }
        tracing::debug!(
            flow_id = self.flow_id,
            addresses = unclaimed.len(),
            "dropping route marks no cached answer claims any more"
        );
        if let Err(e) = self.sink.forget_dns_marks(self.flow_id, self.generation, unclaimed) {
            tracing::error!(
                flow_id = self.flow_id,
                "could not drop the route marks of unclaimed addresses: {e}"
            );
        }
    }

    pub fn resolver_cache_entry(
        resolver: &DNSResolveRuntime,
        domain_key: &Arc<str>,
        query_type: RecordType,
        rdatas: Vec<Record>,
        response_code: ResponseCode,
    ) -> CacheEntry {
        CacheEntry {
            domain_key: domain_key.clone(),
            query_type,
            rdatas,
            response_code,
            mark: resolver.mark().clone(),
            filter: resolver.filter_mode(),
            matched_rule_id: Some(resolver.get_config_id()),
            matched_rule_order: Some(resolver.order()),
        }
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
        assert!(!index.is_claimed(claim.ip));
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
        assert!(index.is_claimed(shared.ip));
        assert!(index.take_stale().is_empty(), "a surviving claim keeps the value valid");
    }
}
