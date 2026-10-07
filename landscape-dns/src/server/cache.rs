use std::{
    collections::HashSet,
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
        Self {
            cache: Self::build_cache(runtime_config.load().as_ref()),
            runtime_config,
            flow_id,
            sink,
            generation,
        }
    }

    fn build_cache(runtime_config: &CacheRuntimeConfig) -> DNSCache {
        Cache::builder()
            .max_capacity(runtime_config.cache_capacity as u64)
            .time_to_live(Duration::from_secs(runtime_config.cache_ttl as u64))
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
            update_dns_mark_list.iter().cloned().collect(),
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

        self.cache.insert((domain_key.clone(), query_type), Arc::new(cache_item)).await;

        // Run the marks through arbitration once more now that the answer is in
        // the cache. Installing them and caching the answer cannot be one step —
        // the install takes the datapath write while the cache commit is an
        // `await` — so a rebuild can collect the cache in between and publish a
        // table derived from an answer it could not see, deleting these marks.
        // Re-running the same arbitration covers both that hole and the shared
        // address now being claimed by two answers, which the first pass could
        // not see either.
        if let Err(e) = self.sink.record_dns_answer(
            self.flow_id,
            self.generation,
            update_dns_mark_list.into_iter().collect(),
        ) {
            tracing::error!(
                flow_id = self.flow_id,
                domain = %domain_key,
                "could not re-apply the route marks after caching the answer: {e}"
            );
        }
        Ok(())
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
