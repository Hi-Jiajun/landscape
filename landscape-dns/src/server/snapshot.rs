use std::{collections::HashSet, sync::Arc};

use arc_swap::ArcSwap;
#[cfg(test)]
use arc_swap::Guard;
use std::sync::atomic::{AtomicU64, Ordering};

use landscape_common::flow::{DnsResultSink, FlowMarkInfo};

use crate::{
    CacheDNSItem,
    domain::ParsedDomain,
    server::{
        CacheRuntimeConfig, cache::CacheHandle, local::LocalResolver,
        redirect_engine::RedirectEngine, resolve_engine::ResolveEngine, rule::DNSResolveRuntime,
    },
};

/// Migrated cache entries keep a TTL at most this long when rules are
/// refreshed, so stale answers converge quickly after a config change.
pub(crate) const RULE_REFRESH_TTL_CAP: u32 = 5;

/// Immutable, atomically swappable view of the DNS resolution state: the two
/// rule engines and the cache they share.
#[derive(Debug)]
pub(crate) struct RuntimeSnapshot {
    pub redirect_engine: Arc<RedirectEngine>,
    pub resolve_engine: Arc<ResolveEngine>,
    /// The cache also carries this generation (`cache.generation()`), and the
    /// cache is replaced together with the snapshot, so the value is not
    /// duplicated here where it could drift.
    pub cache: CacheHandle,
}

/// What part of the runtime snapshot to replace on a config refresh.
pub(crate) enum SnapshotPatch {
    /// Replace both engines; migrated cache TTL is capped.
    Full { redirect_engine: RedirectEngine, resolve_engine: ResolveEngine },
    /// Replace only the resolve engine; migrated cache TTL is capped.
    Resolves { resolve_engine: ResolveEngine },
    /// Replace only the redirect engine, dropping cache entries now claimed
    /// by redirects.
    Redirects { redirect_engine: RedirectEngine },
    /// Rebuild the cache from the current config (capacity/TTL), keeping
    /// both engines.
    RebuildCache,
}

/// Owns the current [`RuntimeSnapshot`] and applies [`SnapshotPatch`]es with
/// cache migration and datapath side effects.
pub(crate) struct SnapshotStore {
    runtime: Arc<ArcSwap<RuntimeSnapshot>>,
    runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
    flow_id: u32,
    local_resolver: Arc<LocalResolver>,
    sink: Arc<dyn DnsResultSink>,
    /// Monotonic counter bumped on every applied patch. See [`RuntimeSnapshot`].
    generation: AtomicU64,
    /// Serialises patch application. Two patches must not interleave their
    /// rebuild-and-publish sequences: the older one could otherwise finish last
    /// and put its table and generation back in front of the newer one.
    apply_lock: tokio::sync::Mutex<()>,
}

impl SnapshotStore {
    pub fn new(
        redirect_engine: RedirectEngine,
        resolve_engine: ResolveEngine,
        runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
        flow_id: u32,
        local_resolver: Arc<LocalResolver>,
        sink: Arc<dyn DnsResultSink>,
    ) -> Self {
        const INITIAL_GENERATION: u64 = 1;
        let cache =
            CacheHandle::new(runtime_config.clone(), flow_id, sink.clone(), INITIAL_GENERATION);
        Self {
            runtime: Arc::new(ArcSwap::from_pointee(RuntimeSnapshot {
                redirect_engine: Arc::new(redirect_engine),
                resolve_engine: Arc::new(resolve_engine),
                cache,
            })),
            runtime_config,
            flow_id,
            local_resolver,
            sink,
            generation: AtomicU64::new(INITIAL_GENERATION),
            apply_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Claims the next rule generation. Called once per applied patch, before
    /// the rebuilt table is published, so the table and the snapshot that
    /// describes it share one generation.
    fn next_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub fn flow_id(&self) -> u32 {
        self.flow_id
    }

    #[cfg(test)]
    pub fn runtime_config(&self) -> &Arc<ArcSwap<CacheRuntimeConfig>> {
        &self.runtime_config
    }

    pub fn local_resolver(&self) -> &Arc<LocalResolver> {
        &self.local_resolver
    }

    pub fn sink(&self) -> &Arc<dyn DnsResultSink> {
        &self.sink
    }

    #[cfg(test)]
    pub fn load(&self) -> Guard<Arc<RuntimeSnapshot>> {
        self.runtime.load()
    }

    pub fn load_full(&self) -> Arc<RuntimeSnapshot> {
        self.runtime.load_full()
    }

    pub async fn apply(&self, patch: SnapshotPatch) {
        let _apply_guard = self.apply_lock.lock().await;
        // Every patch replaces rules, so every patch starts a new generation.
        // Answers still in flight keep the snapshot they began with and are
        // stamped with the generation they were produced under.
        let generation = self.next_generation();
        match patch {
            SnapshotPatch::Full { redirect_engine, resolve_engine } => {
                self.swap(
                    Arc::new(redirect_engine),
                    Arc::new(resolve_engine),
                    Some(RULE_REFRESH_TTL_CAP),
                    generation,
                )
                .await;
            }
            SnapshotPatch::Resolves { resolve_engine } => {
                let current = self.runtime.load_full();
                self.swap(
                    current.redirect_engine.clone(),
                    Arc::new(resolve_engine),
                    Some(RULE_REFRESH_TTL_CAP),
                    generation,
                )
                .await;
            }
            SnapshotPatch::Redirects { redirect_engine } => {
                let current = self.runtime.load_full();
                let new_cache = self
                    .remove_redirected_cache(&current.cache, &redirect_engine, generation)
                    .await;
                self.refresh_maps_from_cache(&new_cache);
                self.runtime.store(Arc::new(RuntimeSnapshot {
                    redirect_engine: Arc::new(redirect_engine),
                    resolve_engine: current.resolve_engine.clone(),
                    cache: new_cache,
                }));
            }
            SnapshotPatch::RebuildCache => {
                let current = self.runtime.load_full();
                self.swap(
                    current.redirect_engine.clone(),
                    current.resolve_engine.clone(),
                    None,
                    generation,
                )
                .await;
            }
        }
    }

    /// Rebuilds the cache, migrates surviving entries, publishes the new
    /// runtime snapshot and refreshes the eBPF mark/route maps.
    async fn swap(
        &self,
        redirect_engine: Arc<RedirectEngine>,
        resolve_engine: Arc<ResolveEngine>,
        ttl_cap: Option<u32>,
        generation: u64,
    ) {
        let (new_cache, update_dns_mark_list) =
            self.rebuild_cache(&redirect_engine, &resolve_engine, ttl_cap, generation).await;

        tracing::debug!("add_dns_marks: {:?}", update_dns_mark_list);
        // Publish the rebuilt table before the snapshot that describes it, so a
        // query can never see the new rules while the table still holds the old
        // ones.
        self.sink.refresh_dns_marks(
            self.flow_id,
            generation,
            update_dns_mark_list.into_iter().collect(),
        );
        self.runtime.store(Arc::new(RuntimeSnapshot {
            redirect_engine,
            resolve_engine,
            cache: new_cache,
        }));
        self.sink.rebuild_route_cache();
    }

    async fn rebuild_cache(
        &self,
        redirects: &RedirectEngine,
        resolves: &ResolveEngine,
        ttl_cap: Option<u32>,
        generation: u64,
    ) -> (CacheHandle, HashSet<FlowMarkInfo>) {
        let new_cache = CacheHandle::new(
            self.runtime_config.clone(),
            self.flow_id,
            self.sink.clone(),
            generation,
        );
        self.migrate_cache(&new_cache, redirects, resolves, ttl_cap).await;
        new_cache.run_pending_tasks().await;
        let update_dns_mark_list = new_cache.dns_mark_list();
        (new_cache, update_dns_mark_list)
    }

    async fn remove_redirected_cache(
        &self,
        current_cache: &CacheHandle,
        redirects: &RedirectEngine,
        generation: u64,
    ) -> CacheHandle {
        let new_cache = CacheHandle::new(
            self.runtime_config.clone(),
            self.flow_id,
            self.sink.clone(),
            generation,
        );
        for (key, value) in current_cache.iter() {
            let (domain, req_type) = &*key;
            let Ok(pd) = ParsedDomain::new(domain) else { continue };
            if redirects
                .lookup(&pd, *req_type, self.local_resolver.local_answer_provider())
                .is_none()
            {
                new_cache.insert_raw((domain.clone(), *req_type), value).await;
            }
        }
        new_cache.run_pending_tasks().await;
        new_cache
    }

    async fn migrate_cache(
        &self,
        new_cache: &CacheHandle,
        redirects: &RedirectEngine,
        resolves: &ResolveEngine,
        ttl_cap: Option<u32>,
    ) {
        let current_cache = &self.runtime.load().cache;

        for (key, value) in current_cache.iter() {
            let (domain, req_type) = &*key;
            let Ok(pd) = ParsedDomain::new(domain) else { continue };
            let cache_item = value;
            if redirects
                .lookup(&pd, *req_type, self.local_resolver.local_answer_provider())
                .is_some()
            {
                continue;
            }
            if let Some(resolver) = Self::find_cache_rule(resolves, &pd, &cache_item) {
                let new_mark = resolver.mark().clone();

                let new_item = CacheDNSItem {
                    rdatas: cache_item.rdatas.clone(),
                    response_code: cache_item.response_code,
                    mark: new_mark.clone(),
                    insert_time: cache_item.insert_time,
                    min_ttl: ttl_cap.map_or(cache_item.min_ttl, |cap| cache_item.min_ttl.min(cap)),
                    filter: resolver.filter_mode(),
                    matched_rule_id: Some(resolver.get_config_id()),
                    matched_rule_order: Some(resolver.order()),
                };

                new_cache.insert_raw((domain.clone(), *req_type), Arc::new(new_item)).await;
            }
        }
    }

    fn find_cache_rule<'a>(
        resolves: &'a ResolveEngine,
        domain: &ParsedDomain,
        cache_item: &CacheDNSItem,
    ) -> Option<&'a DNSResolveRuntime> {
        if let Some(rule_order) = cache_item.matched_rule_order
            && let Some(resolver) = resolves.get(rule_order)
            && cache_item.matched_rule_id == Some(resolver.get_config_id())
            && resolver.is_match(domain)
        {
            return Some(resolver);
        }

        resolves.find_match(domain)
    }

    pub fn refresh_maps_from_cache(&self, cache: &CacheHandle) {
        self.sink.refresh_dns_marks(
            self.flow_id,
            cache.generation(),
            cache.dns_mark_list().into_iter().collect(),
        );
        self.sink.rebuild_route_cache();
    }
}
