use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::domain::ParsedDomain;
use crate::server::rule::DNSResolveRuntime;

#[derive(Debug, Default)]
pub struct ResolveEngine {
    rules: BTreeMap<u32, DNSResolveRuntime>,
    /// How often each rule index matched, for the configuration audit.
    ///
    /// Counted here rather than derived from the query metrics: those record the
    /// outcome of a query, not which rule produced it, so "this rule has never
    /// matched" can only be answered by counting the match itself.
    hits: BTreeMap<u32, Arc<AtomicU64>>,
}

impl ResolveEngine {
    pub fn new(rules: BTreeMap<u32, DNSResolveRuntime>) -> Self {
        let hits = rules.keys().map(|order| (*order, Arc::new(AtomicU64::new(0)))).collect();
        Self { rules, hits }
    }

    pub fn find_match(&self, domain: &ParsedDomain) -> Option<&DNSResolveRuntime> {
        let rule = self.rules.values().find(|rule| rule.is_match(domain))?;
        if let Some(counter) = self.hits.get(&rule.order()) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        Some(rule)
    }

    /// Match counts per rule index, for the audit. Reading does not reset them.
    pub fn match_counts(&self) -> BTreeMap<u32, u64> {
        self.hits.iter().map(|(order, count)| (*order, count.load(Ordering::Relaxed))).collect()
    }

    pub fn get(&self, order: u32) -> Option<&DNSResolveRuntime> {
        self.rules.get(&order)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&u32, &DNSResolveRuntime)> {
        self.rules.iter()
    }
}

#[cfg(test)]
#[path = "resolve_engine_tests.rs"]
mod tests;
