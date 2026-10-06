use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use landscape_common::flow::{DnsMarkInstallError, DnsResultSink, FlowMarkInfo};

use crate::maps::{LandscapeMapPath, flow_dns, route};

/// Which rule generation a flow's mark table currently reflects.
///
/// A DNS query that started before a rule change keeps the snapshot it began
/// with, so it can finish after the rebuild already published the new table.
/// Admitting only writes that are at least as new as the published generation
/// keeps the old rules from being re-applied to one address.
#[derive(Debug, Default)]
pub struct MarkGenerationGate {
    published: Mutex<HashMap<u32, u64>>,
}

impl MarkGenerationGate {
    /// Records `generation` as published for `flow_id`; returns `false` when a
    /// newer generation has already been published, i.e. this write is stale.
    pub fn admit(&self, flow_id: u32, generation: u64) -> bool {
        let mut published = self.published.lock().unwrap_or_else(|e| e.into_inner());
        match published.get(&flow_id) {
            Some(current) if generation < *current => false,
            _ => {
                published.insert(flow_id, generation);
                true
            }
        }
    }

    /// The generation currently published for a flow, if any.
    pub fn published(&self, flow_id: u32) -> Option<u64> {
        self.published.lock().unwrap_or_else(|e| e.into_inner()).get(&flow_id).copied()
    }
}

/// eBPF-backed [`DnsResultSink`]: writes DNS answers into the flow-dns mark
/// maps and keeps the LAN route cache in sync.
pub struct EbpfDnsResultSink {
    paths: Arc<LandscapeMapPath>,
    generations: MarkGenerationGate,
}

impl EbpfDnsResultSink {
    pub fn new(paths: Arc<LandscapeMapPath>) -> Self {
        Self { paths, generations: MarkGenerationGate::default() }
    }
}

impl DnsResultSink for EbpfDnsResultSink {
    fn record_dns_answer(
        &self,
        flow_id: u32,
        generation: u64,
        marks: Vec<FlowMarkInfo>,
    ) -> Result<(), DnsMarkInstallError> {
        if !self.generations.admit(flow_id, generation) {
            let current = self.generations.published(flow_id).unwrap_or(generation);
            return Err(DnsMarkInstallError::superseded(flow_id, generation, current));
        }
        flow_dns::update_flow_dns_rule(&self.paths, flow_id, marks)
            .map_err(|e| DnsMarkInstallError { flow_id, detail: e.to_string() })
    }

    fn refresh_dns_marks(&self, flow_id: u32, generation: u64, marks: Vec<FlowMarkInfo>) {
        // The rebuild is authoritative: it moves the published generation
        // forward even when the table itself turned out empty.
        self.generations.admit(flow_id, generation);
        if let Err(e) = flow_dns::refreash_flow_dns_inner_map(&self.paths, flow_id, marks) {
            // A refresh recomputes the table from the whole cache, so a failure
            // leaves the previous inner map in place; the next refresh retries.
            tracing::error!("failed to refresh the DNS mark table for flow {flow_id}: {e}");
        }
    }

    fn rebuild_route_cache(&self) {
        route::cache::recreate_route_lan_cache_inner_map(&self.paths);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_write_for_a_flow_is_admitted() {
        let gate = MarkGenerationGate::default();
        assert!(gate.admit(0, 1));
        assert_eq!(gate.published(0), Some(1));
    }

    #[test]
    fn same_generation_may_keep_writing() {
        let gate = MarkGenerationGate::default();
        assert!(gate.admit(0, 3));
        // Several answers of one generation all reach the table.
        assert!(gate.admit(0, 3));
        assert!(gate.admit(0, 3));
    }

    #[test]
    fn a_stale_generation_is_rejected() {
        let gate = MarkGenerationGate::default();
        assert!(gate.admit(0, 4));
        // An answer that started before the rule change must not re-apply the
        // rules that change replaced.
        assert!(!gate.admit(0, 3));
        assert!(!gate.admit(0, 1));
        // ... and it must not move the published generation backwards.
        assert_eq!(gate.published(0), Some(4));
    }

    #[test]
    fn a_newer_generation_takes_over() {
        let gate = MarkGenerationGate::default();
        assert!(gate.admit(0, 4));
        assert!(gate.admit(0, 5));
        assert_eq!(gate.published(0), Some(5));
        assert!(!gate.admit(0, 4));
    }

    #[test]
    fn flows_are_tracked_independently() {
        let gate = MarkGenerationGate::default();
        assert!(gate.admit(10, 2));
        // Another flow's generation counter is unrelated.
        assert!(gate.admit(14, 1));
        assert_eq!(gate.published(10), Some(2));
        assert_eq!(gate.published(14), Some(1));
        assert_eq!(gate.published(99), None);
    }
}
