use std::sync::Arc;

use landscape_common::flow::{DnsMarkInstallError, DnsResultSink, FlowMarkInfo};

use crate::maps::{LandscapeMapPath, flow_dns, route};

/// eBPF-backed [`DnsResultSink`]: writes DNS answers into the flow-dns mark
/// maps and keeps the LAN route cache in sync.
pub struct EbpfDnsResultSink {
    paths: Arc<LandscapeMapPath>,
}

impl EbpfDnsResultSink {
    pub fn new(paths: Arc<LandscapeMapPath>) -> Self {
        Self { paths }
    }
}

impl DnsResultSink for EbpfDnsResultSink {
    fn record_dns_answer(
        &self,
        flow_id: u32,
        marks: Vec<FlowMarkInfo>,
    ) -> Result<(), DnsMarkInstallError> {
        flow_dns::update_flow_dns_rule(&self.paths, flow_id, marks)
            .map_err(|e| DnsMarkInstallError { flow_id, detail: e.to_string() })
    }

    fn refresh_dns_marks(&self, flow_id: u32, marks: Vec<FlowMarkInfo>) {
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
