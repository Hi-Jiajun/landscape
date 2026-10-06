use std::sync::Arc;

use landscape_common::flow::{DnsMarkInstallError, DnsResultSink, FlowMarkInfo};

use crate::maps::{LandscapeMapPath, flow_dns, route};

/// eBPF-backed [`DnsResultSink`]: writes DNS answers into the flow-dns mark
/// maps and keeps the LAN route cache in sync.
///
/// The rule-generation gate lives in [`flow_dns`], next to the write lock, so
/// that the generation check and the map write it guards happen under one lock
/// instead of two separate steps.
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
        generation: u64,
        marks: Vec<FlowMarkInfo>,
    ) -> Result<(), DnsMarkInstallError> {
        flow_dns::update_flow_dns_rule(&self.paths, flow_id, generation, marks).map_err(|e| {
            if matches!(e, flow_dns::FlowDnsWriteError::Superseded { .. }) {
                DnsMarkInstallError { flow_id, detail: e.to_string(), superseded: true }
            } else {
                DnsMarkInstallError::write_failed(flow_id, e.to_string())
            }
        })
    }

    fn refresh_dns_marks(
        &self,
        flow_id: u32,
        generation: u64,
        marks: Vec<FlowMarkInfo>,
    ) -> Result<(), DnsMarkInstallError> {
        if let Err(e) =
            flow_dns::refreash_flow_dns_inner_map(&self.paths, flow_id, generation, marks)
        {
            // The previous inner map stays in place, and the caller keeps the
            // previous rules so the two still agree.
            tracing::error!(
                flow_id,
                "failed to refresh the DNS mark table; keeping the previous rules: {e}"
            );
            return Err(DnsMarkInstallError::write_failed(flow_id, e.to_string()));
        }
        Ok(())
    }

    fn rebuild_route_cache(&self) {
        route::cache::recreate_route_lan_cache_inner_map(&self.paths);
    }
}
