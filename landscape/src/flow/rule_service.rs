use std::sync::Arc;

use landscape_common::{
    concurrency::{spawn_task, task_label},
    database::store::{Change, ConfigStore},
    event::dns::DnsEvent,
    event::hub::EnrolledDeviceEventReader,
    flow::{
        FlowEntryMatchMode, FlowRuleError, FlowTarget, config::FlowConfig,
        dataplane::FlowRuleDataplane,
    },
    service::controller::{ConfigStoreController, ConfigStoreFlowController},
};
use landscape_database::{
    flow_rule::repository::{FlowConfigRepository, find_duplicate_resolved_modes},
    provider::LandscapeDBServiceProvider,
};
use std::collections::BTreeMap;
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

use crate::proxy::tproxy::TproxyDelivery;
use crate::sys_service::route::IpRouteService;

/// Derive the `flow_id -> local TProxy listener port` mapping the kernel has to
/// deliver.
///
/// The datapath keys flows by the low byte of `skb->mark` (`route4_flow_verdict`
/// guarantees `mark & 0xff == flow_id`), so two flows sharing that byte cannot
/// coexist — a collision is reported instead of silently redirecting the wrong
/// traffic.
pub fn collect_tproxy_targets(flow_configs: &[FlowConfig]) -> BTreeMap<u8, u16> {
    let mut targets: BTreeMap<u8, u16> = BTreeMap::new();
    for config in flow_configs {
        if !config.enable {
            continue;
        }
        if config.flow_id > u8::MAX as u32 {
            tracing::warn!(
                "flow {} has flow_id {}, but the datapath only carries the low 8 bits; tproxy delivery cannot be programmed for it",
                config.name,
                config.flow_id
            );
            continue;
        }
        let flow_byte = config.flow_id as u8;
        for target in &config.flow_targets {
            if target.weight == 0 {
                continue;
            }
            let FlowTarget::LocalTproxy { port } = &target.target else {
                continue;
            };
            let port = *port;
            match targets.get(&flow_byte) {
                Some(existing) if *existing != port => tracing::error!(
                    "flows share flow_id {flow_byte} (mark & 0xff) with different tproxy ports ({existing} and {port}); only the last one can be delivered"
                ),
                _ => {}
            }
            targets.insert(flow_byte, port);
        }
    }
    targets
}

#[derive(Clone)]
pub struct FlowRuleService {
    store: FlowConfigRepository,
    dns_events_tx: mpsc::Sender<DnsEvent>,
    route_service: IpRouteService,
    dataplane: Arc<dyn FlowRuleDataplane>,
    tproxy: Arc<TproxyDelivery>,
}

impl FlowRuleService {
    pub async fn new(
        store_provider: LandscapeDBServiceProvider,
        dns_events_tx: mpsc::Sender<DnsEvent>,
        route_service: IpRouteService,
        device_reader: EnrolledDeviceEventReader,
        dataplane: Arc<dyn FlowRuleDataplane>,
        tproxy: Arc<TproxyDelivery>,
    ) -> Self {
        let store = store_provider.flow_rule_store();
        let result = Self {
            store,
            dns_events_tx,
            route_service,
            dataplane,
            tproxy,
        };
        // Subscribe before the initial sync so no WanRouteEvent can slip in
        // between the sync and the subscription; events arriving during the
        // sync only trigger a redundant, idempotent resync.
        let wan_route_events = result.route_service.subscribe_wan_route_events();
        result.refresh_flow_matches().await;
        result.sync_all_flow_wan_targets().await;
        result.sync_tproxy_delivery().await;

        let this = result.clone();
        spawn_task(task_label::task::FLOW_RULE_OBSERVER, async move {
            let mut rx = device_reader;
            while rx.recv().await.is_ok() {
                this.refresh_flow_matches().await;
            }
        });

        // Recompute the per-flow WAN target slots whenever the route service
        // reports a WAN route change; the flow side owns the configs, so the
        // join lives here instead of inside the route service.
        let this = result.clone();
        spawn_task(task_label::task::FLOW_WAN_ROUTE_OBSERVER, async move {
            let mut events = wan_route_events;
            loop {
                match events.recv().await {
                    Ok(_) => this.sync_all_flow_wan_targets().await,
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        tracing::warn!("flow wan route observer missed {missed} events; resyncing");
                        this.sync_all_flow_wan_targets().await;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        result
    }

    pub async fn refresh_flow_matches(&self) {
        let runtime_configs = match self.store.list_runtime_configs().await {
            Ok(runtime_configs) => runtime_configs,
            Err(error) => {
                tracing::error!("failed to load flow runtime configs: {error:?}");
                return;
            }
        };

        self.dataplane.sync_flow_matches(&runtime_configs);

        let _ = self.dns_events_tx.send(DnsEvent::FlowUpdated).await;
    }

    /// Recompute every flow's WAN target slots from the current store
    /// contents against the route service's WAN state.
    async fn sync_all_flow_wan_targets(&self) {
        let configs = self.store.list().await.unwrap_or_else(|error| {
            tracing::error!("failed to load flow configs for wan target sync: {error:?}");
            Vec::new()
        });
        self.route_service.sync_flow_wan_targets(&configs).await;
    }

    /// Publish the current `flow_id -> tproxy port` mapping to the delivery
    /// fabric, which reconciles the kernel TPROXY rules against it.
    pub async fn sync_tproxy_delivery(&self) {
        let configs = self.store.list().await.unwrap_or_else(|error| {
            tracing::error!("failed to load flow configs for tproxy delivery sync: {error:?}");
            Vec::new()
        });
        self.tproxy.set_targets(collect_tproxy_targets(&configs)).await;
    }
}

impl FlowRuleService {
    pub async fn find_resolved_conflict_for_modes(
        &self,
        exclude_id: uuid::Uuid,
        modes: &[FlowEntryMatchMode],
    ) -> Result<Option<(FlowEntryMatchMode, FlowConfig)>, FlowRuleError> {
        self.store.find_resolved_conflict_for_modes(exclude_id, modes).await
    }

    pub async fn find_duplicate_resolved_mode(
        &self,
        modes: &[FlowEntryMatchMode],
    ) -> Result<Option<FlowEntryMatchMode>, FlowRuleError> {
        let resolved_modes = self.store.resolve_modes(modes).await?;
        Ok(find_duplicate_resolved_modes(&resolved_modes))
    }

    pub async fn validate_modes_resolvable(
        &self,
        modes: &[FlowEntryMatchMode],
    ) -> Result<(), FlowRuleError> {
        self.store.validate_modes_resolvable(modes).await
    }
}

impl ConfigStoreFlowController for FlowRuleService {}

#[async_trait::async_trait]
impl ConfigStoreController for FlowRuleService {
    type Id = Uuid;
    type Config = FlowConfig;
    type Store = FlowConfigRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }

    async fn notify_changed(&self, changes: Vec<Change<Self::Config>>) {
        self.refresh_flow_matches().await;
        let configs: Vec<FlowConfig> = changes.into_iter().map(|change| change.new).collect();
        self.route_service.sync_flow_wan_targets(&configs).await;
        // Ports may have changed (or a target may have stopped being a local
        // TProxy), so the kernel rules are re-derived from the whole store.
        self.sync_tproxy_delivery().await;
    }

    async fn notify_deleted(&self, old: Self::Config) {
        self.refresh_flow_matches().await;
        self.route_service.clear_flow_wan_targets(old.flow_id);
        self.dataplane.delete_flow(old.flow_id);
        self.dataplane.invalidate_lan_cache();
        // The deleted flow may have owned a redirect rule.
        self.sync_tproxy_delivery().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::flow::{FlowTarget, config::WeightedFlowTarget};

    fn flow(flow_id: u32, enable: bool, targets: Vec<WeightedFlowTarget>) -> FlowConfig {
        FlowConfig {
            id: Uuid::new_v4(),
            enable,
            flow_id,
            flow_match_rules: Vec::new(),
            flow_targets: targets,
            name: format!("flow-{flow_id}"),
            remark: String::new(),
            update_at: 0.0,
        }
    }

    fn tproxy(port: u16, weight: u32) -> WeightedFlowTarget {
        WeightedFlowTarget::new(FlowTarget::LocalTproxy { port }, weight)
    }

    #[test]
    fn collects_enabled_local_tproxy_targets_only() {
        let configs = vec![
            flow(10, true, vec![tproxy(7892, 1)]),
            flow(
                11,
                true,
                vec![WeightedFlowTarget::new(FlowTarget::Interface { name: "wan".to_string() }, 1)],
            ),
            flow(12, false, vec![tproxy(7894, 1)]),
            flow(13, true, vec![tproxy(7895, 0)]),
            flow(14, true, vec![tproxy(7896, 2)]),
        ];

        let targets = collect_tproxy_targets(&configs);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets.get(&10), Some(&7892));
        assert_eq!(targets.get(&14), Some(&7896));
        // disabled / non-tproxy / zero-weight entries never produce a redirect
        assert!(!targets.contains_key(&11));
        assert!(!targets.contains_key(&12));
        assert!(!targets.contains_key(&13));
    }

    #[test]
    fn flow_ids_above_the_mark_byte_are_skipped() {
        // The datapath only carries the low byte of the flow id, so a flow the
        // kernel cannot address is skipped rather than given a redirect for an
        // unrelated flow byte (300 & 0xff == 44).
        let configs = vec![flow(300, true, vec![tproxy(7892, 1)])];
        assert!(collect_tproxy_targets(&configs).is_empty());
    }

    #[test]
    fn a_duplicate_flow_id_keeps_the_last_port() {
        let configs =
            vec![flow(10, true, vec![tproxy(7892, 1)]), flow(10, true, vec![tproxy(7893, 1)])];
        let targets = collect_tproxy_targets(&configs);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets.get(&10), Some(&7893));
    }
}
