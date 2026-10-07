//! Flow rule sync: push flow-match rules and per-flow destination-IP
//! marks into the eBPF maps and invalidate the verdict cache.

use crate::flow::RuntimeFlowConfig;
use crate::flow::ip_mark::IpMarkInfo;
use serde::{Deserialize, Serialize};

/// What the datapath does with a destination that nothing classified.
///
/// The contract for this gateway is that an unclassified destination goes to a
/// managed tier or is refused - never silently direct. Which of those it is, is
/// an operator decision, so it is explicit configuration rather than a default
/// hidden in the datapath.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum UnclassifiedPolicy {
    /// Leave the packet on its own flow. This is the historical behaviour and
    /// means an unclassified destination leaves from the client's own address.
    #[default]
    Passthrough,
    /// Refuse it in the datapath.
    Drop,
    /// Send it to a managed tier. A tier that does not exist refuses the packet
    /// rather than falling back to a direct path.
    ProxyTier { flow_id: u32 },
}

/// eBPF capability for the flow rule services.
pub trait FlowRuleDataplane: Send + Sync {
    /// Reconcile the flow-match map to `configs` (also invalidates the
    /// LAN verdict cache on change).
    fn sync_flow_matches(&self, configs: &[RuntimeFlowConfig]);

    /// Create or update the per-flow destination-IP LPM marks of
    /// `flow_id`.
    fn set_dst_ip_marks(&self, flow_id: u32, ips: Vec<IpMarkInfo>);

    /// Delete outer map-in-map entries for `flow_id` when a flow is removed.
    fn delete_flow(&self, flow_id: u32);

    /// Recreate the LAN verdict-cache inner maps (invalidate all cached
    /// verdicts).
    fn invalidate_lan_cache(&self);

    /// Set the policy for an unclassified destination.
    ///
    /// Changing it **must** invalidate the LAN verdict cache: a cached verdict is
    /// the outcome of the old policy, and leaving it in place would keep serving
    /// the previous decision for every destination that was already resolved.
    fn set_unclassified_policy(&self, policy: UnclassifiedPolicy);
}

/// No-op implementation for tests.
pub struct NoopFlowRuleDataplane;

impl FlowRuleDataplane for NoopFlowRuleDataplane {
    fn sync_flow_matches(&self, _configs: &[RuntimeFlowConfig]) {}

    fn set_dst_ip_marks(&self, _flow_id: u32, _ips: Vec<IpMarkInfo>) {}

    fn delete_flow(&self, _flow_id: u32) {}

    fn invalidate_lan_cache(&self) {}

    fn set_unclassified_policy(&self, _policy: UnclassifiedPolicy) {}
}
