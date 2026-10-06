use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::service::ServiceStatus;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum ProxyEngine {
    #[default]
    Mihomo,
    MeowRs,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProxySubscription {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_update_interval")]
    pub update_interval_hours: u32,
    #[serde(default)]
    pub last_updated_at: Option<f64>,
    #[serde(default)]
    pub node_count: usize,
}

fn default_true() -> bool {
    true
}

fn default_update_interval() -> u32 {
    24
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProxyGroupConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub group_type: String,
    #[serde(default)]
    pub proxies: Vec<String>,
    #[serde(default)]
    pub use_providers: Vec<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub interval: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProxyListenerConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub listener_type: String,
    pub port: u16,
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub network: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProxyPluginConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub engine: ProxyEngine,
    #[serde(default)]
    pub engine_path: Option<String>,
    #[serde(default = "default_tproxy_port")]
    pub tproxy_port: u16,
    #[serde(default = "default_mixed_port")]
    pub mixed_port: u16,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    #[serde(default = "default_api_secret")]
    pub api_secret: String,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub subscriptions: Vec<ProxySubscription>,
    #[serde(default)]
    pub groups: Vec<ProxyGroupConfig>,
    #[serde(default)]
    pub custom_nodes: Vec<serde_json::Value>,
    #[serde(default = "default_listeners")]
    pub listeners: Vec<ProxyListenerConfig>,
    #[serde(default = "default_external_ui")]
    pub external_ui: Option<String>,

    /// Manage the kernel TPROXY fabric (mangle chain + `ip rule` + local route)
    /// for flows whose target is a local TProxy listener. Disable to keep
    /// hand-written rules untouched.
    #[serde(default = "default_true")]
    pub manage_tproxy_delivery: bool,

    /// Behaviour when a flow targets a TProxy port that nothing is listening
    /// on: `direct` keeps forwarding the flow unproxied (fail-open), `drop`
    /// keeps the redirect in place so the connection fails instead of leaking
    /// (fail-closed).
    #[serde(default)]
    pub tproxy_missing_listener: TproxyMissingListener,
}

/// What to do when a `LocalTproxy` flow points at a port with no listener.
///
/// Defaults to [`TproxyMissingListener::Drop`] on purpose: a flow that is
/// classified as proxied must never silently leave through the WAN with the
/// real source address just because the proxy is unavailable. Fail-open is
/// still available, but it has to be opted into explicitly and it weakens the
/// "real IP never exposed" property.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum TproxyMissingListener {
    /// Keep the redirect so packets are dropped by the missing listener
    /// instead of leaving the router unproxied (fail-closed, default).
    #[default]
    Drop,
    /// Forward the flow unproxied (fail-open). Explicit opt-in only: this can
    /// expose the router's real WAN address for a flow that was meant to be
    /// proxied.
    Direct,
}

/// One `LocalTproxy` flow and whether the kernel side is ready to deliver it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TproxyTargetStatus {
    pub flow_id: u8,
    pub port: u16,
    /// A socket is bound on `port` (TCP listener or bound UDP socket).
    pub listener_ready: bool,
    /// A redirect rule is installed for this target.
    pub rule_installed: bool,
}

/// Kernel state of the local TProxy delivery fabric for one address family
/// (`ipv4` / `ipv6`); the two families own separate netfilter tables and
/// separate routing rule tables.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TproxyFamilyStatus {
    pub family: String,
    pub chain_present: bool,
    pub prerouting_hooked: bool,
    pub ip_rule_present: bool,
    pub local_route_present: bool,
    /// Rules of our chain, in kernel order, as printed by `iptables -S`.
    #[serde(default)]
    pub rules: Vec<String>,
    /// Hand-written rules that duplicated a managed target and were removed.
    #[serde(default)]
    pub adopted_rules: Vec<String>,
}

impl TproxyFamilyStatus {
    pub fn is_consistent(&self) -> bool {
        self.chain_present
            && self.prerouting_hooked
            && self.ip_rule_present
            && self.local_route_present
    }
}

/// Kernel state of the local TProxy delivery fabric.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TproxyDeliveryStatus {
    pub enabled: bool,
    #[serde(default)]
    pub families: Vec<TproxyFamilyStatus>,
    #[serde(default)]
    pub targets: Vec<TproxyTargetStatus>,
    /// TPROXY rules outside our chains (informational; never modified).
    #[serde(default)]
    pub foreign_tproxy_rules: Vec<String>,
    /// `ip rule` entries that also target our route table but are not ours.
    /// Usually a leftover `fwmark 0x1/0x1` from a hand-written script: such a
    /// rule matches **every odd flow id** (the datapath stores the flow id in
    /// the mark's low byte) and can hijack unproxied packets into the local
    /// route table. Reported, never modified.
    #[serde(default)]
    pub foreign_ip_rules: Vec<String>,
    pub backend: Option<String>,
    pub last_error: Option<String>,
}

impl TproxyDeliveryStatus {
    /// Everything the fabric needs is in place for the configured targets.
    pub fn is_consistent(&self) -> bool {
        self.last_error.is_none()
            && !self.families.is_empty()
            && self.families.iter().all(|f| f.is_consistent())
            && self.targets.iter().all(|t| t.rule_installed)
    }
}

fn default_tproxy_port() -> u16 {
    17890
}

fn default_mixed_port() -> u16 {
    7890
}

fn default_api_port() -> u16 {
    9090
}

fn default_api_secret() -> String {
    "".to_string()
}

fn default_external_ui() -> Option<String> {
    Some("/var/lib/sing-box/ui".to_string())
}

fn default_mode() -> String {
    "rule".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for ProxyPluginConfig {
    fn default() -> Self {
        Self {
            enable: false,
            engine: ProxyEngine::default(),
            engine_path: None,
            tproxy_port: default_tproxy_port(),
            mixed_port: default_mixed_port(),
            api_port: default_api_port(),
            api_secret: default_api_secret(),
            external_ui: default_external_ui(),
            mode: default_mode(),
            log_level: default_log_level(),
            subscriptions: Vec::new(),
            groups: vec![
                ProxyGroupConfig {
                    name: "🚀 节点选择".to_string(),
                    group_type: "select".to_string(),
                    proxies: vec!["⚡ 自动优选".to_string(), "🎯 全球直连".to_string()],
                    use_providers: Vec::new(),
                    url: None,
                    interval: None,
                },
                ProxyGroupConfig {
                    name: "🤖 AI服务".to_string(),
                    group_type: "select".to_string(),
                    proxies: vec!["🚀 节点选择".to_string(), "DIRECT".to_string()],
                    use_providers: Vec::new(),
                    url: None,
                    interval: None,
                },
                ProxyGroupConfig {
                    name: "🎥 流媒体".to_string(),
                    group_type: "select".to_string(),
                    proxies: vec!["🚀 节点选择".to_string(), "DIRECT".to_string()],
                    use_providers: Vec::new(),
                    url: None,
                    interval: None,
                },
                ProxyGroupConfig {
                    name: "🎮 外服游戏".to_string(),
                    group_type: "select".to_string(),
                    proxies: vec!["🚀 节点选择".to_string(), "DIRECT".to_string()],
                    use_providers: Vec::new(),
                    url: None,
                    interval: None,
                },
                ProxyGroupConfig {
                    name: "🎮 Steam".to_string(),
                    group_type: "select".to_string(),
                    proxies: vec!["🎯 全球直连".to_string(), "🚀 节点选择".to_string()],
                    use_providers: Vec::new(),
                    url: None,
                    interval: None,
                },
                ProxyGroupConfig {
                    name: "💬 即时通讯".to_string(),
                    group_type: "select".to_string(),
                    proxies: vec!["🚀 节点选择".to_string(), "DIRECT".to_string()],
                    use_providers: Vec::new(),
                    url: None,
                    interval: None,
                },
                ProxyGroupConfig {
                    name: "🐟 漏网之鱼".to_string(),
                    group_type: "select".to_string(),
                    proxies: vec!["🚀 节点选择".to_string(), "DIRECT".to_string()],
                    use_providers: Vec::new(),
                    url: None,
                    interval: None,
                },
                ProxyGroupConfig {
                    name: "⚡ 自动优选".to_string(),
                    group_type: "url-test".to_string(),
                    proxies: Vec::new(),
                    use_providers: Vec::new(),
                    url: Some("http://www.gstatic.com/generate_204".to_string()),
                    interval: Some(300),
                },
                ProxyGroupConfig {
                    name: "🎯 全球直连".to_string(),
                    group_type: "select".to_string(),
                    proxies: vec!["DIRECT".to_string()],
                    use_providers: Vec::new(),
                    url: None,
                    interval: None,
                },
            ],
            custom_nodes: Vec::new(),
            listeners: default_listeners(),
            manage_tproxy_delivery: true,
            tproxy_missing_listener: TproxyMissingListener::default(),
        }
    }
}

pub fn default_listeners() -> Vec<ProxyListenerConfig> {
    vec![
        // TProxy inbound listeners (L4 redirect from eBPF flow rules)
        ProxyListenerConfig {
            name: "flow-ai".to_string(),
            listener_type: "tproxy".to_string(),
            port: 7892,
            proxy: Some("🤖 AI服务".to_string()),
            target: None,
            network: None,
        },
        ProxyListenerConfig {
            name: "flow-stream".to_string(),
            listener_type: "tproxy".to_string(),
            port: 7893,
            proxy: Some("🎥 流媒体".to_string()),
            target: None,
            network: None,
        },
        ProxyListenerConfig {
            name: "flow-game".to_string(),
            listener_type: "tproxy".to_string(),
            port: 7894,
            proxy: Some("🎮 外服游戏".to_string()),
            target: None,
            network: None,
        },
        ProxyListenerConfig {
            name: "flow-im".to_string(),
            listener_type: "tproxy".to_string(),
            port: 7895,
            proxy: Some("💬 即时通讯".to_string()),
            target: None,
            network: None,
        },
        ProxyListenerConfig {
            name: "flow-final".to_string(),
            listener_type: "tproxy".to_string(),
            port: 7896,
            proxy: Some("🐟 漏网之鱼".to_string()),
            target: None,
            network: None,
        },
        ProxyListenerConfig {
            name: "flow-steam".to_string(),
            listener_type: "tproxy".to_string(),
            port: 7897,
            proxy: Some("🎮 Steam".to_string()),
            target: None,
            network: None,
        },
        // DNS inbound tunnels (forwarding DNS queries through specific proxy groups to avoid pollution & optimize CDN)
        ProxyListenerConfig {
            name: "dns-ai".to_string(),
            listener_type: "tunnel".to_string(),
            port: 1054,
            proxy: Some("🤖 AI服务".to_string()),
            target: Some("1.1.1.1:53".to_string()),
            network: Some(vec!["tcp".to_string(), "udp".to_string()]),
        },
        ProxyListenerConfig {
            name: "dns-stream".to_string(),
            listener_type: "tunnel".to_string(),
            port: 1055,
            proxy: Some("🎥 流媒体".to_string()),
            target: Some("1.1.1.1:53".to_string()),
            network: Some(vec!["tcp".to_string(), "udp".to_string()]),
        },
        ProxyListenerConfig {
            name: "dns-game".to_string(),
            listener_type: "tunnel".to_string(),
            port: 1056,
            proxy: Some("🎮 外服游戏".to_string()),
            target: Some("1.1.1.1:53".to_string()),
            network: Some(vec!["tcp".to_string(), "udp".to_string()]),
        },
        ProxyListenerConfig {
            name: "dns-im".to_string(),
            listener_type: "tunnel".to_string(),
            port: 1057,
            proxy: Some("💬 即时通讯".to_string()),
            target: Some("1.1.1.1:53".to_string()),
            network: Some(vec!["tcp".to_string(), "udp".to_string()]),
        },
        ProxyListenerConfig {
            name: "dns-final".to_string(),
            listener_type: "tunnel".to_string(),
            port: 1053,
            proxy: Some("🐟 漏网之鱼".to_string()),
            target: Some("1.1.1.1:53".to_string()),
            network: Some(vec!["tcp".to_string(), "udp".to_string()]),
        },
        ProxyListenerConfig {
            name: "dns-steam".to_string(),
            listener_type: "tunnel".to_string(),
            port: 1058,
            proxy: Some("🎮 Steam".to_string()),
            target: Some("1.1.1.1:53".to_string()),
            network: Some(vec!["tcp".to_string(), "udp".to_string()]),
        },
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProxyRuntimeInfo {
    pub status: ServiceStatus,
    pub pid: Option<u32>,
    pub memory_bytes: u64,
    pub cpu_percent: f32,
    pub uptime_seconds: u64,
    pub engine_version: Option<String>,
    pub tproxy_port: u16,
    pub mixed_port: u16,
    pub api_port: u16,
    pub total_nodes: usize,
    pub subscriptions_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProxyNodeItem {
    pub name: String,
    pub node_type: String,
    pub delay: Option<u64>,
    #[serde(default)]
    pub history: Vec<ProxyDelayHistory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProxyDelayHistory {
    pub time: String,
    pub delay: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProxyGroupItem {
    pub name: String,
    pub group_type: String,
    pub now: String,
    pub all: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SelectGroupProxyReq {
    pub group_name: String,
    pub proxy_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TestDelayReq {
    pub proxy_name: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ToggleProxyReq {
    pub enable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateSubscriptionReq {
    pub name: String,
    pub url: String,
}
