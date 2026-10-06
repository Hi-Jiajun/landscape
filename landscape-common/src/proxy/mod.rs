use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::service::ServiceStatus;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum ProxyEngine {
    Mihomo,
    MeowRs,
    Custom,
}

impl Default for ProxyEngine {
    fn default() -> Self {
        Self::Mihomo
    }
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
                    proxies: vec!["🎯 全球直连".to_string()],
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

