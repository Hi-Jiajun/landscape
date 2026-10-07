use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::service::ServiceStatus;

pub mod dataplane;

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

    /// Block the DNS paths that bypass the managed resolver.
    #[serde(default)]
    pub dns_guard: DnsGuardConfig,
}

/// How aggressively to block DNS paths that bypass the managed resolver.
///
/// Plaintext DNS is already redirected into the resolver, so this is about the
/// encrypted paths a client can choose for itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsGuardConfig {
    /// Off by default: it refuses client traffic, which is a decision to make
    /// deliberately.
    #[serde(default)]
    pub enable: bool,
    /// Which interface's clients are guarded. Matches the interface the existing
    /// DNS redirect hooks, so both cover the same clients.
    #[serde(default = "default_guard_iface")]
    pub lan_iface: String,
    /// Known DoH endpoints to refuse. Ordinary HTTPS, so only an address works;
    /// an endpoint nobody listed is a documented boundary.
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub doh_block_ips: Vec<std::net::IpAddr>,
    /// Trusted hosts allowed to keep speaking an encrypted resolver to one named
    /// destination.
    ///
    /// A destination is required rather than optional. "This host may use DoT
    /// anywhere" cannot be expressed, and that is deliberate: the exemption is
    /// an authorisation for one service on one peer, so the safe default (no
    /// exemption at all) stays the only way to say "anything".
    #[serde(default)]
    pub exempt: Vec<DnsGuardExempt>,
    /// Refuse IPv4 fragments and IPv6 packets carrying a Fragment header.
    ///
    /// A non-first fragment has no L4 header and cannot be classified, so
    /// letting it through would let a client reach the resolver the guard just
    /// refused. On by default, because the safe direction here is to refuse and
    /// count; every refusal is visible in the counters.
    #[serde(default = "default_true")]
    pub drop_fragments: bool,
    /// Refuse packets whose header chain cannot be parsed.
    ///
    /// Off by default, and this deliberately diverges from the stricter
    /// reading: on IPv6 the scanner rejects ESP/AH chains, and silently dropping
    /// those looks like a broken network rather than a policy. They are counted
    /// either way.
    #[serde(default)]
    pub drop_unclassified: bool,
}

fn default_guard_iface() -> String {
    "lan".to_string()
}

impl Default for DnsGuardConfig {
    fn default() -> Self {
        Self {
            enable: false,
            lan_iface: default_guard_iface(),
            doh_block_ips: Vec::new(),
            exempt: Vec::new(),
            drop_fragments: true,
            drop_unclassified: false,
        }
    }
}

/// Which transport a [`DnsGuardExempt`] covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum DnsGuardProtocol {
    Tcp,
    Udp,
    Both,
}

impl DnsGuardProtocol {
    /// The `iptables -p` argument list this covers.
    pub fn as_iptables_protocols(self) -> Vec<&'static str> {
        match self {
            Self::Tcp => vec!["tcp"],
            Self::Udp => vec!["udp"],
            Self::Both => vec!["tcp", "udp"],
        }
    }

    /// The IP protocol numbers this covers, for the datapath map key.
    pub fn as_l4_protocols(self) -> Vec<u8> {
        match self {
            Self::Tcp => vec![6],
            Self::Udp => vec![17],
            Self::Both => vec![6, 17],
        }
    }
}

/// One trusted host, one service, one destination.
///
/// Identity is the source address plus the service, never the flow: the flow a
/// packet lands in is chosen by its destination, so a flow or a `local_tproxy`
/// target carries no identity at all.
///
/// Matching a bare source address is not authentication - anything on the same
/// flat LAN can claim it. The trusted boundary has to come from the link (a
/// separate VLAN, switch-side source filtering); a static DHCP lease does not
/// provide it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsGuardExempt {
    /// The trusted host.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub client: std::net::IpAddr,
    /// The only peer this host may reach with this service.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub destination: std::net::IpAddr,
    pub protocol: DnsGuardProtocol,
    pub port: u16,
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

/// Kernel state of the DNS leak guard.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsGuardStatus {
    pub enabled: bool,
    /// Which interface's clients are guarded.
    pub lan_iface: String,
    /// The rules currently installed, as the tool prints them.
    #[serde(default)]
    pub rules: Vec<String>,
    /// How many DoH endpoints are blocked by address.
    #[serde(default)]
    pub doh_blocked: usize,
    /// How many hosts hold an encrypted-resolver exemption.
    #[serde(default)]
    pub exempted_hosts: usize,
    /// Datapath counters, per packet.
    #[serde(default)]
    pub counters: DnsGuardCounters,
    /// Packets refused by the refusal chain, per packet.
    ///
    /// Read from the kernel rather than remembered, so it is the counter the
    /// rules themselves kept. It is comparable with
    /// [`DnsGuardCounters::handoff_dot`] and `handoff_doh`: a handoff with no
    /// refusal is a packet that was taken away from the normal path and then
    /// ruled on by nothing.
    #[serde(default)]
    pub refused_packets: u64,
    /// Plaintext-DNS connections sent to the managed resolver.
    ///
    /// Per *connection*, not per packet, because the hijack is a NAT rule and
    /// NAT decides on the first packet of a flow. It must not be compared with
    /// the per-packet handoff counter.
    #[serde(default)]
    pub hijacked_connections: u64,
    /// Set when the datapath half could not be programmed. The rules above are
    /// the netfilter half, which may still be installed; with the datapath half
    /// missing, direct flows are not guarded at all, so this is not a detail.
    #[serde(default)]
    pub dataplane_error: Option<String>,
    pub last_error: Option<String>,
}

/// Datapath packet counters.
///
/// These are per packet, while the netfilter counters are per rule match, so the
/// two never line up one for one. What does mean something is a nonzero handoff
/// count with the matching refusal count staying at zero: the packet is being
/// handed to the stack and nothing is ruling on it.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsGuardCounters {
    /// Handed to the local stack for the resolver to answer.
    pub handoff_plaintext: u64,
    /// Handed to the local stack so the 853 rule can refuse it.
    pub handoff_dot: u64,
    /// Handed to the local stack so the DoH rule can refuse it.
    pub handoff_doh: u64,
    /// Left alone because the host holds an exemption for exactly this service.
    pub exempted: u64,
    /// Refused in the datapath because a fragment cannot be classified.
    pub fragments_refused: u64,
    /// Passed through because fragment refusal is switched off.
    pub fragments_passed: u64,
    /// Passed through because the header chain could not be parsed and refusal
    /// is switched off.
    pub unclassified_passed: u64,
    /// Ignored because the destination is on the LAN.
    pub lan_destination: u64,
}

/// Which of the four leak classes a finding belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum LeakClass {
    /// A client query can reach an unintended resolver instead of the managed one.
    Dns,
    /// IPv6 can take a different path than IPv4 for the same scope, so a v4-only
    /// guard would let v6 out directly.
    Ipv6,
    /// A proxied flow can leave through the WAN when the proxy is unavailable.
    ProxyFailure,
    /// Traffic the operator expects to be proxied can expose the home address.
    RealIp,
}

impl LeakClass {
    pub fn label(self) -> &'static str {
        match self {
            LeakClass::Dns => "dns",
            LeakClass::Ipv6 => "ipv6",
            LeakClass::ProxyFailure => "proxy_failure",
            LeakClass::RealIp => "real_ip",
        }
    }

    pub const ALL: [LeakClass; 4] =
        [LeakClass::Dns, LeakClass::Ipv6, LeakClass::ProxyFailure, LeakClass::RealIp];
}

/// How much a finding matters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum LeakSeverity {
    /// The class is covered, and this is the evidence for it.
    #[default]
    Ok,
    /// Something is off but the guard still holds (for example the proxy is down
    /// and the flow is being refused, which is the intended behaviour).
    Notice,
    /// The guard for this class is not in place as configured.
    Warn,
    /// Traffic can leave in a way the configuration says it must not.
    Leak,
}

impl LeakSeverity {
    pub fn label(self) -> &'static str {
        match self {
            LeakSeverity::Ok => "ok",
            LeakSeverity::Notice => "notice",
            LeakSeverity::Warn => "warn",
            LeakSeverity::Leak => "leak",
        }
    }
}

/// One observation about one leak class, with the evidence behind it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LeakFinding {
    pub class: LeakClass,
    pub severity: LeakSeverity,
    /// Short machine-readable name of what was checked.
    pub check: String,
    /// What was found, in the operator's terms.
    pub detail: String,
    /// The raw values the verdict came from, so it can be verified rather than
    /// taken on trust.
    #[serde(default)]
    pub evidence: Vec<String>,
}

/// One cell of the {confirmed proxy, confirmed direct, unknown} x {engine ok,
/// engine failed} matrix: what the configuration does in that state, and whether
/// that is the required behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MatrixCell {
    /// `proxy` / `direct` / `unknown`
    pub classification: String,
    /// `engine_ok` / `engine_failed`
    pub engine: String,
    /// What actually happens in this state now.
    pub behaviour: String,
    /// Whether that matches the required matrix.
    pub required: bool,
    #[serde(default)]
    pub note: Option<String>,
}

/// The whole picture: whether each leak class is covered, and whether the flow
/// matrix behaves as required.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LeakGuardReport {
    /// Highest severity across every finding, so a caller can alert on one value.
    pub worst: LeakSeverity,
    pub findings: Vec<LeakFinding>,
    pub matrix: Vec<MatrixCell>,
    /// Proxied flows whose listener is not bound, i.e. the engine is not
    /// delivering for them right now.
    #[serde(default)]
    pub flows_without_listener: Vec<u8>,
    pub engine_running: bool,
    /// The configured policy for a proxied flow whose listener is missing.
    pub missing_listener_policy: TproxyMissingListener,
}

impl LeakGuardReport {
    pub fn push(&mut self, finding: LeakFinding) {
        if finding.severity > self.worst {
            self.worst = finding.severity;
        }
        self.findings.push(finding);
    }

    /// Whether anything needs the operator's attention.
    pub fn is_healthy(&self) -> bool {
        self.worst < LeakSeverity::Warn
    }
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
            dns_guard: DnsGuardConfig::default(),
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
