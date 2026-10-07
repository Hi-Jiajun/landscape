use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::dns::bind::DnsBindConfig;
use crate::dns::upstream::DnsUpstreamMode;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsUpstreamConfig {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,

    pub name: Option<String>,

    pub remark: String,

    pub mode: DnsUpstreamMode,

    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub ips: Vec<IpAddr>,

    /// Addresses of a second resolver to use when this one cannot be reached.
    ///
    /// The architecture pairs a domestic ISP resolver (in `ips`) with a public
    /// one here, so a rule that binds this upstream inherits the pairing rather
    /// than each rule having to name two upstreams. Empty means no failover, which
    /// is the previous behaviour.
    ///
    /// The backup is used **only** when the primary produced no answer at all: a
    /// NODATA or a legitimate NXDOMAIN is the primary's answer, not a reason to
    /// ask someone else.
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub backup_ips: Vec<IpAddr>,

    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub port: Option<u16>,

    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub enable_ip_validation: Option<bool>,

    /// Opt in to the experimental upstream connection pool (default: false).
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = true))]
    pub use_experimental_pool: Option<bool>,

    /// Source-address binding for connections to this upstream (optional).
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub bind_config: DnsBindConfig,

    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeDBStore<Uuid> for DnsUpstreamConfig {
    fn get_id(&self) -> Uuid {
        self.id
    }
    fn get_update_at(&self) -> f64 {
        self.update_at
    }
    fn set_update_at(&mut self, ts: f64) {
        self.update_at = ts;
    }
}

impl Default for DnsUpstreamConfig {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: None,
            remark: "Landscape Router Default DNS Upstream".to_string(),
            mode: DnsUpstreamMode::Plaintext,
            ips: vec![IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1))],
            backup_ips: Vec::new(),
            enable_ip_validation: None,
            use_experimental_pool: None,
            port: Some(53),
            bind_config: DnsBindConfig::default(),
            update_at: get_f64_timestamp(),
        }
    }
}

impl DnsUpstreamConfig {
    /// Whether this upstream has no address to query, i.e. it is the placeholder
    /// a fresh install is seeded with rather than a usable resolver.
    ///
    /// Every mode builds its nameservers from `ips`, so an empty list cannot
    /// resolve anything. Treating it as "not configured" keeps a config omission
    /// from silently becoming a public-resolver fallback: the rule builder refuses
    /// such a rule and says which one it is.
    pub fn is_placeholder(&self) -> bool {
        self.ips.is_empty()
    }
}

crate::impl_trivial_validatable!(DnsUpstreamConfig);
