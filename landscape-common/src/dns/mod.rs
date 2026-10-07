use crate::dns::config::DnsUpstreamConfig;
use crate::dns::rule::{DNSRuleConfig, FilterResult, default_flow_id};
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

pub mod api;
pub mod bind;
pub mod check;
pub mod config;
pub mod dnr;
pub mod domain;
pub mod error;
pub mod provider_profile;
pub mod redirect;
pub mod rule;
pub mod runtime;
pub mod upstream;

pub use runtime::{CacheRuntimeConfig, DohRuntimeConfig, FlowDnsDependencies};

pub fn gen_default_dns_rule_and_upstream() -> (DNSRuleConfig, DnsUpstreamConfig) {
    // The seed exists so a fresh install has a rule to edit, not so that DNS
    // works before anything is configured. It is marked as a placeholder and
    // carries no upstream addresses, so the rule builder refuses it and the
    // operator is told to pick a resolver instead of having every query
    // silently forwarded to a public one.
    let mut upstream = DnsUpstreamConfig::default();
    upstream.ips.clear();
    upstream.remark = "Unconfigured placeholder: set a real DNS upstream for this rule".to_string();
    let rule = DNSRuleConfig {
        id: gen_database_uuid(),
        name: "Landscape Router default rule".into(),
        index: 10000,
        enable: true,
        filter: FilterResult::default(),
        mark: Default::default(),
        source: vec![],
        flow_id: default_flow_id(),
        update_at: get_f64_timestamp(),
        upstream_id: upstream.id,
    };
    (rule, upstream)
}
