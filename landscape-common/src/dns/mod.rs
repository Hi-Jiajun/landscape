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
    // works before anything is configured: it ships **disabled** and carries no
    // upstream address.
    //
    // Both halves matter. No address means nothing to query, so the rule cannot
    // quietly become a public-resolver fallback. Disabled means it does not take
    // part in resolution at all — an enabled rule with an empty source matches
    // every domain, so shipping one would answer (or refuse) the whole internet
    // for an install that has not been configured yet.
    let mut upstream = DnsUpstreamConfig::default();
    upstream.ips.clear();
    upstream.remark = "Unconfigured placeholder: set a real DNS upstream for this rule".to_string();
    let rule = DNSRuleConfig {
        id: gen_database_uuid(),
        name: "Landscape Router default rule".into(),
        index: 10000,
        enable: false,
        filter: FilterResult::default(),
        mark: Default::default(),
        source: vec![],
        flow_id: default_flow_id(),
        update_at: get_f64_timestamp(),
        upstream_id: upstream.id,
    };
    (rule, upstream)
}
