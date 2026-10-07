//! The match counters the configuration audit reads.

use std::collections::BTreeMap;

use landscape_common::dns::config::DnsUpstreamConfig;
use landscape_common::dns::rule::{DomainConfig, DomainMatchType, FilterResult};
use landscape_common::flow::mark::{FlowMark, FlowMarkAction};

use crate::connection::pool::ResolvePool;
use crate::domain::ParsedDomain;
use crate::server::matcher::RuntimeRuleMatcher;
use crate::server::resolve_engine::ResolveEngine;
use crate::server::rule::{DNSResolveRuntime, ResolveRuleParams};

fn pd(name: &str) -> ParsedDomain {
    ParsedDomain::new(name).unwrap()
}

fn rule(index: u32, domain: &str) -> DNSResolveRuntime {
    let matcher = RuntimeRuleMatcher::new(
        vec![DomainConfig {
            match_type: DomainMatchType::Full,
            value: domain.to_string(),
        }],
        vec![],
        vec![],
        false,
    );
    DNSResolveRuntime::new(ResolveRuleParams {
        rule_id: uuid::Uuid::new_v4(),
        order: index,
        filter: FilterResult::default(),
        mark: FlowMark::new(FlowMarkAction::Direct, 0, false),
        upstream: DnsUpstreamConfig::default(),
        matcher,
        flow_id: 0,
        pool: std::sync::Arc::new(ResolvePool::default()),
    })
    .expect("a plaintext upstream builds a resolver")
}

#[test]
fn matching_a_rule_counts_once_per_query() {
    let engine = ResolveEngine::new(BTreeMap::from([(10, rule(10, "a.example"))]));

    // Nothing has matched yet, which is what the audit sees on a fresh start.
    assert_eq!(engine.match_counts().get(&10).copied(), Some(0));

    assert!(engine.find_match(&pd("a.example")).is_some());
    assert!(engine.find_match(&pd("a.example")).is_some());
    // A domain no rule matches must not increment anything.
    assert!(engine.find_match(&pd("other.example")).is_none());

    assert_eq!(
        engine.match_counts().get(&10).copied(),
        Some(2),
        "the audit's never-matched check depends on this count being real"
    );
}

#[test]
fn every_rule_gets_a_counter_even_before_it_matches() {
    // Without an entry for each rule the audit could not tell "never matched"
    // from "not counted".
    let engine = ResolveEngine::new(BTreeMap::from([
        (10, rule(10, "a.example")),
        (20, rule(20, "b.example")),
    ]));
    let counts = engine.match_counts();
    assert_eq!(counts.len(), 2);
    assert!(counts.values().all(|count| *count == 0));
}

#[test]
fn the_counters_are_not_reset_by_reading_them() {
    let engine = ResolveEngine::new(BTreeMap::from([(10, rule(10, "a.example"))]));
    engine.find_match(&pd("a.example"));
    let first = engine.match_counts();
    let second = engine.match_counts();
    assert_eq!(first, second, "reading the statistics must not clear them");
    assert_eq!(first.get(&10).copied(), Some(1));
}
