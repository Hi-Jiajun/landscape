//! Tests for the static checks.

use std::collections::HashMap;

use crate::config_service::geo::GeoConfigKey;
use crate::dns::rule::{DNSRuleConfig, DomainConfig, DomainMatchType, FilterResult, RuleSource};
use crate::flow::mark::{FlowMark, FlowMarkAction};
use crate::utils::id::gen_database_uuid;

use super::{AuditInput, AuditLimits, FindingKind, audit};
use crate::audit::{AuditReport, Confidence};

/// A rule that matches `sources` and routes the way `action` says.
fn rule(
    index: u32,
    sources: Vec<RuleSource>,
    action: FlowMarkAction,
    flow_id: u8,
) -> DNSRuleConfig {
    DNSRuleConfig {
        id: gen_database_uuid(),
        name: format!("rule {index}"),
        index,
        enable: true,
        filter: FilterResult::default(),
        upstream_id: gen_database_uuid(),
        mark: FlowMark::new(action, flow_id, false),
        source: sources,
        flow_id: 0,
        update_at: 0.0,
    }
}

fn domain(value: &str) -> RuleSource {
    RuleSource::Config(DomainConfig {
        match_type: DomainMatchType::Full,
        value: value.to_string(),
    })
}

fn geokey(key: &str) -> RuleSource {
    RuleSource::GeoKey(GeoConfigKey {
        name: "geosite".into(),
        key: key.into(),
        inverse: false,
        attribute_key: None,
    })
}

/// Audit with no runtime statistics, which is what a fresh install has.
fn run(rules: Vec<DNSRuleConfig>) -> AuditReport {
    audit(AuditInput {
        rules: &rules,
        hits: HashMap::new(),
        observed_secs: None,
        hits_available: false,
        limits: AuditLimits::default(),
    })
}

/// Audit with a specific observation window and hit counts.
fn run_with_hits(
    rules: Vec<DNSRuleConfig>,
    hits: HashMap<u32, u64>,
    observed_secs: u64,
) -> AuditReport {
    audit(AuditInput {
        rules: &rules,
        hits,
        observed_secs: Some(observed_secs),
        hits_available: true,
        limits: AuditLimits::default(),
    })
}

#[test]
fn a_clean_configuration_reports_nothing() {
    let report = run(vec![
        rule(10, vec![domain("a.example")], FlowMarkAction::Redirect, 5),
        rule(20, vec![domain("b.example")], FlowMarkAction::Direct, 0),
    ]);
    assert!(!report.has_findings(), "{:#?}", report.findings);
    assert_eq!(report.worst, None);
}

#[test]
fn an_identical_rule_is_a_certain_duplicate() {
    let report = run(vec![
        rule(10, vec![domain("a.example")], FlowMarkAction::Redirect, 5),
        rule(20, vec![domain("a.example")], FlowMarkAction::Redirect, 5),
    ]);
    assert_eq!(report.count_of(FindingKind::Duplicate), 1);
    let found = report.findings.iter().find(|f| f.kind == FindingKind::Duplicate).unwrap();
    assert_eq!(found.confidence, Confidence::Certain);
    assert!(!found.evidence.is_empty(), "a finding must show its evidence");
    assert!(found.requires_confirmation, "phase 1 never applies a change");
    // Removing a rule that cannot match cannot widen access.
    assert!(!found.suggestion.as_ref().unwrap().widens_direct_access);
}

#[test]
fn the_same_domains_with_a_different_action_are_not_a_duplicate() {
    let report = run(vec![
        rule(10, vec![domain("a.example")], FlowMarkAction::Redirect, 5),
        rule(20, vec![domain("a.example")], FlowMarkAction::Direct, 0),
    ]);
    assert_eq!(report.count_of(FindingKind::Duplicate), 0);
}

#[test]
fn a_catch_all_before_a_rule_shadows_it_and_is_marked_as_widening_access() {
    // The case that matters: fixing the order makes the later rule take effect,
    // which can move traffic somewhere new, so the suggestion says so and demands
    // confirmation.
    let report = run(vec![
        rule(10, vec![], FlowMarkAction::Direct, 0),
        rule(20, vec![domain("ai.example")], FlowMarkAction::Redirect, 5),
    ]);
    let found = report
        .findings
        .iter()
        .find(|f| f.kind == FindingKind::Shadowed)
        .expect("the shadowed rule must be reported");
    assert_eq!(found.confidence, Confidence::Certain);
    assert!(
        found.suggestion.as_ref().unwrap().widens_direct_access,
        "making the later rule take effect can send traffic somewhere new"
    );
    assert!(found.requires_confirmation);
}

#[test]
fn a_low_indexed_catch_all_is_reported_as_a_catch_all_too_early() {
    let report = run(vec![
        rule(10, vec![], FlowMarkAction::Redirect, 14),
        rule(20, vec![domain("a.example")], FlowMarkAction::Direct, 0),
    ]);
    assert_eq!(report.count_of(FindingKind::CatchAllTooEarly), 1);
}

#[test]
fn a_last_indexed_catch_all_is_reported_as_such_rather_than_as_an_error() {
    let report = run(vec![
        rule(10, vec![domain("a.example")], FlowMarkAction::Direct, 0),
        rule(1000, vec![], FlowMarkAction::Redirect, 14),
    ]);
    assert_eq!(report.count_of(FindingKind::CatchAllTooEarly), 0);
    assert_eq!(report.count_of(FindingKind::ActionMismatch), 1);
    let found = report.findings.iter().find(|f| f.kind == FindingKind::ActionMismatch).unwrap();
    assert!(found.detail.contains("deliberate catch-all"));
}

#[test]
fn a_catch_all_that_only_defers_is_left_alone() {
    // The seeded rule is exactly this shape; it is not a finding.
    let report = run(vec![rule(10000, vec![], FlowMarkAction::KeepGoing, 0)]);
    assert!(!report.has_findings(), "{:#?}", report.findings);
}

#[test]
fn a_redirect_without_a_target_is_reported() {
    // Redirect to flow 0 is not a proxy tier in the datapath.
    let report = run(vec![rule(80, vec![domain("x.example")], FlowMarkAction::Redirect, 0)]);
    let found = report
        .findings
        .iter()
        .find(|f| f.kind == FindingKind::ActionMismatch)
        .expect("redirect to the default flow behaves like direct");
    assert_eq!(found.confidence, Confidence::Likely);
    assert!(!found.suggestion.as_ref().unwrap().widens_direct_access);
}

#[test]
fn rule_bloat_is_reported_above_the_limit() {
    let rules: Vec<DNSRuleConfig> = (0..30)
        .map(|i| rule(i, vec![domain(&format!("d{i}.example"))], FlowMarkAction::Direct, 0))
        .collect();
    let report = audit(AuditInput {
        rules: &rules,
        hits: HashMap::new(),
        observed_secs: None,
        hits_available: false,
        limits: AuditLimits { max_rules: 10, max_per_kind: 20 },
    });
    assert_eq!(report.count_of(FindingKind::RuleBloat), 1);
}

#[test]
fn geo_keys_are_not_treated_as_matching_everything() {
    // A geo key's members are not in the configuration, so containment cannot be
    // decided; calling it a catch-all would produce a false shadowing finding for
    // every rule after it.
    let report = run(vec![
        rule(10, vec![geokey("GEOLOCATION-!CN")], FlowMarkAction::Redirect, 14),
        rule(20, vec![domain("ai.example")], FlowMarkAction::Redirect, 5),
    ]);
    assert_eq!(report.count_of(FindingKind::Shadowed), 0);
    assert_eq!(report.count_of(FindingKind::CatchAllTooEarly), 0);
}

#[test]
fn the_never_matched_check_stays_off_without_statistics() {
    let report = run(vec![rule(10, vec![domain("a.example")], FlowMarkAction::Direct, 0)]);
    assert_eq!(report.count_of(FindingKind::NeverMatched), 0);
    assert!(
        report.checked.iter().any(|line| line.contains("unavailable")),
        "the report must say the check did not run: {:?}",
        report.checked
    );
}

#[test]
fn a_short_observation_window_does_not_claim_a_rule_is_unused() {
    let report = run_with_hits(
        vec![rule(10, vec![domain("a.example")], FlowMarkAction::Direct, 0)],
        HashMap::new(),
        600,
    );
    assert_eq!(report.count_of(FindingKind::NeverMatched), 0);
    assert!(report.checked.iter().any(|line| line.contains("shorter than")));
}

#[test]
fn a_long_enough_window_reports_an_unused_rule_as_suspicious_only() {
    let report = run_with_hits(
        vec![rule(10, vec![domain("a.example")], FlowMarkAction::Direct, 0)],
        HashMap::new(),
        48 * 3600,
    );
    assert_eq!(report.count_of(FindingKind::NeverMatched), 1);
    let found = report.findings.iter().find(|f| f.kind == FindingKind::NeverMatched).unwrap();
    assert_eq!(found.confidence, Confidence::Suspicious);
    // Never deleted automatically, and not even called likely: an unused domain
    // looks exactly the same as an unused rule.
    assert!(found.suggestion.is_none());
    assert!(found.evidence.iter().any(|e| e.contains("never removed")));
}

#[test]
fn a_matched_rule_is_not_reported_as_unused() {
    let report = run_with_hits(
        vec![rule(10, vec![domain("a.example")], FlowMarkAction::Direct, 0)],
        HashMap::from([(10, 5)]),
        48 * 3600,
    );
    assert_eq!(report.count_of(FindingKind::NeverMatched), 0);
}

#[test]
fn a_disabled_rule_is_not_audited() {
    let mut disabled = rule(10, vec![], FlowMarkAction::Direct, 0);
    disabled.enable = false;
    let report = run(vec![disabled]);
    assert!(!report.has_findings(), "{:#?}", report.findings);
}

#[test]
fn every_finding_carries_evidence_and_demands_confirmation() {
    let report = run(vec![
        rule(10, vec![], FlowMarkAction::Direct, 0),
        rule(20, vec![domain("a.example")], FlowMarkAction::Redirect, 0),
        rule(30, vec![domain("a.example")], FlowMarkAction::Redirect, 0),
    ]);
    assert!(report.has_findings());
    for found in &report.findings {
        assert!(!found.evidence.is_empty(), "{} has no evidence", found.kind.label());
        assert!(!found.detail.is_empty());
        assert!(found.requires_confirmation, "phase 1 must not apply anything");
        if let Some(suggestion) = &found.suggestion {
            assert!(!suggestion.verify.is_empty(), "a suggestion must say how to check it");
            assert!(!suggestion.rollback.is_empty(), "and how to undo it");
            assert!(!suggestion.effect.is_empty());
        }
    }
}
