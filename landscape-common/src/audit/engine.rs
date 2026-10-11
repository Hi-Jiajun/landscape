//! The checks themselves.
//!
//! Everything here is decidable from the configuration alone, or from the
//! configuration plus a match count. Nothing infers an intent: a rule that cannot
//! match is reported because an earlier rule's match set provably contains it,
//! not because the traffic "looks wrong".

use std::collections::HashMap;

use crate::dns::rule::{DNSRuleConfig, DomainMatchType, RuleSource};
use crate::flow::mark::FlowMarkAction;

use super::{AuditLimits, AuditReport, Confidence, Finding, FindingKind, Suggestion};

/// What the caller knows that the configuration alone does not.
pub struct AuditInput<'a> {
    pub rules: &'a [DNSRuleConfig],
    /// How many times each rule's index matched, from the runtime statistics.
    pub hits: HashMap<u32, u64>,
    /// What those statistics cover, for the report to state.
    pub observed_secs: Option<u64>,
    /// Whether the statistics are available at all. When they are not, the
    /// "never matched" check is skipped rather than reporting every rule as
    /// unused.
    pub hits_available: bool,
    pub limits: AuditLimits,
}

/// Shortest observation for "this rule never matched" to mean anything.
const MIN_OBSERVATION_SECS: u64 = 24 * 3600;

/// Run every check and collect the findings.
pub fn audit(input: AuditInput<'_>) -> AuditReport {
    let mut report = AuditReport {
        phase: "static checks and runtime statistics; no inference, no automatic changes".into(),
        checked: vec![
            format!("{} DNS rule(s)", input.rules.len()),
            if input.hits_available {
                format!("match counts over {}s", input.observed_secs.unwrap_or(0))
            } else {
                "match counts: unavailable (the never-matched check is off)".to_string()
            },
        ],
        ..Default::default()
    };

    check_bloat(&input, &mut report);
    check_catch_all_and_empty_source(&input, &mut report);
    check_duplicates(&input, &mut report);
    check_shadowing(&input, &mut report);
    check_redirect_without_target(&input, &mut report);
    check_never_matched(&input, &mut report);

    report
}

/// A rule reduced to what the checks compare.
struct RuleView {
    index: u32,
    name: String,
    action: FlowMarkAction,
    /// `None` when a source is a geo key: its members live in the geo files, so
    /// containment cannot be decided here without guessing.
    domains: Option<Vec<(DomainMatchType, String)>>,
}

impl RuleView {
    fn label(&self) -> String {
        format!("{}: {}", self.index, self.name)
    }
}

fn view(rule: &DNSRuleConfig) -> RuleView {
    let mut domains = Vec::new();
    let mut only_manual = true;
    for source in &rule.source {
        match source {
            RuleSource::Config(config) => {
                domains.push((config.match_type.clone(), config.value.clone()));
            }
            RuleSource::GeoKey(_) => only_manual = false,
        }
    }
    // An empty source matches everything, which is a property of the rule rather
    // than an unknown set; it has to stay distinguishable from "cannot decide".
    let domains = if rule.source.is_empty() {
        Some(Vec::new())
    } else if only_manual {
        Some(domains)
    } else {
        None
    };

    RuleView {
        index: rule.index,
        name: rule.name.clone(),
        action: rule.mark.action(),
        domains,
    }
}

/// Rule counts that have outgrown what a person can maintain.
fn check_bloat(input: &AuditInput<'_>, report: &mut AuditReport) {
    let enabled = input.rules.iter().filter(|rule| rule.enable).count();
    if enabled <= input.limits.max_rules {
        return;
    }
    report.push(
        Finding {
            kind: FindingKind::RuleBloat,
            confidence: Confidence::Certain,
            subject: format!("{enabled} enabled rules"),
            detail: format!(
                "There are {enabled} enabled DNS rules, above the {} this check treats as \
                 maintainable. Large rule sets drift: duplicates and shadowed rules accumulate \
                 unnoticed, and every new rule has to be checked against all the others.",
                input.limits.max_rules
            ),
            evidence: vec![
                format!("enabled rules: {enabled}"),
                format!("threshold: {}", input.limits.max_rules),
            ],
            suggestion: Some(Suggestion {
                action: "Merge rules that share a destination and an action, and remove the ones \
                         reported as duplicate or shadowed."
                    .into(),
                effect: "Fewer rules to reason about, and fewer chances for a later rule to be \
                         hidden by an earlier one."
                    .into(),
                widens_direct_access: false,
                verify: "Re-run this check; the enabled rule count should fall, with no new \
                         findings of type shadowed or duplicate."
                    .into(),
                rollback: "`rescue snapshot` before editing and `rescue rollback` to return."
                    .into(),
            }),
            requires_confirmation: true,
        },
        &input.limits,
    );
}

/// A catch-all, and where it sits.
fn check_catch_all_and_empty_source(input: &AuditInput<'_>, report: &mut AuditReport) {
    let enabled: Vec<&DNSRuleConfig> = input.rules.iter().filter(|rule| rule.enable).collect();
    let highest = enabled.iter().map(|rule| rule.index).max();

    for rule in enabled {
        if !rule.source.is_empty() {
            continue;
        }
        // A catch-all that only defers to the flow's own policy is the seeded
        // shape and does nothing by itself.
        if rule.mark.action() == FlowMarkAction::KeepGoing {
            continue;
        }
        let is_last = Some(rule.index) == highest;
        // One suggestion per source, worded for where the rule actually is.
        let action = if is_last {
            format!(
                "This is the last rule, so the catch-all is where it belongs. Keep it only if \
                 every domain the rules above did not claim should be handled by flow {}.",
                rule.mark.flow_id()
            )
        } else {
            format!(
                "Move this rule after index {}, or give it the domains it is meant to match.",
                highest.unwrap_or(rule.index)
            )
        };
        report.push(
            Finding {
                kind: if is_last {
                    FindingKind::ActionMismatch
                } else {
                    FindingKind::CatchAllTooEarly
                },
                confidence: Confidence::Certain,
                subject: view(rule).label(),
                detail: format!(
                    "This rule has no match source, so it matches every domain, and its action is \
                     `{:?}`. {}",
                    rule.mark.action(),
                    if is_last {
                        "As the last rule that is a deliberate catch-all."
                    } else {
                        "Because it is not the last rule, every rule after it can never match."
                    }
                ),
                evidence: vec![
                    format!("action: {:?}", rule.mark.action()),
                    "source: empty (matches everything)".into(),
                    format!("index: {}, highest index: {highest:?}", rule.index),
                ],
                suggestion: Some(Suggestion {
                    action,
                    effect: "A catch-all before other rules hides them; moving it last makes the \
                             ordering express what is meant, and the rules after it start \
                             working."
                        .into(),
                    widens_direct_access: true,
                    verify: "Query a domain a previously shadowed rule matches and check which \
                             rule the DNS check reports."
                        .into(),
                    rollback: "`rescue snapshot` before editing and `rescue rollback` after."
                        .into(),
                }),
                requires_confirmation: true,
            },
            &input.limits,
        );
    }
}

/// Two rules with the same effect.
fn check_duplicates(input: &AuditInput<'_>, report: &mut AuditReport) {
    let views: Vec<RuleView> = input.rules.iter().filter(|rule| rule.enable).map(view).collect();
    for (position, rule) in views.iter().enumerate() {
        let Some(domains) = &rule.domains else { continue };
        for other in views.iter().skip(position + 1) {
            let Some(other_domains) = &other.domains else { continue };
            if domains != other_domains || rule.action != other.action {
                continue;
            }
            report.push(
                Finding {
                    kind: FindingKind::Duplicate,
                    confidence: Confidence::Certain,
                    subject: other.label(),
                    detail: format!(
                        "This rule matches the same domains and does the same thing as {}, so \
                         whichever comes second can never take effect.",
                        rule.label()
                    ),
                    evidence: vec![
                        format!("{}: {domains:?}", rule.label()),
                        format!("{}: {other_domains:?}", other.label()),
                        format!("both actions: {:?}", rule.action),
                    ],
                    suggestion: Some(Suggestion {
                        action: format!("Delete {} and keep {}.", other.label(), rule.label()),
                        effect: "One rule fewer, with no change in behaviour: the second rule \
                                 could never match anyway."
                            .into(),
                        // Removing a rule that cannot match cannot widen anything.
                        widens_direct_access: false,
                        verify: "Re-run the check; the duplicate finding should be gone and the \
                                 routing unchanged."
                            .into(),
                        rollback: "`rescue snapshot` before deleting and `rescue rollback` after."
                            .into(),
                    }),
                    requires_confirmation: true,
                },
                &input.limits,
            );
        }
    }
}

/// A rule an earlier catch-all always claims first.
fn check_shadowing(input: &AuditInput<'_>, report: &mut AuditReport) {
    let mut ordered: Vec<RuleView> =
        input.rules.iter().filter(|rule| rule.enable).map(view).collect();
    ordered.sort_by_key(|rule| rule.index);

    for (position, later) in ordered.iter().enumerate() {
        let Some(later_domains) = &later.domains else { continue };
        if later_domains.is_empty() {
            continue;
        }
        for earlier in ordered.iter().take(position) {
            let catch_all = earlier.domains.as_ref().is_some_and(|set| set.is_empty());
            // A catch-all with the same action has the same effect anyway, which
            // the duplicate check reports when the sources match.
            if !catch_all || earlier.action == later.action {
                continue;
            }
            report.push(
                Finding {
                    kind: FindingKind::Shadowed,
                    confidence: Confidence::Certain,
                    subject: later.label(),
                    detail: format!(
                        "{} (index {}) matches every domain and comes first, so this rule can \
                         never take effect.",
                        earlier.label(),
                        earlier.index
                    ),
                    evidence: vec![
                        format!("{}: source is empty (matches all)", earlier.label()),
                        format!("{}: {later_domains:?}", later.label()),
                        format!("indexes: {} before {}", earlier.index, later.index),
                    ],
                    suggestion: Some(Suggestion {
                        action: format!(
                            "Move the catch-all ({}) after index {}, or give it the domains it is \
                             meant to match.",
                            earlier.label(),
                            later.index
                        ),
                        effect: "The rules after the catch-all start working, which changes \
                                 routing for their domains. Make sure that is what they are for \
                                 before applying."
                            .into(),
                        // Making a rule take effect can move traffic out of a
                        // proxy tier or into one.
                        widens_direct_access: true,
                        verify: "Query a domain the shadowed rule matches and check which rule \
                                 the DNS check reports."
                            .into(),
                        rollback: "`rescue snapshot` before editing and `rescue rollback` after."
                            .into(),
                    }),
                    requires_confirmation: true,
                },
                &input.limits,
            );
        }
    }
}

/// A redirect that names no target flow behaves like a direct rule, not like a
/// proxy tier.
fn check_redirect_without_target(input: &AuditInput<'_>, report: &mut AuditReport) {
    for rule in input.rules.iter().filter(|rule| rule.enable) {
        if rule.mark.action() != FlowMarkAction::Redirect || rule.mark.flow_id() != 0 {
            continue;
        }
        report.push(
            Finding {
                kind: FindingKind::ActionMismatch,
                confidence: Confidence::Likely,
                subject: view(rule).label(),
                detail: "This rule's action is `redirect` but names no target flow, so the \
                         datapath resolves it to the default flow: it behaves like `direct`, not \
                         like a proxy tier."
                    .into(),
                evidence: vec![
                    "action: redirect".into(),
                    "target flow: 0 (the default flow, which is not a proxy tier)".into(),
                ],
                suggestion: Some(Suggestion {
                    action: "Give the rule the proxy flow it is meant to use, or change its \
                             action to `direct` so the intent is explicit."
                        .into(),
                    effect: "Makes the rule say what it does. Naming a proxy flow here would send \
                             traffic through a proxy it currently bypasses."
                        .into(),
                    widens_direct_access: false,
                    verify: "The DNS check for a domain this rule matches should report the \
                             intended flow."
                        .into(),
                    rollback: "`rescue snapshot` and `rescue rollback`.".into(),
                }),
                requires_confirmation: true,
            },
            &input.limits,
        );
    }
}

/// A rule that never matched. Reported only when the statistics can support it.
fn check_never_matched(input: &AuditInput<'_>, report: &mut AuditReport) {
    if !input.hits_available {
        return;
    }
    let observed = input.observed_secs.unwrap_or(0);
    if observed < MIN_OBSERVATION_SECS {
        report.checked.push(format!(
            "never-matched check skipped: {observed}s of statistics is shorter than the \
             {MIN_OBSERVATION_SECS}s needed before absence of matches means anything"
        ));
        return;
    }

    for rule in input.rules.iter().filter(|rule| rule.enable) {
        if input.hits.get(&rule.index).copied().unwrap_or(0) > 0 {
            continue;
        }
        report.push(
            Finding {
                kind: FindingKind::NeverMatched,
                // Not certain: a domain that is simply not used looks exactly the
                // same as a rule that never matches.
                confidence: Confidence::Suspicious,
                subject: view(rule).label(),
                detail: format!(
                    "This rule matched nothing in the {observed}s of statistics available. That \
                     can be normal, so this is a prompt to look rather than a reason to delete \
                     anything."
                ),
                evidence: vec![
                    format!("hits for index {}: 0", rule.index),
                    format!("observation window: {observed}s"),
                    "an explicit security rule is never removed because it is unused".into(),
                ],
                suggestion: None,
                requires_confirmation: true,
            },
            &input.limits,
        );
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
