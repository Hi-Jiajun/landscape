//! Static configuration checks and explainable suggestions.
//!
//! First phase of the self-improving loop, and deliberately only that much: this
//! reads the configuration and the runtime statistics, reports what looks wrong
//! with the evidence it used, and says what could be changed. It never changes a
//! rule. Anything that would widen direct access is called out as requiring a
//! human decision, because "the tool decided" is not an acceptable reason for
//! traffic to start leaving unproxied.
//!
//! Findings carry a confidence grade rather than a percentage: the grade says how
//! much the evidence actually supports acting, and an uncalibrated "97% sure"
//! would be worse than useless when the cost of being wrong is a leak.

mod engine;

pub use engine::{AuditInput, audit};

use serde::{Deserialize, Serialize};

/// How strongly the evidence supports acting on a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum Confidence {
    /// Nothing can be concluded: one sample, or the explanation is ambiguous.
    /// Recorded so a pattern can be seen later, never a reason to change a rule.
    Undecidable,
    /// Something recurred but a normal explanation is still plausible. Worth a
    /// closer look, not a change.
    Suspicious,
    /// Several independent signals agree and the usual innocent explanations have
    /// been ruled out. A precise suggestion is worth making.
    Likely,
    /// A reproducible violation of a stated intent — a rule that can never match,
    /// a duplicate, a value that contradicts its own configuration. The finding
    /// itself is certain; whether the rule *should* change may still be a
    /// question.
    Certain,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Undecidable => "C0",
            Confidence::Suspicious => "C1",
            Confidence::Likely => "C2",
            Confidence::Certain => "C3",
        }
    }
}

/// What kind of problem a finding describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum FindingKind {
    /// A rule can never match because an earlier one already matches everything
    /// it would.
    Shadowed,
    /// Two rules match the same set with different routing.
    Overlapping,
    /// Two rules are identical in effect.
    Duplicate,
    /// A catch-all sits where it hides the rules after it.
    CatchAllTooEarly,
    /// A rule's action cannot achieve what its own source implies.
    ActionMismatch,
    /// A rule never matched within the observation window.
    NeverMatched,
    /// The number of rules is growing without bound.
    RuleBloat,
}

impl FindingKind {
    pub fn label(self) -> &'static str {
        match self {
            FindingKind::Shadowed => "shadowed",
            FindingKind::Overlapping => "overlapping",
            FindingKind::Duplicate => "duplicate",
            FindingKind::CatchAllTooEarly => "catch_all_too_early",
            FindingKind::ActionMismatch => "action_mismatch",
            FindingKind::NeverMatched => "never_matched",
            FindingKind::RuleBloat => "rule_bloat",
        }
    }
}

/// One thing the check found, with everything needed to judge it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Finding {
    pub kind: FindingKind,
    pub confidence: Confidence,
    /// Which rule, as `index: name`, so the operator can find it.
    pub subject: String,
    /// What is wrong, in the operator's terms.
    pub detail: String,
    /// The values the verdict came from.
    #[serde(default)]
    pub evidence: Vec<String>,
    /// What could be done, when there is something concrete to do.
    #[serde(default)]
    pub suggestion: Option<Suggestion>,
    /// Always true when the change would widen direct access, and true for every
    /// change in this phase — the field exists so a later phase cannot quietly
    /// start applying the safe-looking ones.
    pub requires_confirmation: bool,
}

/// A concrete change the operator could make.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Suggestion {
    /// What to do, as a sentence.
    pub action: String,
    /// What would get better, and at what cost.
    pub effect: String,
    /// Whether acting would let traffic leave unproxied that does not today.
    pub widens_direct_access: bool,
    /// How to check that the change did what was intended.
    pub verify: String,
    /// What to do if it turns out to be wrong.
    pub rollback: String,
}

/// Limits that keep the loop from growing without bound.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuditLimits {
    /// Rules above this count are reported as bloat.
    pub max_rules: usize,
    /// How many findings of one kind are listed before the rest are counted only.
    pub max_per_kind: usize,
}

impl Default for AuditLimits {
    fn default() -> Self {
        Self { max_rules: 200, max_per_kind: 20 }
    }
}

/// What the audit concluded.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuditReport {
    /// The highest confidence among the findings, so a caller can alert on one
    /// value.
    pub worst: Option<Confidence>,
    pub findings: Vec<Finding>,
    /// Findings that were counted but not listed, per kind, so the totals stay
    /// honest without the report growing with the configuration.
    #[serde(default)]
    pub summarised: Vec<(String, usize)>,
    /// What was inspected, so "no findings" is not mistaken for "not checked".
    pub checked: Vec<String>,
    /// The phase this ran in: only static checks and statistics, no inference.
    pub phase: String,
}

impl AuditReport {
    /// Record a finding, subject to the per-kind cap.
    pub fn push(&mut self, finding: Finding, limits: &AuditLimits) {
        if self.worst.is_none_or(|worst| finding.confidence > worst) {
            self.worst = Some(finding.confidence);
        }
        let seen = self.findings.iter().filter(|f| f.kind == finding.kind).count();
        if seen >= limits.max_per_kind {
            let label = finding.kind.label().to_string();
            match self.summarised.iter_mut().find(|(kind, _)| *kind == label) {
                Some((_, count)) => *count += 1,
                None => self.summarised.push((label, 1)),
            }
            return;
        }
        self.findings.push(finding);
    }

    /// Whether anything is worth the operator's attention.
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty() || !self.summarised.is_empty()
    }

    pub fn count_of(&self, kind: FindingKind) -> usize {
        self.findings.iter().filter(|finding| finding.kind == kind).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(kind: FindingKind, confidence: Confidence) -> Finding {
        Finding {
            kind,
            confidence,
            subject: "10: a".into(),
            detail: "d".into(),
            evidence: vec!["e".into()],
            suggestion: None,
            requires_confirmation: true,
        }
    }

    #[test]
    fn confidence_is_ordered_so_the_worst_is_comparable() {
        assert!(Confidence::Undecidable < Confidence::Suspicious);
        assert!(Confidence::Suspicious < Confidence::Likely);
        assert!(Confidence::Likely < Confidence::Certain);
    }

    #[test]
    fn a_report_keeps_the_highest_confidence() {
        let limits = AuditLimits::default();
        let mut report = AuditReport::default();
        report.push(finding(FindingKind::NeverMatched, Confidence::Suspicious), &limits);
        assert_eq!(report.worst, Some(Confidence::Suspicious));
        report.push(finding(FindingKind::Shadowed, Confidence::Certain), &limits);
        assert_eq!(report.worst, Some(Confidence::Certain));
        assert_eq!(report.count_of(FindingKind::Shadowed), 1);
    }

    #[test]
    fn the_per_kind_cap_counts_the_rest_instead_of_listing_them() {
        // Without the cap a configuration with hundreds of one problem would make
        // the report as large as the configuration.
        let limits = AuditLimits { max_rules: 200, max_per_kind: 3 };
        let mut report = AuditReport::default();
        for _ in 0..10 {
            report.push(finding(FindingKind::Duplicate, Confidence::Certain), &limits);
        }
        assert_eq!(report.count_of(FindingKind::Duplicate), 3);
        assert_eq!(report.summarised, vec![("duplicate".to_string(), 7)]);
        assert!(report.has_findings());
    }

    #[test]
    fn a_capped_report_still_reports_the_worst_confidence() {
        // The severity must reflect what was seen, not only what was listed.
        let limits = AuditLimits { max_rules: 200, max_per_kind: 1 };
        let mut report = AuditReport::default();
        report.push(finding(FindingKind::Duplicate, Confidence::Certain), &limits);
        report.push(finding(FindingKind::Duplicate, Confidence::Certain), &limits);
        assert_eq!(report.worst, Some(Confidence::Certain));
    }
}
