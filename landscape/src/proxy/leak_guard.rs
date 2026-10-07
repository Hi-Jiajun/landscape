//! Evaluates the four leak classes and the delivery matrix from the state that
//! actually exists on the machine.
//!
//! Every verdict carries the values it was derived from, because "no leak" is
//! only meaningful if the operator can see what was inspected. The checks read
//! the kernel (the TProxy fabric, the firewall), the engine and the plugin
//! configuration; nothing here changes state.

use landscape_common::flow::mark::FlowMarkAction;
use landscape_common::proxy::{
    DnsGuardStatus, LeakClass, LeakFinding, LeakGuardReport, LeakSeverity, MatrixCell,
    TproxyDeliveryStatus, TproxyMissingListener, TproxyTargetStatus,
};

/// Everything the check needs, gathered by the caller so this stays testable
/// without a live kernel.
pub struct LeakGuardInput<'a> {
    pub tproxy: &'a TproxyDeliveryStatus,
    pub engine_running: bool,
    pub missing_listener_policy: TproxyMissingListener,
    /// An interface currently holds a global IPv6 address, so an IPv6 packet can
    /// leave. Read from the machine rather than from configuration: a configured
    /// IPv6 that did not come up cannot leak, and one that came up outside the
    /// configuration still can.
    pub wan_has_ipv6: bool,
    /// `iptables -S`-style lines of the DNS hijack rules, when known.
    pub dns_hijack_rules: Vec<String>,
    /// Kernel state of the DNS leak guard, which blocks the paths that bypass the
    /// managed resolver.
    pub dns_guard: DnsGuardStatus,
    /// Flow ids the flow rules classify as proxied. The fabric's targets come from
    /// the same rules, so a flow listed here but absent from the fabric is one the
    /// configuration expects to be proxied and is not.
    pub proxied_flows: Vec<u8>,
    /// What the DNS rules do with a destination nothing more specific matched.
    pub routing_default: RoutingDefault,
    /// The datapath's policy for a destination nothing classified.
    pub unclassified: landscape_common::flow::dataplane::UnclassifiedPolicy,
}

/// The rules a destination reaches when no earlier rule claims it.
///
/// This is read from the rule set rather than assumed, because the interesting
/// states are invisible in any single rule: a rule can *look* like it sends
/// traffic to the proxy and still resolve to a direct path.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RoutingDefault {
    /// The rule that catches everything else: the highest-indexed enabled rule
    /// with no source. Unmatched traffic lands here.
    pub terminal: Option<RoutingDefaultRule>,
    /// Enabled rules that ask for a redirect naming no tier (flow 0).
    ///
    /// The engine resolves such a mark to `Direct` - a redirect whose target is
    /// the default flow has no managed tier to send the traffic to - so a rule
    /// written as "send this to the proxy" quietly means "let it out directly".
    /// Measured on 2026-10-07: the non-China rule was in exactly this shape, and
    /// a LAN client's real IPv6 address reached three external reflectors,
    /// confirmed on the WAN with the reflector replying to that address.
    pub targetless_redirects: Vec<RoutingDefaultRule>,
}

/// One rule that decides where unmatched traffic goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingDefaultRule {
    pub index: u32,
    pub name: String,
    /// A short description of what it matches, for the evidence line.
    pub matches: String,
}

impl RoutingDefault {
    /// Build it from the DNS rules.
    ///
    /// Disabled rules are ignored: they decide nothing.
    pub fn from_rules(rules: impl IntoIterator<Item = RoutingRule>) -> Self {
        let mut terminal: Option<RoutingDefaultRule> = None;
        let mut targetless: Vec<RoutingDefaultRule> = Vec::new();
        for rule in rules {
            if !rule.enable {
                continue;
            }
            if rule.matches_everything {
                let candidate = RoutingDefaultRule {
                    index: rule.index,
                    name: rule.name.clone(),
                    matches: "matches everything".to_string(),
                };
                // The highest index wins: evaluation stops at the first match, so
                // the last catch-all is the one a destination actually reaches.
                if terminal.as_ref().is_none_or(|seen| rule.index > seen.index) {
                    terminal = Some(candidate);
                }
                continue;
            }
            if rule.redirect_to_no_tier {
                targetless.push(RoutingDefaultRule {
                    index: rule.index,
                    name: rule.name.clone(),
                    matches: rule.matches.clone(),
                });
            }
        }
        targetless.sort_by_key(|rule| rule.index);
        Self { terminal, targetless_redirects: targetless }
    }
}

/// One configured DNS rule, reduced to what the routing default depends on.
#[derive(Debug, Clone)]
pub struct RoutingRule {
    pub index: u32,
    pub name: String,
    pub enable: bool,
    /// No source: the rule matches every destination.
    pub matches_everything: bool,
    /// The rule's mark is a redirect that names no flow, which the datapath
    /// resolves to `Direct`.
    pub redirect_to_no_tier: bool,
    /// What the rule matches, for the evidence line.
    pub matches: String,
}

impl RoutingRule {
    /// Reduce a configured rule.
    pub fn new(
        index: u32,
        name: String,
        enable: bool,
        mark: landscape_common::flow::mark::FlowMark,
        matches_everything: bool,
        matches: String,
    ) -> Self {
        Self {
            index,
            name,
            enable,
            matches_everything,
            redirect_to_no_tier: mark.action() == FlowMarkAction::Redirect && mark.flow_id() == 0,
            matches,
        }
    }
}

/// Build the report.
pub fn evaluate(input: LeakGuardInput<'_>) -> LeakGuardReport {
    let mut report = LeakGuardReport {
        engine_running: input.engine_running,
        missing_listener_policy: input.missing_listener_policy,
        flows_without_listener: input
            .tproxy
            .targets
            .iter()
            .filter(|target| !target.listener_ready)
            .map(|target| target.flow_id)
            .collect(),
        ..Default::default()
    };

    check_fabric(&mut report, &input);
    check_proxy_failure(&mut report, &input);
    check_dns(&mut report, &input);
    check_ipv6(&mut report, &input);
    check_real_ip(&mut report, &input);
    check_routing_default(&mut report, &input);
    report.matrix = matrix(&input);
    report
}

/// Where a destination goes when no earlier rule claims it.
///
/// A rule set can look complete and still send unmatched traffic straight out:
/// the terminal rule's own action decides, and a redirect that names no tier
/// resolves to `Direct` rather than to any proxy. Both are read from the rules
/// themselves, so the finding names the rule instead of describing a hypothesis.
fn check_routing_default(report: &mut LeakGuardReport, input: &LeakGuardInput<'_>) {
    // The policy that actually decides where an unclassified destination goes.
    // This is the check that matters for it: a rule set can be perfect and the
    // datapath still send an unclassified destination out directly, which is what
    // happened until this policy existed.
    use landscape_common::flow::dataplane::UnclassifiedPolicy;
    match input.unclassified {
        UnclassifiedPolicy::Passthrough => report.push(LeakFinding {
            class: LeakClass::RealIp,
            severity: LeakSeverity::Leak,
            check: "unclassified_destination_is_direct".into(),
            detail: "A destination that no DNS rule and no destination-IP rule classified keeps \
                     the flow the packet already had, and with no device-to-flow assignment that \
                     flow is 0 - a plain forward. It therefore leaves from the client's own \
                     address, which is exactly what the routing contract forbids. Measured on \
                     2026-10-07: a LAN client's real IPv6 address reached three independent \
                     external reflectors, confirmed on the WAN."
                .into(),
            evidence: vec![
                "datapath policy for an unclassified destination: passthrough".into(),
                "flow 0 has no tier, so passthrough resolves to a direct forward".into(),
                "the route cache holds these verdicts as mark 0x00000000 (KeepGoing, flow 0), \
                 while a destination a rule sent direct is cached as 0x00000100 (Direct)"
                    .to_string(),
            ],
        }),
        UnclassifiedPolicy::Drop => report.push(LeakFinding {
            class: LeakClass::RealIp,
            severity: LeakSeverity::Ok,
            check: "unclassified_destination_is_direct".into(),
            detail: "A destination nothing classified is refused in the datapath, so it cannot \
                     leave from the client's own address."
                .into(),
            evidence: vec!["datapath policy for an unclassified destination: drop".into()],
        }),
        UnclassifiedPolicy::ProxyTier { flow_id } => report.push(LeakFinding {
            class: LeakClass::RealIp,
            severity: LeakSeverity::Ok,
            check: "unclassified_destination_is_direct".into(),
            detail: format!(
                "A destination nothing classified is sent to tier {flow_id}. If that tier has no \
                 delivery target the packet is refused rather than forwarded, so the fallback \
                 cannot silently become a direct path."
            ),
            evidence: vec![format!(
                "datapath policy for an unclassified destination: tier {flow_id}"
            )],
        }),
    }

    for rule in &input.routing_default.targetless_redirects {
        report.push(LeakFinding {
            class: LeakClass::RealIp,
            severity: LeakSeverity::Leak,
            check: "dns_rule_resolves_to_direct".into(),
            detail: format!(
                "DNS rule {} (\u{201c}{}\u{201d}, matching {}) is written as a redirect but names \
                 no flow, and the datapath resolves a redirect with no target flow to `Direct`. \
                 Every destination it matches therefore leaves from the client's own address \
                 instead of from a proxy tier - the rule reads as protection it does not \
                 provide. Fixing it is a routing decision: point it at a proxy tier, or make it \
                 a drop.",
                rule.index, rule.name, rule.matches
            ),
            evidence: vec![
                format!("rule index {}: {}", rule.index, rule.name),
                format!("matches: {}", rule.matches),
                "mark: redirect with flow 0 -> resolved as direct".to_string(),
            ],
        });
    }

    if let Some(rule) = &input.routing_default.terminal {
        // Not a leak on its own: the terminal rule keeps whatever flow the packet
        // already carries, and that flow may well be a proxy tier. What is worth
        // saying is that unmatched traffic is not *owned* by any rule, so its
        // destination is decided by the client's own flow rather than by policy.
        report.push(LeakFinding {
            class: LeakClass::RealIp,
            severity: LeakSeverity::Warn,
            check: "dns_terminal_rule_is_not_a_tier".into(),
            detail: format!(
                "The terminal DNS rule {} (\u{201c}{}\u{201d}) matches everything and names no \
                 proxy tier, so a destination that no earlier rule claims keeps the flow the \
                 packet already had. Whether that is a proxy or a direct path is then decided by \
                 the client's flow assignment rather than by a rule.",
                rule.index, rule.name
            ),
            evidence: vec![
                format!("rule index {}: {}", rule.index, rule.name),
                rule.matches.clone(),
            ],
        });
    }
}

/// The delivery fabric itself: if it is not in place, every per-flow conclusion
/// below is meaningless.
fn check_fabric(report: &mut LeakGuardReport, input: &LeakGuardInput<'_>) {
    if !input.tproxy.enabled {
        report.push(LeakFinding {
            class: LeakClass::ProxyFailure,
            severity: LeakSeverity::Warn,
            check: "tproxy_fabric_enabled".into(),
            detail: "The local TProxy delivery fabric is disabled, so a flow that targets a \
                     TProxy port is not being redirected at all: whether that flow is proxied \
                     or leaves directly is decided by the flow's own target."
                .into(),
            evidence: vec!["tproxy.enabled = false".into()],
        });
        return;
    }

    let mut broken = Vec::new();
    for family in &input.tproxy.families {
        if !family.is_consistent() {
            broken.push(format!(
                "{}: chain={} hooked={} ip_rule={} local_route={}",
                family.family,
                family.chain_present,
                family.prerouting_hooked,
                family.ip_rule_present,
                family.local_route_present
            ));
        }
    }
    if input.tproxy.families.is_empty() {
        // Enabled, but with no family state at all: nothing is being redirected,
        // so every flow that targets a TProxy port is following its ordinary path.
        report.push(LeakFinding {
            class: LeakClass::ProxyFailure,
            severity: LeakSeverity::Leak,
            check: "tproxy_fabric_consistent".into(),
            detail: "The delivery fabric reports no address family, so nothing is redirecting \
                     packets for the flows that target a proxy port."
                .into(),
            evidence: vec!["tproxy.enabled = true, families = []".into()],
        });
    } else if broken.is_empty() {
        report.push(LeakFinding {
            class: LeakClass::ProxyFailure,
            severity: LeakSeverity::Ok,
            check: "tproxy_fabric_consistent".into(),
            detail: "The delivery fabric is present and consistent for every address family \
                     it covers."
                .into(),
            evidence: input
                .tproxy
                .families
                .iter()
                .map(|f| {
                    format!(
                        "{}: {} rule(s), adopted {}",
                        f.family,
                        f.rules.len(),
                        f.adopted_rules.len()
                    )
                })
                .collect(),
        });
    } else {
        report.push(LeakFinding {
            class: LeakClass::ProxyFailure,
            severity: LeakSeverity::Leak,
            check: "tproxy_fabric_consistent".into(),
            detail: "The delivery fabric is incomplete, so packets a flow marked for proxying \
                     are not being redirected into the proxy: they follow the flow's ordinary \
                     path instead."
                .into(),
            evidence: broken,
        });
    }

    if let Some(error) = &input.tproxy.last_error {
        report.push(LeakFinding {
            class: LeakClass::ProxyFailure,
            severity: LeakSeverity::Warn,
            check: "tproxy_last_error".into(),
            detail: "The last attempt to program the delivery fabric reported an error.".into(),
            evidence: vec![error.clone()],
        });
    }
}

/// Proxy failure must refuse, not fall through.
fn check_proxy_failure(report: &mut LeakGuardReport, input: &LeakGuardInput<'_>) {
    let missing: Vec<&TproxyTargetStatus> =
        input.tproxy.targets.iter().filter(|t| !t.listener_ready).collect();

    if input.missing_listener_policy == TproxyMissingListener::Direct {
        // Only a leak if a flow is actually in that state; otherwise it is a
        // standing hazard the operator has opted into.
        let severity = if missing.is_empty() { LeakSeverity::Warn } else { LeakSeverity::Leak };
        report.push(LeakFinding {
            class: LeakClass::ProxyFailure,
            severity,
            check: "missing_listener_policy".into(),
            detail: if missing.is_empty() {
                "A flow whose proxy listener is missing would be forwarded directly. No flow is \
                 in that state right now, but the policy is fail-open."
                    .into()
            } else {
                "A flow's proxy listener is missing and the policy forwards such flows directly, \
                 so those flows are leaving through the WAN with the real source address."
                    .into()
            },
            evidence: vec![
                "tproxy_missing_listener = direct".into(),
                format!(
                    "flows without a listener: {:?}",
                    missing.iter().map(|t| t.flow_id).collect::<Vec<_>>()
                ),
            ],
        });
    } else {
        report.push(LeakFinding {
            class: LeakClass::ProxyFailure,
            severity: if missing.is_empty() {
                LeakSeverity::Ok
            } else {
                // The guard is working: those flows are being refused, not leaked.
                LeakSeverity::Notice
            },
            check: "missing_listener_policy".into(),
            detail: if missing.is_empty() {
                "Every proxied flow has a listener, and a flow that lost its listener would be \
                 refused rather than forwarded directly."
                    .into()
            } else {
                "Some flows have no listener and are being refused (not forwarded) — the \
                 intended fail-closed behaviour, but those flows are unusable until the proxy \
                 returns."
                    .into()
            },
            evidence: vec![
                "tproxy_missing_listener = drop".into(),
                format!(
                    "flows without a listener: {:?}",
                    missing.iter().map(|t| t.flow_id).collect::<Vec<_>>()
                ),
            ],
        });
    }

    // A configured flow whose redirect rule is absent is silently unproxied even
    // though the listener exists.
    let unredirected: Vec<u8> =
        input.tproxy.targets.iter().filter(|t| !t.rule_installed).map(|t| t.flow_id).collect();
    if !unredirected.is_empty() {
        report.push(LeakFinding {
            class: LeakClass::ProxyFailure,
            severity: LeakSeverity::Leak,
            check: "flow_redirect_installed".into(),
            detail: "A flow is configured to be proxied but has no redirect rule, so its packets \
                     are not entering the proxy."
                .into(),
            evidence: vec![format!("flows without a redirect rule: {unredirected:?}")],
        });
    }
}

/// DNS must reach the managed resolver and no other.
fn check_dns(report: &mut LeakGuardReport, input: &LeakGuardInput<'_>) {
    if input.dns_hijack_rules.is_empty() {
        report.push(LeakFinding {
            class: LeakClass::Dns,
            severity: LeakSeverity::Warn,
            check: "dns_hijack_present".into(),
            detail: "No client DNS hijack rule was found, so a client querying a resolver of its \
                     own choice is not being redirected to the managed one."
                .into(),
            evidence: vec!["dns hijack rules: (none reported)".into()],
        });
        return;
    }
    report.push(LeakFinding {
        class: LeakClass::Dns,
        severity: LeakSeverity::Ok,
        check: "dns_hijack_present".into(),
        detail: "Client DNS is redirected to the managed resolver.".into(),
        evidence: input.dns_hijack_rules.clone(),
    });

    // "A rule exists" is not the same as "the guard owns it". A hand-installed
    // redirect is not reconciled by any configuration and does not survive a
    // reboot, so the false sense of coverage it creates is worth a warning of its
    // own.
    if !dns_hijack_is_owned(&input.dns_hijack_rules) {
        report.push(LeakFinding {
            class: LeakClass::Dns,
            severity: LeakSeverity::Warn,
            check: "dns_hijack_unowned".into(),
            detail: "The plaintext-DNS redirect is not owned by anything that reconciles it: it \
                     is not in the guard's own chain, so it is not re-applied when the \
                     configuration changes and it disappears on reboot. Plaintext DNS works \
                     today on the strength of a rule nobody maintains."
                .into(),
            evidence: input.dns_hijack_rules.clone(),
        });
    }

    // The redirect covers plaintext DNS. A client that chooses an encrypted
    // resolver for itself is a separate path, and whether it is blocked is a
    // configuration decision rather than an accident.
    if !input.dns_guard.enabled {
        report.push(LeakFinding {
            class: LeakClass::Dns,
            severity: LeakSeverity::Warn,
            check: "encrypted_dns_blocked".into(),
            detail: "The DNS leak guard is off, so a client can reach a resolver of its own \
                     choosing over DoT or DoQ and bypass the managed resolver entirely. \
                     Plaintext DNS is still redirected."
                .into(),
            evidence: vec![
                "dns_guard.enable = false".into(),
                format!("plaintext redirect rules: {}", input.dns_hijack_rules.len()),
            ],
        });
    } else if let Some(error) = &input.dns_guard.last_error {
        report.push(LeakFinding {
            class: LeakClass::Dns,
            severity: LeakSeverity::Leak,
            check: "encrypted_dns_blocked".into(),
            detail: "The DNS leak guard is enabled but could not be applied, so the encrypted \
                     path is open despite the configuration."
                .into(),
            evidence: vec![error.clone()],
        });
    } else if let Some(error) = &input.dns_guard.dataplane_error {
        // The rules being installed is not the same as the path being closed. On
        // this router a direct flow is forwarded in TC before netfilter runs, so
        // a guard that only exists in netfilter refuses nothing at all - which is
        // exactly the state this reports instead of calling it healthy.
        report.push(LeakFinding {
            class: LeakClass::Dns,
            severity: LeakSeverity::Leak,
            check: "encrypted_dns_blocked".into(),
            detail: "The DNS leak guard is enabled, but the half that decides sits in the \
                     datapath and could not be programmed. Netfilter alone cannot refuse a \
                     client's encrypted DNS: the datapath forwards a direct flow before \
                     netfilter sees it, so the path is open despite the rules being installed."
                .into(),
            evidence: vec![
                error.clone(),
                format!("{} refusal rule(s) installed", input.dns_guard.rules.len()),
            ],
        });
    } else if input.dns_guard.counters.handoff_dot + input.dns_guard.counters.handoff_doh > 0
        && !refuses_encrypted_dns(&input.dns_guard.rules)
    {
        // A handoff with nothing to refuse it: the packet is taken off the normal
        // path and then ruled on by no one.
        //
        // This deliberately does **not** compare the two counters, which was wrong:
        // the datapath counters live in a pinned map that survives a restart, while
        // the netfilter counters belong to a chain rebuilt on every apply and start
        // again at zero. Comparing them reported a leak on the first report after a
        // deploy, with nothing actually wrong. The refusal rules are the durable
        // evidence, so they are what this reads.
        let handed_off =
            input.dns_guard.counters.handoff_dot + input.dns_guard.counters.handoff_doh;
        report.push(LeakFinding {
            class: LeakClass::Dns,
            severity: LeakSeverity::Leak,
            check: "encrypted_dns_blocked".into(),
            detail: "Encrypted-DNS packets are being taken off the normal path but nothing is \
                     refusing them, so the guard is only half installed."
                .into(),
            evidence: vec![
                format!("handed to the receive side: {handed_off} packet(s)"),
                format!("refusal rules found: {}", input.dns_guard.rules.len()),
            ],
        });
    } else {
        report.push(LeakFinding {
            class: LeakClass::Dns,
            severity: LeakSeverity::Ok,
            check: "encrypted_dns_blocked".into(),
            detail: format!(
                "DoT and DoQ from the LAN are refused, so a client cannot take its DNS to a \
                 resolver of its own choosing. {}known DoH endpoint(s) are refused by address; \
                 an endpoint nobody listed is indistinguishable from other HTTPS and is not \
                 claimed to be covered.",
                if input.dns_guard.doh_blocked == 0 { "No " } else { "" }
            ),
            evidence: input.dns_guard.rules.clone(),
        });
    }

    // Plaintext DNS has two transports and they are not the same problem. UDP is
    // managed; TCP needs the managed resolver to actually speak TCP, and
    // redirecting a TCP query to a listener that does not is a refused query
    // rather than a managed one. So the state is a declared choice with a
    // counter, not an assumption - and while it is open, say so.
    if input.dns_guard.enabled && input.dns_guard.counters.plaintext_tcp_left > 0 {
        report.push(LeakFinding {
            class: LeakClass::Dns,
            severity: LeakSeverity::Warn,
            check: "plaintext_dns_tcp_open".into(),
            detail: "Plaintext DNS over TCP is not intercepted: the TCP hijack is switched off \
                     because the managed resolver had not been confirmed to serve TCP. A client \
                     that asks over TCP reaches the resolver it names. UDP is managed."
                .into(),
            evidence: vec![format!(
                "{} TCP quer(ies) left on their normal path; turn the TCP hijack on only after \
                 the managed resolver answers `dig +tcp`",
                input.dns_guard.counters.plaintext_tcp_left
            )],
        });
    }

    // A TPROXY rule outside our chain, or an `ip rule` that also points at our
    // route table, can take packets a flow marked for proxying and route them by
    // that rule instead.
    if !input.tproxy.foreign_tproxy_rules.is_empty() {
        report.push(LeakFinding {
            class: LeakClass::Dns,
            severity: LeakSeverity::Warn,
            check: "foreign_tproxy_rules".into(),
            detail: "TPROXY rules outside the managed chains are present; they can deliver \
                     packets for the managed flows to a different port."
                .into(),
            evidence: input.tproxy.foreign_tproxy_rules.clone(),
        });
    }
}

/// IPv6 must not take a path IPv4 is denied.
fn check_ipv6(report: &mut LeakGuardReport, input: &LeakGuardInput<'_>) {
    if !input.wan_has_ipv6 {
        report.push(LeakFinding {
            class: LeakClass::Ipv6,
            severity: LeakSeverity::Notice,
            check: "ipv6_enabled".into(),
            detail: "No interface holds a global IPv6 address, so there is no IPv6 egress to \
                     leak through. Reported rather than assumed: bringing IPv6 up later changes \
                     the answer."
                .into(),
            evidence: vec!["no global IPv6 address on any interface".into()],
        });
        return;
    }

    let v6 = input.tproxy.families.iter().find(|f| f.family.contains("ipv6") || f.family == "6");
    match v6 {
        Some(family) if family.is_consistent() => {
            report.push(LeakFinding {
                class: LeakClass::Ipv6,
                severity: LeakSeverity::Ok,
                check: "ipv6_fabric_consistent".into(),
                detail: "IPv6 is enabled and the delivery fabric covers it, so a flowed IPv6 \
                         packet is redirected the same way its IPv4 counterpart is."
                    .into(),
                evidence: vec![format!("ipv6: {} rule(s)", family.rules.len())],
            });
        }
        Some(family) => {
            report.push(LeakFinding {
                class: LeakClass::Ipv6,
                severity: LeakSeverity::Leak,
                check: "ipv6_fabric_consistent".into(),
                detail: "IPv6 is enabled but the delivery fabric is not consistent for it, so \
                         IPv6 traffic for a proxied flow can leave directly while the same flow \
                         over IPv4 is proxied."
                    .into(),
                evidence: vec![format!(
                    "ipv6: chain={} hooked={} ip_rule={} local_route={}",
                    family.chain_present,
                    family.prerouting_hooked,
                    family.ip_rule_present,
                    family.local_route_present
                )],
            });
        }
        None => {
            report.push(LeakFinding {
                class: LeakClass::Ipv6,
                severity: LeakSeverity::Leak,
                check: "ipv6_fabric_present".into(),
                detail: "IPv6 is enabled but the delivery fabric has no IPv6 family state, so \
                         nothing is redirecting IPv6 for the proxied flows."
                    .into(),
                evidence: vec!["no ipv6 entry in the fabric status".into()],
            });
        }
    }
}

/// Nothing outside the managed fabric may route a proxied flow's packets.
fn check_real_ip(report: &mut LeakGuardReport, input: &LeakGuardInput<'_>) {
    if input.tproxy.foreign_ip_rules.is_empty() {
        report.push(LeakFinding {
            class: LeakClass::RealIp,
            severity: LeakSeverity::Ok,
            check: "foreign_ip_rules".into(),
            detail: "No routing rule outside the managed set targets the proxy route table, so \
                     nothing is diverting the proxied flows."
                .into(),
            evidence: vec!["foreign ip rules: (none)".into()],
        });
    } else {
        report.push(LeakFinding {
            class: LeakClass::RealIp,
            severity: LeakSeverity::Warn,
            check: "foreign_ip_rules".into(),
            detail: "A routing rule outside the managed set also targets the proxy route table. \
                     Such a rule commonly matches by mark, and the datapath keeps the flow id in \
                     the mark, so a coarse mask can pull unproxied packets into it."
                .into(),
            evidence: input.tproxy.foreign_ip_rules.clone(),
        });
    }

    if !input.proxied_flows.is_empty() {
        let delivered: Vec<u8> = input.tproxy.targets.iter().map(|target| target.flow_id).collect();
        let undelivered: Vec<u8> =
            input.proxied_flows.iter().copied().filter(|flow| !delivered.contains(flow)).collect();
        if undelivered.is_empty() {
            report.push(LeakFinding {
                class: LeakClass::RealIp,
                severity: LeakSeverity::Ok,
                check: "proxied_flows_delivered".into(),
                detail: "Every flow the rules classify as proxied has a delivery target, so none \
                         of them is quietly following its ordinary path."
                    .into(),
                evidence: vec![format!(
                    "proxied flows: {:?}; delivered: {:?}",
                    input.proxied_flows, delivered
                )],
            });
        } else {
            report.push(LeakFinding {
                class: LeakClass::RealIp,
                severity: LeakSeverity::Leak,
                check: "proxied_flows_delivered".into(),
                detail: "A flow the rules classify as proxied has no delivery target in the \
                         fabric, so its traffic is not going through the proxy."
                    .into(),
                evidence: vec![format!(
                    "proxied flows: {:?}; proxied but undelivered: {undelivered:?}",
                    input.proxied_flows
                )],
            });
        }
    }
}

/// Whether each cell of the required matrix holds.
///
/// The required behaviour: a confirmed-proxy flow must be refused when the engine
/// is unavailable (never forwarded directly); an unknown flow must be blocked in
/// that state; a confirmed-direct flow keeps working; and with the engine running
/// the flows are delivered to their tiers.
fn matrix(input: &LeakGuardInput<'_>) -> Vec<MatrixCell> {
    let engine_failed = !input.engine_running;
    let blocking = input.missing_listener_policy == TproxyMissingListener::Drop;

    let engine_ok_behaviour = if input.tproxy.targets.is_empty() {
        "no flow targets a proxy tier".to_string()
    } else {
        format!(
            "flow(s) {:?} delivered to their tiers",
            input.tproxy.targets.iter().map(|t| t.flow_id).collect::<Vec<_>>()
        )
    };

    let mut cells = Vec::new();

    // Confirmed proxy.
    cells.push(MatrixCell {
        classification: "confirmed_proxy".into(),
        engine: "engine_ok".into(),
        behaviour: engine_ok_behaviour.clone(),
        required: true,
        note: None,
    });
    cells.push(MatrixCell {
        classification: "confirmed_proxy".into(),
        engine: "engine_failed".into(),
        behaviour: if blocking {
            "refused: the redirect stays and the connection fails".to_string()
        } else {
            "forwarded directly".to_string()
        },
        required: blocking,
        note: if blocking {
            None
        } else {
            Some(
                "set tproxy_missing_listener to `drop` to refuse instead of forwarding".to_string(),
            )
        },
    });

    // Unknown. Its delivery is the same fabric as a proxied flow: an unknown
    // domain reaches the managed catch-all tier, so the engine-failure answer is
    // the same one.
    cells.push(MatrixCell {
        classification: "unknown".into(),
        engine: "engine_ok".into(),
        behaviour: "handled by the catch-all tier, alongside confirmed-proxy flows".into(),
        required: true,
        note: None,
    });
    cells.push(MatrixCell {
        classification: "unknown".into(),
        engine: "engine_failed".into(),
        behaviour: if blocking {
            "blocked: same fabric as a confirmed-proxy flow, so it is refused".to_string()
        } else {
            "forwarded directly".to_string()
        },
        required: blocking,
        note: if blocking {
            None
        } else {
            Some(
                "an unknown flow must be blocked, not forwarded, when the engine is down"
                    .to_string(),
            )
        },
    });

    // Confirmed direct: the fabric is not involved, so neither state changes it.
    for engine in ["engine_ok", "engine_failed"] {
        cells.push(MatrixCell {
            classification: "confirmed_direct".into(),
            engine: engine.into(),
            behaviour: "forwarded directly, as its rule says (its DNS stays managed)".into(),
            required: true,
            note: None,
        });
    }

    let _ = engine_failed;
    cells
}

/// Whether any interface holds a global IPv6 address.
///
/// Read from `/proc/net/if_inet6` rather than from configuration: it reports what
/// the kernel actually has, so an IPv6 that was configured but never came up is
/// not treated as a leak path, and one that came up outside the configuration
/// still is. Link-local (`fe80::/10`) and loopback are excluded because they
/// cannot reach the internet.
pub fn wan_has_global_ipv6() -> bool {
    let Ok(content) = std::fs::read_to_string("/proc/net/if_inet6") else {
        // No IPv6 support in the kernel at all.
        return false;
    };
    content.lines().any(|line| {
        let mut parts = line.split_whitespace();
        let Some(address) = parts.next() else { return false };
        let prefix_len = parts.next().and_then(|value| value.parse::<u8>().ok()).unwrap_or(128);
        // A /128 is a host route for a local address; anything in the
        // fe80::/10 range is link-local.
        let link_local = address.len() >= 4
            && matches!(&address[..4].to_ascii_lowercase()[..], "fe8" | "fe9" | "fea" | "feb");
        !link_local && prefix_len != 128
    })
}

/// The DNS redirect rules that are actually installed, so the DNS verdict rests
/// on the kernel rather than on what the configuration intended.
///
/// Both our own chain and anything that redirects 53 from `PREROUTING` are
/// collected. The distinction between them is reported, because a rule nobody
/// owns is a rule that survives the next configuration change and disappears at
/// the next reboot - which is exactly how the only hijack rule on the live box
/// came to be there, in no file in this repository and in no script on it.
pub async fn dns_hijack_rules() -> Vec<String> {
    let mut out = Vec::new();
    for arguments in [
        vec!["-t", "nat", "-S", "PREROUTING"],
        vec!["-t", "nat", "-S", "LANDSCAPE_DNS"],
        vec!["-t", "nat", "-S", "LANDSCAPE_DNS_HIJACK"],
    ] {
        if let Ok(stdout) = run_iptables(&arguments).await {
            for line in stdout.lines() {
                // Only the rules that actually send 53 somewhere are evidence.
                if line.contains("--dport 53") || line.contains("--dports 53") {
                    out.push(line.trim().to_string());
                }
            }
        }
    }
    out
}

/// Whether the installed hijack rules include one this service owns.
///
/// A rule in `PREROUTING` that redirects 53 is *not* ours: the guard works
/// through its own chain, so anything else was put there by hand.
pub fn dns_hijack_is_owned(rules: &[String]) -> bool {
    rules.iter().any(|rule| rule.contains("LANDSCAPE_DNS_HIJACK"))
}

/// Whether the refusal rules for encrypted DNS are installed.
///
/// Read from the rule set rather than from a counter: the rule set is what the
/// kernel enforces, while the counters have different lifetimes on the two sides
/// (the datapath's survive a restart, the chain's restart with the chain).
fn refuses_encrypted_dns(rules: &[String]) -> bool {
    // The refusal chain's own target; the leak report reads the rules as text, so
    // the literal is the one the guard writes (`BLOCK_TARGET` in `dns_guard.rs`).
    rules.iter().any(|rule| rule.contains("853") && rule.contains("DROP"))
}

async fn run_iptables(arguments: &[&str]) -> Result<String, String> {
    let output = tokio::process::Command::new("iptables")
        .args(arguments)
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use landscape_common::flow::dataplane::UnclassifiedPolicy;
    use landscape_common::flow::mark::FlowMark;
    use landscape_common::proxy::{TproxyFamilyStatus, TproxyTargetStatus};

    use super::*;

    fn consistent_families() -> Vec<TproxyFamilyStatus> {
        ["ipv4", "ipv6"]
            .into_iter()
            .map(|family| TproxyFamilyStatus {
                family: family.to_string(),
                chain_present: true,
                prerouting_hooked: true,
                ip_rule_present: true,
                local_route_present: true,
                rules: vec!["-j TPROXY --on-port 7892".to_string()],
                adopted_rules: vec![],
            })
            .collect()
    }

    fn base<'a>(
        tproxy: &'a TproxyDeliveryStatus,
        policy: TproxyMissingListener,
    ) -> LeakGuardInput<'a> {
        LeakGuardInput {
            tproxy,
            engine_running: true,
            missing_listener_policy: policy,
            wan_has_ipv6: true,
            dns_hijack_rules: vec![
                "-A PREROUTING -i lan -j LANDSCAPE_DNS_HIJACK".to_string(),
                "-A LANDSCAPE_DNS_HIJACK -p udp --dport 53 -j REDIRECT --to-ports 53".to_string(),
            ],
            dns_guard: enabled_dns_guard(),
            proxied_flows: vec![14],
            routing_default: RoutingDefault::default(),
            // The contract for this gateway: an unclassified destination goes to a
            // managed tier rather than out directly. The fixture is the *compliant*
            // configuration, so a test that wants to exercise the non-compliant one
            // has to say so - which is how `passthrough_for_unclassified...` fails
            // loudly if this default is ever relaxed.
            unclassified: UnclassifiedPolicy::ProxyTier { flow_id: 14 },
        }
    }

    /// The guard as it looks when it has been turned on and applied.
    fn enabled_dns_guard() -> DnsGuardStatus {
        DnsGuardStatus {
            enabled: true,
            lan_iface: "lan".into(),
            rules: vec![
                "iptables -t mangle -A LANDSCAPE_DNS_GUARD -p tcp --dport 853 -j DROP".into(),
                "iptables -t mangle -A LANDSCAPE_DNS_GUARD -p udp --dport 853 -j DROP".into(),
            ],
            doh_blocked: 0,
            exempted_hosts: 0,
            counters: landscape_common::proxy::DnsGuardCounters::default(),
            refused_packets: 0,
            hijacked_connections: 0,
            dataplane_error: None,
            last_error: None,
        }
    }

    fn healthy_tproxy() -> TproxyDeliveryStatus {
        TproxyDeliveryStatus {
            enabled: true,
            families: consistent_families(),
            targets: vec![TproxyTargetStatus {
                flow_id: 14,
                port: 7896,
                listener_ready: true,
                rule_installed: true,
            }],
            foreign_tproxy_rules: vec![],
            foreign_ip_rules: vec![],
            backend: Some("mihomo".into()),
            last_error: None,
        }
    }

    fn severity_of(report: &LeakGuardReport, check: &str) -> Option<LeakSeverity> {
        report.findings.iter().find(|f| f.check == check).map(|f| f.severity)
    }

    #[test]
    fn a_healthy_setup_reports_no_warning() {
        let tproxy = healthy_tproxy();
        let report = evaluate(base(&tproxy, TproxyMissingListener::Drop));
        assert!(report.is_healthy(), "unexpected findings: {:?}", report.findings);
        assert_eq!(severity_of(&report, "missing_listener_policy"), Some(LeakSeverity::Ok));
        assert_eq!(severity_of(&report, "ipv6_fabric_consistent"), Some(LeakSeverity::Ok));
    }

    #[test]
    fn a_fail_open_policy_with_a_missing_listener_is_a_leak() {
        let mut tproxy = healthy_tproxy();
        tproxy.targets[0].listener_ready = false;
        let report = evaluate(base(&tproxy, TproxyMissingListener::Direct));
        assert_eq!(severity_of(&report, "missing_listener_policy"), Some(LeakSeverity::Leak));
        assert!(!report.is_healthy());
        assert_eq!(report.flows_without_listener, vec![14]);
    }

    #[test]
    fn fail_closed_with_a_missing_listener_is_only_a_notice() {
        let mut tproxy = healthy_tproxy();
        tproxy.targets[0].listener_ready = false;
        let report = evaluate(base(&tproxy, TproxyMissingListener::Drop));
        // The guard is doing its job: refused, not leaked.
        assert_eq!(severity_of(&report, "missing_listener_policy"), Some(LeakSeverity::Notice));
        assert!(report.is_healthy());
    }

    #[test]
    fn ipv6_enabled_without_v6_delivery_is_a_leak() {
        let mut tproxy = healthy_tproxy();
        tproxy.families.retain(|f| f.family != "ipv6");
        let report = evaluate(base(&tproxy, TproxyMissingListener::Drop));
        assert_eq!(severity_of(&report, "ipv6_fabric_present"), Some(LeakSeverity::Leak));
    }

    #[test]
    fn ipv6_disabled_is_reported_as_such_rather_than_assumed_safe() {
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.wan_has_ipv6 = false;
        let report = evaluate(input);
        assert_eq!(severity_of(&report, "ipv6_enabled"), Some(LeakSeverity::Notice));
        assert!(
            report.findings.iter().all(|f| f.class != LeakClass::Ipv6 || f.check == "ipv6_enabled")
        );
    }

    #[test]
    fn a_broken_fabric_is_a_leak_even_with_a_good_policy() {
        let mut tproxy = healthy_tproxy();
        tproxy.families[0].chain_present = false;
        let report = evaluate(base(&tproxy, TproxyMissingListener::Drop));
        assert_eq!(severity_of(&report, "tproxy_fabric_consistent"), Some(LeakSeverity::Leak));
    }

    #[test]
    /// An enabled fabric that reports no family at all is redirecting nothing,
    /// which is the widest form of "the flows are not being proxied".
    fn an_enabled_fabric_with_no_families_is_a_leak() {
        let mut tproxy = healthy_tproxy();
        tproxy.families.clear();
        let report = evaluate(base(&tproxy, TproxyMissingListener::Drop));
        assert_eq!(severity_of(&report, "tproxy_fabric_consistent"), Some(LeakSeverity::Leak));
    }

    #[test]
    fn a_proxied_flow_the_fabric_does_not_deliver_is_a_leak() {
        let mut tproxy = healthy_tproxy();
        tproxy.targets.clear();
        let report = evaluate(base(&tproxy, TproxyMissingListener::Drop));
        let finding = report.findings.iter().find(|f| f.check == "proxied_flows_delivered");
        let finding = finding.expect("the check must run when flows are classified as proxied");
        assert_eq!(finding.severity, LeakSeverity::Leak);
        assert!(finding.evidence[0].contains("undelivered"));
    }

    #[test]
    fn no_classified_flows_means_the_delivery_check_is_not_claimed() {
        // Without the classification there is nothing to compare against, so the
        // report stays silent rather than claiming coverage it did not verify.
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.proxied_flows.clear();
        let report = evaluate(input);
        assert!(report.findings.iter().all(|f| f.check != "proxied_flows_delivered"));
    }

    #[test]
    fn foreign_routing_rules_are_reported_with_their_text() {
        let mut tproxy = healthy_tproxy();
        tproxy.foreign_ip_rules = vec!["100: from all fwmark 0x1/0x1 lookup 100".into()];
        let report = evaluate(base(&tproxy, TproxyMissingListener::Drop));
        let finding = report.findings.iter().find(|f| f.check == "foreign_ip_rules").unwrap();
        assert_eq!(finding.severity, LeakSeverity::Warn);
        assert!(finding.evidence[0].contains("fwmark"));
    }

    #[test]
    fn missing_dns_hijack_is_reported() {
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.dns_hijack_rules.clear();
        let report = evaluate(input);
        assert_eq!(severity_of(&report, "dns_hijack_present"), Some(LeakSeverity::Warn));
    }

    #[test]
    fn the_guard_being_off_is_reported_as_a_warning() {
        // Plaintext DNS is redirected either way; this is about the encrypted path
        // a client can choose for itself.
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.dns_guard = DnsGuardStatus::default();
        let report = evaluate(input);
        let finding = report.findings.iter().find(|f| f.check == "encrypted_dns_blocked").unwrap();
        assert_eq!(finding.severity, LeakSeverity::Warn);
        assert!(finding.detail.contains("DoT"));
        // The plaintext redirect is still reported as covered, so the two paths
        // are not conflated.
        assert_eq!(severity_of(&report, "dns_hijack_present"), Some(LeakSeverity::Ok));
    }

    #[test]
    fn a_guard_that_could_not_be_applied_is_a_leak_not_a_notice() {
        // Configured-on but not in the kernel is the dangerous state: the operator
        // believes the path is closed.
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.dns_guard = DnsGuardStatus {
            enabled: true,
            lan_iface: "lan".into(),
            rules: vec![],
            doh_blocked: 0,
            exempted_hosts: 0,
            counters: landscape_common::proxy::DnsGuardCounters::default(),
            refused_packets: 0,
            hijacked_connections: 0,
            dataplane_error: None,
            last_error: Some("ip6tables: no chain".into()),
        };
        let report = evaluate(input);
        let finding = report.findings.iter().find(|f| f.check == "encrypted_dns_blocked").unwrap();
        assert_eq!(finding.severity, LeakSeverity::Leak);
        assert!(finding.evidence[0].contains("no chain"));
    }

    #[test]
    fn a_guard_that_only_exists_in_netfilter_is_a_leak() {
        // The measured live state on 2026-10-07: refusal rules installed and
        // counted, and a client's DoT still connected, because the datapath
        // forwards a direct flow before netfilter runs. Reporting that as healthy
        // is the failure this branch exists to prevent.
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.dns_guard = enabled_dns_guard();
        input.dns_guard.dataplane_error = Some("open dns_guard_config_map: No such file".into());
        let report = evaluate(input);
        let finding = report.findings.iter().find(|f| f.check == "encrypted_dns_blocked").unwrap();
        assert_eq!(finding.severity, LeakSeverity::Leak);
        assert!(finding.evidence[0].contains("dns_guard_config_map"));
    }

    #[test]
    fn a_handoff_that_is_being_refused_is_healthy() {
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.dns_guard = enabled_dns_guard();
        input.dns_guard.counters.handoff_dot = 12;
        input.dns_guard.refused_packets = 12;
        // The hijack counter is per connection, so it is allowed to differ from
        // the per-packet handoff count without that meaning anything.
        input.dns_guard.counters.handoff_plaintext = 40;
        input.dns_guard.hijacked_connections = 7;
        let report = evaluate(input);
        let finding = report.findings.iter().find(|f| f.check == "encrypted_dns_blocked").unwrap();
        assert_eq!(finding.severity, LeakSeverity::Ok);
    }

    /// The two counter sets have different lifetimes - the datapath's live in a
    /// pinned map that survives a restart, the refusal chain's start again at zero
    /// when the chain is rebuilt. Comparing them reported a leak on the first
    /// report after a deploy with nothing wrong, so the check reads the rules
    /// instead. This is that exact state: handoffs counted, refusals not yet.
    #[test]
    fn a_handoff_whose_refusal_counter_was_reset_is_not_a_leak() {
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.dns_guard = enabled_dns_guard();
        input.dns_guard.counters.handoff_dot = 301;
        input.dns_guard.refused_packets = 0;
        let report = evaluate(input);
        let finding = report.findings.iter().find(|f| f.check == "encrypted_dns_blocked").unwrap();
        assert_eq!(
            finding.severity,
            LeakSeverity::Ok,
            "the refusal rules are installed, so this is not a leak: {}",
            finding.detail
        );
    }

    /// ... and the state it does catch: handoffs happening with no refusal rules.
    #[test]
    fn a_handoff_with_no_refusal_rules_is_a_leak() {
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.dns_guard = enabled_dns_guard();
        input.dns_guard.counters.handoff_dot = 301;
        input.dns_guard.refused_packets = 0;
        input.dns_guard.rules.retain(|rule| !rule.contains("853"));
        let report = evaluate(input);
        let finding = report.findings.iter().find(|f| f.check == "encrypted_dns_blocked").unwrap();
        assert_eq!(finding.severity, LeakSeverity::Leak);
    }

    #[test]
    fn a_hijack_rule_nobody_owns_is_reported_even_though_dns_works() {
        // The measured live state: exactly one redirect rule, in no file in this
        // repository and in no script on the box. DNS worked, and would have
        // stopped working at the next reboot.
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.dns_hijack_rules =
            vec!["-A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 53".to_string()];
        let report = evaluate(input);
        assert_eq!(severity_of(&report, "dns_hijack_present"), Some(LeakSeverity::Ok));
        assert_eq!(severity_of(&report, "dns_hijack_unowned"), Some(LeakSeverity::Warn));
    }

    #[test]
    fn a_hijack_rule_the_guard_owns_produces_no_such_warning() {
        let tproxy = healthy_tproxy();
        let input = base(&tproxy, TproxyMissingListener::Drop);
        assert!(dns_hijack_is_owned(&input.dns_hijack_rules));
        let report = evaluate(input);
        assert_eq!(severity_of(&report, "dns_hijack_unowned"), None);
    }

    /// A rule that reads as a redirect but names no tier resolves to direct, so
    /// the traffic it matches leaves from the client's own address. This is the
    /// shape the non-China rule had on 2026-10-07, when a LAN client's real IPv6
    /// reached three external reflectors (confirmed on the WAN).
    #[test]
    fn a_redirect_that_names_no_tier_is_reported_as_a_leak() {
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.routing_default = RoutingDefault::from_rules([RoutingRule::new(
            1000,
            "not-china".into(),
            true,
            FlowMark::new(FlowMarkAction::Redirect, 0, false),
            false,
            "geo_key=GEOLOCATION-!CN".into(),
        )]);
        let report = evaluate(input);
        let finding = report.findings.iter().find(|f| f.check == "dns_rule_resolves_to_direct");
        let finding = finding.expect("a targetless redirect must be reported");
        assert_eq!(finding.severity, LeakSeverity::Leak);
        assert_eq!(finding.class, LeakClass::RealIp);
        assert!(finding.detail.contains("1000"), "{}", finding.detail);
        assert!(finding.detail.contains("not-china"), "{}", finding.detail);
    }

    /// The same rule pointed at a real tier is not a finding: it does what it says.
    #[test]
    fn a_redirect_that_names_a_tier_is_not_reported() {
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.routing_default = RoutingDefault::from_rules([RoutingRule::new(
            1000,
            "not-china".into(),
            true,
            FlowMark::new(FlowMarkAction::Redirect, 14, false),
            false,
            "geo_key=GEOLOCATION-!CN".into(),
        )]);
        let report = evaluate(input);
        assert_eq!(severity_of(&report, "dns_rule_resolves_to_direct"), None);
    }

    /// A disabled rule decides nothing and must not be reported.
    #[test]
    fn a_disabled_targetless_redirect_is_not_reported() {
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.routing_default = RoutingDefault::from_rules([RoutingRule::new(
            1000,
            "not-china".into(),
            false,
            FlowMark::new(FlowMarkAction::Redirect, 0, false),
            false,
            "geo_key=GEOLOCATION-!CN".into(),
        )]);
        let report = evaluate(input);
        assert_eq!(severity_of(&report, "dns_rule_resolves_to_direct"), None);
    }

    /// The terminal default is the *last* catch-all, because evaluation stops at
    /// the first match: a lower-indexed catch-all with no source shadows nothing.
    #[test]
    fn from_rules_takes_the_last_catch_all_as_the_terminal_default() {
        let default = RoutingDefault::from_rules([
            RoutingRule::new(
                100,
                "early catch-all".into(),
                true,
                FlowMark::new(FlowMarkAction::KeepGoing, 0, false),
                true,
                String::new(),
            ),
            RoutingRule::new(
                10000,
                "Landscape Router default rule".into(),
                true,
                FlowMark::new(FlowMarkAction::KeepGoing, 0, false),
                true,
                String::new(),
            ),
            RoutingRule::new(
                99999,
                "disabled catch-all".into(),
                false,
                FlowMark::new(FlowMarkAction::KeepGoing, 0, false),
                true,
                String::new(),
            ),
        ]);
        let terminal = default.terminal.expect("a terminal rule");
        assert_eq!(terminal.index, 10000);
    }

    /// A terminal catch-all is worth saying out loud, but it is not itself a leak:
    /// the packet keeps the flow it already had, which may be a proxy tier.
    #[test]
    fn a_terminal_catch_all_is_a_warning_not_a_leak() {
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.routing_default = RoutingDefault::from_rules([RoutingRule::new(
            10000,
            "Landscape Router default rule".into(),
            true,
            FlowMark::new(FlowMarkAction::KeepGoing, 0, false),
            true,
            String::new(),
        )]);
        let report = evaluate(input);
        let finding = report.findings.iter().find(|f| f.check == "dns_terminal_rule_is_not_a_tier");
        let finding = finding.expect("the terminal rule must be reported");
        assert_eq!(finding.severity, LeakSeverity::Warn);
    }

    /// The check that matters for the observed leak: with the datapath's policy
    /// left at passthrough, an unclassified destination leaves from the client's
    /// own address, and the report must say so rather than calling `real_ip` fine.
    #[test]
    fn passthrough_for_unclassified_destinations_is_a_leak() {
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.unclassified = UnclassifiedPolicy::Passthrough;
        let report = evaluate(input);
        let finding = report
            .findings
            .iter()
            .find(|f| f.check == "unclassified_destination_is_direct")
            .expect("passthrough must be reported");
        assert_eq!(finding.severity, LeakSeverity::Leak);
        assert_eq!(finding.class, LeakClass::RealIp);
        assert!(
            finding.evidence.iter().any(|e| e.contains("0x00000000")),
            "the evidence must cite what the cache actually holds: {:?}",
            finding.evidence
        );
    }

    #[test]
    fn a_fallback_tier_closes_the_unclassified_path() {
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.unclassified = UnclassifiedPolicy::ProxyTier { flow_id: 14 };
        let report = evaluate(input);
        let finding = report
            .findings
            .iter()
            .find(|f| f.check == "unclassified_destination_is_direct")
            .unwrap();
        assert_eq!(finding.severity, LeakSeverity::Ok);
        assert_eq!(finding.class, LeakClass::RealIp);
        // The tier number has to be in the finding, or the reader cannot tell which
        // tier unclassified traffic actually goes to.
        assert!(finding.detail.contains("14"), "{}", finding.detail);
    }

    #[test]
    fn dropping_unclassified_destinations_closes_it_too() {
        let tproxy = healthy_tproxy();
        let mut input = base(&tproxy, TproxyMissingListener::Drop);
        input.unclassified = UnclassifiedPolicy::Drop;
        let report = evaluate(input);
        let finding = report
            .findings
            .iter()
            .find(|f| f.check == "unclassified_destination_is_direct")
            .unwrap();
        assert_eq!(finding.severity, LeakSeverity::Ok);
    }

    #[test]
    fn an_applied_guard_reports_its_rules_and_does_not_claim_unlisted_doh() {
        let tproxy = healthy_tproxy();
        let report = evaluate(base(&tproxy, TproxyMissingListener::Drop));
        let finding = report.findings.iter().find(|f| f.check == "encrypted_dns_blocked").unwrap();
        assert_eq!(finding.severity, LeakSeverity::Ok);
        assert!(!finding.evidence.is_empty(), "the installed rules are the evidence");
        assert!(
            finding.detail.contains("not") && finding.detail.contains("claimed to be covered"),
            "the boundary must be stated rather than glossed: {}",
            finding.detail
        );
    }

    #[test]
    fn the_matrix_marks_a_fail_open_engine_failure_as_not_required() {
        let tproxy = healthy_tproxy();
        let report = evaluate(base(&tproxy, TproxyMissingListener::Direct));
        let cell = report
            .matrix
            .iter()
            .find(|c| c.classification == "unknown" && c.engine == "engine_failed")
            .expect("the unknown/engine_failed cell is always present");
        assert!(!cell.required, "an unknown flow must be blocked when the engine is down");
        assert!(cell.note.is_some(), "and the report must say how to fix it");
    }

    #[test]
    fn the_matrix_requires_blocking_once_the_policy_is_fail_closed() {
        let tproxy = healthy_tproxy();
        let report = evaluate(base(&tproxy, TproxyMissingListener::Drop));
        for classification in ["confirmed_proxy", "unknown"] {
            let cell = report
                .matrix
                .iter()
                .find(|c| c.classification == classification && c.engine == "engine_failed")
                .unwrap();
            assert!(cell.required, "{classification} must be refused when the engine is down");
        }
        // A direct flow is never affected by the engine.
        for cell in report.matrix.iter().filter(|c| c.classification == "confirmed_direct") {
            assert!(cell.required);
        }
    }

    #[test]
    fn every_finding_carries_evidence() {
        let mut tproxy = healthy_tproxy();
        tproxy.families.clear();
        tproxy.targets.clear();
        tproxy.foreign_ip_rules.push("-".into());
        tproxy.foreign_tproxy_rules.push("-".into());
        tproxy.last_error = Some("boom".into());
        let report = evaluate(base(&tproxy, TproxyMissingListener::Direct));
        assert!(!report.findings.is_empty());
        for finding in &report.findings {
            assert!(!finding.evidence.is_empty(), "{} has no evidence", finding.check);
            assert!(!finding.detail.is_empty());
        }
    }
}
