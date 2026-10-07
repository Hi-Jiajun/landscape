//! Evaluates the four leak classes and the delivery matrix from the state that
//! actually exists on the machine.
//!
//! Every verdict carries the values it was derived from, because "no leak" is
//! only meaningful if the operator can see what was inspected. The checks read
//! the kernel (the TProxy fabric, the firewall), the engine and the plugin
//! configuration; nothing here changes state.

use landscape_common::proxy::{
    LeakClass, LeakFinding, LeakGuardReport, LeakSeverity, MatrixCell, TproxyDeliveryStatus,
    TproxyMissingListener, TproxyTargetStatus,
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
    /// Flow ids the flow rules classify as proxied. The fabric's targets come from
    /// the same rules, so a flow listed here but absent from the fabric is one the
    /// configuration expects to be proxied and is not.
    pub proxied_flows: Vec<u8>,
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
    report.matrix = matrix(&input);
    report
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
pub async fn dns_hijack_rules() -> Vec<String> {
    let mut out = Vec::new();
    for arguments in
        [vec!["-t", "nat", "-S", "PREROUTING"], vec!["-t", "nat", "-S", "LANDSCAPE_DNS"]]
    {
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
                "-A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 53".to_string(),
            ],
            proxied_flows: vec![14],
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
