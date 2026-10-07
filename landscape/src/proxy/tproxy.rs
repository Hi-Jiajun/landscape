//! Kernel TPROXY delivery fabric for `FlowTarget::LocalTproxy`.
//!
//! ## Why this exists
//!
//! The datapath classifies a packet into a flow and writes the flow id into the
//! low byte of `skb->mark` (`route4_flow_verdict` keeps `mark & 0xff == flow_id`
//! for every verdict it produces). Delivering such a packet to a *local*
//! transparent listener is the job of netfilter: a TPROXY rule has to match the
//! flow's mark, make the kernel treat the packet as local, and hand it to the
//! listener while preserving the original destination.
//!
//! Without that fabric a `LocalTproxy` flow is silently forwarded as if it were
//! a plain WAN target - the connection succeeds, unproxied. This module makes
//! the fabric derived, idempotent and inspectable, for **both address
//! families** (the router's LAN has IPv6 and a v4-only fabric would leave IPv6
//! flows pointing at a stale hard-coded port):
//!
//! * one dedicated mangle chain (`LANDSCAPE_TPROXY`) per family, hooked from
//!   `PREROUTING`,
//! * one TPROXY rule per `(flow_id, tcp|udp)` that targets a local listener,
//! * the `ip rule` + `local default` route the kernel needs to accept those
//!   packets locally,
//! * removal of rules that are no longer backed by a flow configuration -
//!   including TPROXY rules previously written by hand into `PREROUTING`.
//!
//! ## Scope
//!
//! Only forwarded (LAN client) traffic is covered. Locally generated traffic
//! never traverses `PREROUTING`, and marking it early enough would need a
//! `cgroup/connect4` hook; that case is reported rather than silently proxied
//! or silently dropped (see [`TproxyDeliveryStatus`]).
//!
//! Rules the fabric does not own are never modified. In particular the
//! DNS-over-53 redirect and the loopback `ACCEPT` rules that a deployment may
//! install elsewhere stay untouched; when a hand-written TPROXY rule duplicates
//! a managed target it is removed (reported as "adopted") so the packet is not
//! delivered twice.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use landscape_common::proxy::{
    TproxyDeliveryStatus, TproxyFamilyStatus, TproxyMissingListener, TproxyTargetStatus,
};
use tokio::process::Command;
use tokio::sync::{Mutex, RwLock};

/// Our own chain in the `mangle` table, used in both families.
pub const TPROXY_CHAIN: &str = "LANDSCAPE_TPROXY";

/// Routing table the TPROXY-marked packets are looked up in.
pub const TPROXY_ROUTE_TABLE: &str = "100";

/// Mark written by the TPROXY target so the `ip rule` picks the packet up.
///
/// This must not collide with what the datapath already writes into
/// `skb->mark`: `route4_flow_verdict` puts the **flow id in the low byte**, so
/// bit 0 is set for every odd flow id. A `fwmark 0x1/0x1` rule would therefore
/// also hijack ordinary packets of odd-numbered flows into the local route
/// table - which silently turns the `direct` (fail-open) policy into a
/// blackhole. Bits 16-23 are unused by `FLOW_ID_MASK` (0x000000ff),
/// `FLOW_ACTION_MASK` (0x00007f00), `FLOW_ALLOW_REUSE_PORT_MASK` (0x00008000)
/// and `FLOW_SOURCE_MASK` (0xff000000), so the mark lives there and the mask
/// keeps it exclusive.
const TPROXY_MARK: &str = "0x10000/0x10000";
/// The `fwmark` spec of our policy rule. Kept next to [`TPROXY_MARK`]: the rule
/// must select exactly the bit the TPROXY target sets, and nothing else may
/// depend on a different value.
const TPROXY_FWMARK: &str = "0x10000/0x10000";
/// Matching form used for `ip rule` bookkeeping.
const TPROXY_RULE_SELECTOR: &str = "fwmark 0x10000/0x10000";
/// `ip rule` foreign rules that also target our route table are reported (they
/// may hijack unrelated marked packets) but never modified.
const TPROXY_ROUTE_TABLE_SELECTOR: &str = "lookup 100";

/// `iptables` calls are serialized by our own lock; `-w` additionally waits for
/// the system-wide xtables lock instead of failing when something else edits
/// the ruleset (e.g. docker or the operator).
const IPTABLES_WAIT: &str = "5";

/// Below this port a listener most likely belongs to some other service; a
/// warning is logged but the rule is still installed (we run as root).
const WARN_PORT_BELOW: u16 = 1024;

/// Address family a rule set belongs to. The two families keep separate
/// netfilter tables and separate routing rule tables, so every operation is
/// performed once per family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    const ALL: [Family; 2] = [Family::V4, Family::V6];

    fn label(self) -> &'static str {
        match self {
            Family::V4 => "ipv4",
            Family::V6 => "ipv6",
        }
    }

    /// Netfilter tool for this family.
    fn tool(self) -> &'static str {
        match self {
            Family::V4 => "iptables",
            Family::V6 => "ip6tables",
        }
    }

    /// Extra `ip` argument (`ip -6 rule ...`).
    fn ip_flag(self) -> Option<&'static str> {
        match self {
            Family::V4 => None,
            Family::V6 => Some("-6"),
        }
    }

    /// `--on-ip` spec. The value is the family's wildcard address, which is
    /// what `iptables`/`ip6tables` print back for a rule that leaves the option
    /// out - spelling it out keeps our generated spec byte-identical to the
    /// stored one, so a steady state is detected as "unchanged".
    fn on_ip_spec(self) -> Vec<String> {
        match self {
            Family::V4 => vec!["--on-ip".into(), "0.0.0.0".into()],
            Family::V6 => vec!["--on-ip".into(), "::".into()],
        }
    }
}

/// Owns the kernel side of local TProxy delivery.
pub struct TproxyDelivery {
    enabled: AtomicBool,
    fallback: AtomicU8,
    desired: RwLock<BTreeMap<u8, u16>>,
    status: RwLock<TproxyDeliveryStatus>,
    op: Mutex<()>,
}

const FALLBACK_DIRECT: u8 = 0;
const FALLBACK_DROP: u8 = 1;

impl TproxyDelivery {
    pub fn new(enabled: bool, missing_listener: TproxyMissingListener) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            fallback: AtomicU8::new(match missing_listener {
                TproxyMissingListener::Direct => FALLBACK_DIRECT,
                TproxyMissingListener::Drop => FALLBACK_DROP,
            }),
            desired: RwLock::new(BTreeMap::new()),
            status: RwLock::new(TproxyDeliveryStatus::default()),
            op: Mutex::new(()),
        }
    }

    pub fn set_policy(&self, enabled: bool, missing_listener: TproxyMissingListener) {
        self.enabled.store(enabled, Ordering::SeqCst);
        self.fallback.store(
            match missing_listener {
                TproxyMissingListener::Direct => FALLBACK_DIRECT,
                TproxyMissingListener::Drop => FALLBACK_DROP,
            },
            Ordering::SeqCst,
        );
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    fn fallback_drop(&self) -> bool {
        self.fallback.load(Ordering::SeqCst) == FALLBACK_DROP
    }

    /// Replace the desired `flow_id -> tproxy port` mapping and apply it.
    ///
    /// Idempotent: when the mapping is unchanged the kernel is not touched.
    pub async fn set_targets(&self, desired: BTreeMap<u8, u16>) {
        {
            let mut current = self.desired.write().await;
            if *current == desired {
                return;
            }
            *current = desired;
        }
        self.apply().await;
    }

    /// Apply the current desired mapping (used after the plugin is enabled).
    pub async fn activate(&self) {
        self.apply().await;
    }

    /// Remove everything we installed. Leaves foreign rules alone.
    pub async fn teardown(&self) {
        let _guard = self.op.lock().await;
        let mut errors = Vec::new();
        for family in Family::ALL {
            errors.extend(self.teardown_family(family).await);
        }

        *self.status.write().await = TproxyDeliveryStatus {
            enabled: self.is_enabled(),
            last_error: if errors.is_empty() { None } else { Some(errors.join("; ")) },
            ..Default::default()
        };
    }

    async fn teardown_family(&self, family: Family) -> Vec<String> {
        let mut errors = Vec::new();
        if let Err(e) = self.delete_jump(family, "PREROUTING").await {
            errors.push(e);
        }
        if let Err(e) = self.flush_chain(family).await {
            errors.push(e);
        }
        if let Err(e) = self.delete_chain(family).await {
            errors.push(e);
        }
        if let Err(e) = self.remove_local_route(family).await {
            errors.push(e);
        }
        if let Err(e) = self.remove_ip_rule(family).await {
            errors.push(e);
        }
        errors
    }

    pub async fn status(&self) -> TproxyDeliveryStatus {
        self.status.read().await.clone()
    }

    /// Reconcile the kernel state with the desired mapping.
    pub async fn apply(&self) {
        let _guard = self.op.lock().await;

        let mut status = TproxyDeliveryStatus { enabled: self.is_enabled(), ..Default::default() };

        if !self.is_enabled() {
            *self.status.write().await = status;
            return;
        }

        let desired = self.desired.read().await.clone();
        let mut errors = Vec::new();
        for family in Family::ALL {
            let adopted = match self.reconcile_family(family, &desired).await {
                Ok(adopted) => adopted,
                Err(e) => {
                    tracing::error!(
                        "local tproxy delivery reconcile failed for {}: {e}",
                        family.label()
                    );
                    errors.push(format!("{}: {e}", family.label()));
                    Vec::new()
                }
            };
            // Report the state that actually resulted, even after a failure: a
            // partially applied family is exactly what an operator needs to see.
            let mut probe = self.probe_family(family).await;
            probe.adopted_rules = adopted;
            status.families.push(probe);
        }
        if !errors.is_empty() {
            status.last_error = Some(errors.join("; "));
        }

        // Report the post-reconcile state.
        status.targets = desired
            .iter()
            .map(|(flow_id, port)| {
                let installed_in_both = status.families.iter().all(|family| {
                    family.rules.iter().any(|rule| rule_matches_target(rule, *flow_id, *port))
                });
                TproxyTargetStatus {
                    flow_id: *flow_id,
                    port: *port,
                    listener_ready: listener_ready(*port),
                    rule_installed: installed_in_both,
                }
            })
            .collect();
        if let Ok(foreign) = self.foreign_tproxy_rules().await {
            status.foreign_tproxy_rules = foreign;
        }
        if let Ok(foreign) = self.foreign_ip_rules().await {
            status.foreign_ip_rules = foreign;
        }
        if let Ok(out) = run_cmd("iptables", &["--version"]).await {
            status.backend = Some(out.trim().to_string());
        }

        *self.status.write().await = status;
    }

    async fn reconcile_family(
        &self,
        family: Family,
        desired: &BTreeMap<u8, u16>,
    ) -> Result<Vec<String>, String> {
        // Validate before touching the kernel: a bad port must not leave the
        // ruleset half applied.
        for (flow_id, port) in desired {
            if *port == 0 {
                return Err(format!(
                    "flow {flow_id} targets tproxy port 0; refusing to program a redirect"
                ));
            }
            if *port < WARN_PORT_BELOW {
                tracing::warn!(
                    "flow {flow_id} targets privileged tproxy port {port}; the listener must run as root"
                );
            }
        }

        // 1. Our chain (and the jump that feeds it) must exist.
        self.ensure_chain(family).await?;
        self.ensure_jump(family, "PREROUTING").await?;

        // 2. Adopt hand-written redirects: a TPROXY rule in PREROUTING that
        //    duplicates one of our targets is ours now, and leaving it in place
        //    would deliver the packet twice.
        let adopted_rules = self.adopt_matching_rules(family, desired).await?;

        // 3. Build the rule set. `--on-port` is the local listener and
        //    `--tproxy-mark` makes the kernel treat the packet as local via the
        //    routing table below; the original destination is preserved.
        let mut wanted: Vec<Vec<String>> =
            vec![vec!["-i".into(), "lo".into(), "-j".into(), "RETURN".into()]];
        for (flow_id, port) in desired {
            if !listener_ready(*port) {
                if self.fallback_drop() {
                    tracing::warn!(
                        "flow {flow_id} targets tproxy port {port} but no listener is bound; keeping the redirect (fail-closed) so this proxied flow cannot leak out of the real WAN address"
                    );
                } else {
                    tracing::warn!(
                        "flow {flow_id} targets tproxy port {port} but no listener is bound; forwarding the flow directly because tproxy_missing_listener was explicitly set to `direct` (this can expose the real WAN address)"
                    );
                    continue;
                }
            }
            for proto in ["tcp", "udp"] {
                let mut spec: Vec<String> = vec![
                    "-p".into(),
                    proto.into(),
                    "-m".into(),
                    "mark".into(),
                    "--mark".into(),
                    format!("0x{flow_id:02x}/0xff"),
                    "-j".into(),
                    "TPROXY".into(),
                    "--on-port".into(),
                    port.to_string(),
                ];
                spec.extend(family.on_ip_spec());
                spec.push("--tproxy-mark".into());
                spec.push(TPROXY_MARK.into());
                wanted.push(spec);
            }
        }

        // 4. Only rewrite the chain when the content actually differs, so a
        //    steady state never leaves a window without redirect rules.
        let current = self.list_chain(family).await?;
        let wanted_lines: Vec<String> =
            wanted.iter().map(|spec| join_spec(TPROXY_CHAIN, spec)).collect();
        if normalize(&current) != normalize(&wanted_lines) {
            self.flush_chain(family).await?;
            for spec in &wanted {
                self.append_rule(family, spec).await?;
            }
            tracing::info!(
                "local tproxy delivery ({}): {} redirect rule(s) programmed for {} flow(s)",
                family.label(),
                wanted_lines.len().saturating_sub(1),
                desired.len()
            );
        }

        // 5. Routing glue: TPROXY alone is not enough, the marked packet has to
        //    be looked up in a table whose default route is "local".
        self.ensure_local_route(family).await?;
        self.ensure_ip_rule(family).await?;

        Ok(adopted_rules)
    }

    /// Read back the current kernel state for one family.
    async fn probe_family(&self, family: Family) -> TproxyFamilyStatus {
        let rules = self
            .list_chain(family)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|line| !line.trim_end().ends_with(TPROXY_CHAIN))
            .collect();
        TproxyFamilyStatus {
            family: family.label().to_string(),
            chain_present: self.chain_exists(family).await,
            prerouting_hooked: self.jump_present(family, "PREROUTING").await,
            ip_rule_present: self.ip_rule_present(family).await,
            local_route_present: self.local_route_present(family).await,
            rules,
            adopted_rules: Vec::new(),
        }
    }
}

// ── netfilter plumbing ───────────────────────────────────────────────────

impl TproxyDelivery {
    async fn chain_exists(&self, family: Family) -> bool {
        matches!(self.ipt(family, &["-S", TPROXY_CHAIN]).await, Ok((true, _)))
    }

    async fn ensure_chain(&self, family: Family) -> Result<(), String> {
        if self.chain_exists(family).await {
            return Ok(());
        }
        let (ok, out) = self.ipt(family, &["-N", TPROXY_CHAIN]).await?;
        if ok || out.contains("already exists") {
            Ok(())
        } else {
            Err(format!("cannot create {TPROXY_CHAIN}: {}", out.trim()))
        }
    }

    async fn flush_chain(&self, family: Family) -> Result<(), String> {
        let (ok, out) = self.ipt(family, &["-F", TPROXY_CHAIN]).await?;
        if ok || out.contains("No chain/target/match") {
            Ok(())
        } else {
            Err(format!("cannot flush {TPROXY_CHAIN}: {}", out.trim()))
        }
    }

    async fn delete_chain(&self, family: Family) -> Result<(), String> {
        let (ok, out) = self.ipt(family, &["-X", TPROXY_CHAIN]).await?;
        if ok || out.contains("No chain/target/match") {
            Ok(())
        } else {
            Err(format!("cannot delete {TPROXY_CHAIN}: {}", out.trim()))
        }
    }

    async fn list_chain(&self, family: Family) -> Result<Vec<String>, String> {
        let (ok, out) = self.ipt(family, &["-S", TPROXY_CHAIN]).await?;
        if !ok {
            return Ok(Vec::new());
        }
        Ok(out.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
    }

    async fn append_rule(&self, family: Family, spec: &[String]) -> Result<(), String> {
        let mut args: Vec<String> = vec!["-A".into(), TPROXY_CHAIN.into()];
        args.extend(spec.iter().cloned());
        let (ok, out) = self.ipt_owned(family, &args).await?;
        if ok {
            Ok(())
        } else {
            Err(format!("cannot append rule to {TPROXY_CHAIN}: {}", out.trim()))
        }
    }

    async fn jump_present(&self, family: Family, hook: &str) -> bool {
        matches!(self.ipt(family, &["-C", hook, "-j", TPROXY_CHAIN]).await, Ok((true, _)))
    }

    async fn ensure_jump(&self, family: Family, hook: &str) -> Result<(), String> {
        if hook == "OUTPUT" {
            // Deliberately not hooked: locally generated traffic would need the
            // flow mark before `OUTPUT`, which only a cgroup/connect hook can
            // provide. See the module docs.
            return Ok(());
        }
        if self.jump_present(family, hook).await {
            return Ok(());
        }
        let (ok, out) = self.ipt(family, &["-A", hook, "-j", TPROXY_CHAIN]).await?;
        if ok {
            tracing::info!(
                "local tproxy delivery ({}): hooked mangle {hook} -> {TPROXY_CHAIN}",
                family.label()
            );
            Ok(())
        } else {
            Err(format!("cannot hook {hook} -> {TPROXY_CHAIN}: {}", out.trim()))
        }
    }

    async fn delete_jump(&self, family: Family, hook: &str) -> Result<(), String> {
        loop {
            let (ok, _) = self.ipt(family, &["-D", hook, "-j", TPROXY_CHAIN]).await?;
            if !ok {
                return Ok(());
            }
        }
    }

    /// Find TPROXY rules outside our chain that duplicate a target we manage
    /// and delete them (returning their specs for reporting).
    async fn adopt_matching_rules(
        &self,
        family: Family,
        desired: &BTreeMap<u8, u16>,
    ) -> Result<Vec<String>, String> {
        let mut adopted = Vec::new();
        for hook in ["PREROUTING", "OUTPUT"] {
            let (ok, out) = self.ipt(family, &["-S", hook]).await?;
            if !ok {
                continue;
            }
            for line in out.lines() {
                let line = line.trim();
                if !line.contains("-j TPROXY") || line.contains(TPROXY_CHAIN) {
                    continue;
                }
                if !desired.iter().any(|(flow_id, port)| rule_matches_target(line, *flow_id, *port))
                {
                    continue;
                }
                let Some(spec) = line
                    .strip_prefix("-A ")
                    .and_then(|rest| rest.split_once(' ').map(|(_, spec)| spec.to_string()))
                else {
                    continue;
                };
                let mut args: Vec<String> = vec!["-D".into(), hook.into()];
                args.extend(spec.split_whitespace().map(|s| s.to_string()));
                let (ok, out) = self.ipt_owned(family, &args).await?;
                if ok {
                    tracing::info!(
                        "local tproxy delivery ({}): adopted and removed hand-written rule: -A {spec}",
                        family.label()
                    );
                    adopted.push(format!("-A {spec}"));
                } else {
                    tracing::warn!(
                        "local tproxy delivery ({}): could not remove hand-written rule `-A {spec}`: {}",
                        family.label(),
                        out.trim()
                    );
                }
            }
        }
        Ok(adopted)
    }

    /// TPROXY rules that live outside our chain (reported, never modified).
    async fn foreign_tproxy_rules(&self) -> Result<Vec<String>, String> {
        let mut found = Vec::new();
        for family in Family::ALL {
            for hook in ["PREROUTING", "OUTPUT", "POSTROUTING"] {
                let (ok, out) = self.ipt(family, &["-S", hook]).await?;
                if !ok {
                    continue;
                }
                for line in out.lines() {
                    let line = line.trim();
                    if line.contains("-j TPROXY") && !line.contains(TPROXY_CHAIN) {
                        found.push(format!("[{}] {line}", family.label()));
                    }
                }
            }
        }
        Ok(found)
    }

    /// `ip rule` entries pointing at our route table that are not ours.
    ///
    /// The notable case is a legacy `fwmark 0x1/0x1 lookup 100`: because the
    /// datapath stores the flow id in the mark's low byte, that rule matches
    /// every odd flow id and can push unproxied packets into the local route
    /// table (turning a `direct` fallback into a blackhole). We report it so the
    /// operator can remove the leftover, but never touch somebody else's rule.
    async fn foreign_ip_rules(&self) -> Result<Vec<String>, String> {
        let mut found = Vec::new();
        for family in Family::ALL {
            let (ok, out) = self.ip(family, &["rule", "show"]).await?;
            if !ok {
                continue;
            }
            for line in out.lines() {
                let line = line.trim();
                if !line.contains(TPROXY_ROUTE_TABLE_SELECTOR) {
                    continue;
                }
                if line.contains(TPROXY_RULE_SELECTOR) {
                    continue;
                }
                found.push(format!("[{}] {line}", family.label()));
            }
        }
        Ok(found)
    }
}

// ── routing glue ─────────────────────────────────────────────────────────

impl TproxyDelivery {
    async fn ip_rule_present(&self, family: Family) -> bool {
        match self.ip(family, &["rule", "show"]).await {
            Ok((_, out)) => out.lines().any(|l| {
                let l = l.replace('\t', " ");
                l.contains(TPROXY_RULE_SELECTOR)
                    && l.contains(&format!("lookup {TPROXY_ROUTE_TABLE}"))
            }),
            Err(_) => false,
        }
    }

    async fn ensure_ip_rule(&self, family: Family) -> Result<(), String> {
        if self.ip_rule_present(family).await {
            return Ok(());
        }
        let (ok, out) = self
            .ip(family, &["rule", "add", "fwmark", TPROXY_FWMARK, "lookup", TPROXY_ROUTE_TABLE])
            .await?;
        if ok {
            tracing::info!(
                "local tproxy delivery ({}): added `ip rule fwmark {TPROXY_FWMARK} lookup {TPROXY_ROUTE_TABLE}`",
                family.label()
            );
            Ok(())
        } else {
            Err(format!("cannot add the tproxy ip rule: {}", out.trim()))
        }
    }

    async fn remove_ip_rule(&self, family: Family) -> Result<(), String> {
        loop {
            let (ok, _) = self
                .ip(family, &["rule", "del", "fwmark", TPROXY_FWMARK, "lookup", TPROXY_ROUTE_TABLE])
                .await?;
            if !ok {
                return Ok(());
            }
        }
    }

    async fn local_route_present(&self, family: Family) -> bool {
        match self.ip(family, &["route", "show", "table", TPROXY_ROUTE_TABLE]).await {
            Ok((_, out)) => table_has_local_default(&out),
            Err(_) => false,
        }
    }

    async fn ensure_local_route(&self, family: Family) -> Result<(), String> {
        if self.local_route_present(family).await {
            return Ok(());
        }
        let (ok, out) = self
            .ip(
                family,
                &["route", "add", "local", "default", "dev", "lo", "table", TPROXY_ROUTE_TABLE],
            )
            .await?;
        if ok {
            tracing::info!(
                "local tproxy delivery ({}): added `local default dev lo table {TPROXY_ROUTE_TABLE}`",
                family.label()
            );
            Ok(())
        } else {
            Err(format!("cannot add the tproxy local route: {}", out.trim()))
        }
    }

    async fn remove_local_route(&self, family: Family) -> Result<(), String> {
        self.ip(
            family,
            &["route", "del", "local", "default", "dev", "lo", "table", TPROXY_ROUTE_TABLE],
        )
        .await?;
        Ok(())
    }

    async fn ipt(&self, family: Family, args: &[&str]) -> Result<(bool, String), String> {
        let owned: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        self.ipt_owned(family, &owned).await
    }

    async fn ipt_owned(&self, family: Family, args: &[String]) -> Result<(bool, String), String> {
        let mut full: Vec<String> =
            vec!["-t".into(), "mangle".into(), "-w".into(), IPTABLES_WAIT.into()];
        full.extend(args.iter().cloned());
        run_cmd_status_owned(family.tool(), &full).await
    }

    async fn ip(&self, family: Family, args: &[&str]) -> Result<(bool, String), String> {
        let mut full: Vec<String> = Vec::with_capacity(args.len() + 1);
        if let Some(flag) = family.ip_flag() {
            full.push(flag.to_string());
        }
        full.extend(args.iter().map(|a| a.to_string()));
        run_cmd_status_owned("ip", &full).await
    }
}

// ── helpers ──────────────────────────────────────────────────────────────

/// Does `spec` (an `iptables -S` line or a rule spec) redirect exactly this
/// target?
///
/// Adoption is deliberately narrow: the rule must be a TPROXY jump **gated on
/// our flow's mark byte**, which is the signature of the hand-written rules this
/// module replaces. A rule that merely names the same port, or names a
/// different mark, belongs to somebody else and is reported instead of being
/// deleted.
fn rule_matches_target(spec: &str, flow_id: u8, port: u16) -> bool {
    let tokens: Vec<&str> = spec.split_whitespace().collect();
    let value_of = |name: &str| tokens.windows(2).find(|w| w[0] == name).map(|w| w[1]);
    if value_of("-j") != Some("TPROXY") {
        return false;
    }
    let Some(mark) = value_of("--mark") else {
        return false;
    };
    if !mark_selects_flow(mark, flow_id) {
        return false;
    }
    if let Some(on_port) = value_of("--on-port")
        && on_port != port.to_string()
    {
        return false;
    }
    true
}

/// Does an `iptables --mark` value select exactly `flow_id` in the low byte?
///
/// iptables rewrites the spec it prints (`0x0a/0xff` comes back as `0xa/0xff`),
/// so the comparison has to be numeric. The mask's upper bits must be clear:
/// a stricter rule (e.g. `0xa/0xffffffff`) would not match our packets, which
/// carry the flow source in the high byte.
fn mark_selects_flow(mark: &str, flow_id: u8) -> bool {
    let (bits, mask) = mark.split_once('/').unwrap_or((mark, ""));
    let parse = |raw: &str| -> Option<u64> {
        let raw = raw.trim();
        let raw = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")).unwrap_or(raw);
        u64::from_str_radix(raw, 16).ok()
    };
    match (parse(bits), parse(mask)) {
        (Some(bits), Some(mask)) => {
            mask & 0xff == 0xff && mask >> 8 == 0 && bits & 0xff == u64::from(flow_id)
        }
        _ => false,
    }
}

fn join_spec(chain: &str, spec: &[String]) -> String {
    format!("-A {chain} {}", spec.join(" "))
}

/// Canonicalise a rule so that the text we generate compares equal to the text
/// `iptables -S` prints back.
///
/// `iptables` rewrites values while storing them: `--mark 0x0a/0xff` comes back
/// as `0xa/0xff`, `--tproxy-mark 1` as `0x1/0xffffffff`, and the omitted
/// `--on-ip` as the family wildcard. Without this, every reconcile would look
/// like a change and needlessly flush the chain (leaving a window without
/// redirect rules).
fn canonical_rule(line: &str) -> String {
    let canonical_value = |kind: &str, raw: &str| -> String {
        match kind {
            "--mark" | "--tproxy-mark" => {
                let (bits, mask) = raw.split_once('/').unwrap_or((raw, ""));
                let hex = |value: &str| {
                    let value = value.trim().trim_start_matches("0x").trim_start_matches("0X");
                    u64::from_str_radix(value, 16)
                        .map(|n| format!("0x{n:x}"))
                        .unwrap_or_else(|_| value.to_string())
                };
                if mask.is_empty() { hex(bits) } else { format!("{}/{}", hex(bits), hex(mask)) }
            }
            "--on-port" => {
                raw.parse::<u16>().map(|port| port.to_string()).unwrap_or_else(|_| raw.to_string())
            }
            _ => raw.to_string(),
        }
    };

    let mut out: Vec<String> = Vec::new();
    let mut pending: Option<String> = None;
    for token in line.split_whitespace() {
        match pending.take() {
            Some(kind) => out.push(canonical_value(&kind, token)),
            None => {
                if matches!(token, "--mark" | "--tproxy-mark" | "--on-port") {
                    pending = Some(token.to_string());
                }
                out.push(token.to_string());
            }
        }
    }
    out.join(" ")
}

fn normalize(lines: &[String]) -> Vec<String> {
    let mut out: Vec<String> = lines
        .iter()
        .map(|l| canonical_rule(l.trim()))
        // `iptables -S <chain>` prints the chain declaration first, and our
        // loopback guard is an implementation detail of the chain, so neither
        // may count as a content difference.
        .filter(|l| !l.starts_with("-N ") && !l.ends_with("-i lo -j RETURN"))
        .filter(|l| !l.is_empty())
        .collect();
    out.sort();
    out
}

fn table_has_local_default(route_show: &str) -> bool {
    route_show
        .lines()
        .any(|l| l.trim().starts_with("local default") || l.trim().starts_with("local 0.0.0.0/0"))
}

/// Is a socket bound on `port`? Reads the kernel's socket tables so the check
/// works without owning the listener (both families included).
fn listener_ready(port: u16) -> bool {
    let want = format!("{port:04X}");
    for path in ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"] {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in content.lines().skip(1) {
            // Format: `sl local_address rem_address st ...`
            let cols: Vec<&str> = line.split_whitespace().collect();
            let (Some(local), Some(state)) = (cols.get(1), cols.get(3)) else {
                continue;
            };
            let Some((_, bound_port)) = local.rsplit_once(':') else { continue };
            if bound_port != want {
                continue;
            }
            // 0A = TCP_LISTEN, 07 = unconnected bound UDP socket.
            if *state == "0A" || *state == "07" {
                return true;
            }
        }
    }
    false
}

async fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, String> {
    let (ok, out) = run_cmd_status(cmd, args).await?;
    if !ok {
        return Err(format!("{cmd} {} failed: {}", args.join(" "), out.trim()));
    }
    Ok(out)
}

async fn run_cmd_status(cmd: &str, args: &[&str]) -> Result<(bool, String), String> {
    let owned: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    run_cmd_status_owned(cmd, &owned).await
}

async fn run_cmd_status_owned(cmd: &str, args: &[String]) -> Result<(bool, String), String> {
    let output = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| format!("failed to run `{cmd} {}`: {e}", args.join(" ")))?;
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok((output.status.success(), combined))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adoption_requires_the_flow_mark() {
        let spec = "-A PREROUTING -p tcp -m mark --mark 0x0a/0xff -j TPROXY --on-port 7892 --on-ip 0.0.0.0 --tproxy-mark 0x1/0xffffffff";
        assert!(rule_matches_target(spec, 10, 7892));
        // iptables prints `0xa` for `0x0a`.
        let printed = "-A PREROUTING -p tcp -m mark --mark 0xa/0xff -j TPROXY --on-port 7892 --on-ip 0.0.0.0 --tproxy-mark 0x1/0xffffffff";
        assert!(rule_matches_target(printed, 10, 7892));
        // ... and a stricter mask is not our rule (our packets carry the flow
        // source in the mark's high byte, so it would never fire for us).
        let strict = "-A PREROUTING -p tcp -m mark --mark 0xa/0xffffffff -j TPROXY --on-port 7892";
        assert!(!rule_matches_target(strict, 10, 7892));
        assert!(!rule_matches_target(spec, 11, 7892));
        // Same listener but a different flow: still another flow's rule.
        assert!(!rule_matches_target(spec, 11, 7893));
        // A rule that only names the port is somebody else's: deleting it would
        // be taking over a foreign rule, so it must not be adopted.
        let port_only = "-A PREROUTING -p tcp -j TPROXY --on-port 7893 ";
        assert!(!rule_matches_target(port_only, 42, 7893));
        assert!(!rule_matches_target("-A PREROUTING -p tcp -j TPROXY --on-port 9999 ", 10, 7892));
        // Non-TPROXY rules never match.
        assert!(!rule_matches_target("-A PREROUTING -p tcp --mark 0x0a/0xff -j ACCEPT", 10, 7892));
        // The DNS hijack rule a deployment may install is never touched.
        let dns =
            "-A PREROUTING -i lan -p udp --dport 53 ! -d 192.168.1.1 -j REDIRECT --to-ports 53";
        assert!(!rule_matches_target(dns, 10, 7892));
        // A mark-only rule (no listener condition) matches by flow.
        let mark_only = "-A PREROUTING -p tcp -m mark --mark 0x0a/0xff -j TPROXY ";
        assert!(rule_matches_target(mark_only, 10, 7892));
        assert!(!rule_matches_target(mark_only, 11, 7892));
    }

    #[test]
    fn local_default_detection() {
        assert!(table_has_local_default("local default dev lo scope host \n"));
        assert!(table_has_local_default("local 0.0.0.0/0 dev lo scope host\n"));
        assert!(!table_has_local_default("default via 192.168.1.1 dev lan\n"));
        assert!(!table_has_local_default(""));
    }

    #[test]
    fn normalize_ignores_the_loopback_guard() {
        let with_guard = vec![
            "-N LANDSCAPE_TPROXY".to_string(),
            "-A LANDSCAPE_TPROXY -i lo -j RETURN".to_string(),
            "-A LANDSCAPE_TPROXY -p tcp -m mark --mark 0x0a/0xff -j TPROXY".to_string(),
        ];
        let without_guard = vec![
            "-N LANDSCAPE_TPROXY".to_string(),
            "-A LANDSCAPE_TPROXY -p tcp -m mark --mark 0x0a/0xff -j TPROXY".to_string(),
        ];
        assert_eq!(normalize(&with_guard), normalize(&without_guard));
    }

    #[test]
    fn generated_rule_matches_the_datapath_encoding() {
        // `route4_flow_verdict` keeps `mark & 0xff == flow_id`; the rule we build
        // matches exactly that byte.
        let spec = join_spec(
            TPROXY_CHAIN,
            &[
                "-p".into(),
                "tcp".into(),
                "-m".into(),
                "mark".into(),
                "--mark".into(),
                format!("0x{:02x}/0xff", 11),
                "-j".into(),
                "TPROXY".into(),
                "--on-port".into(),
                "7893".into(),
            ],
        );
        assert!(rule_matches_target(&spec, 11, 7893));
    }

    #[test]
    fn only_ipv4_pins_the_wildcard_on_ip() {
        // The wildcard is what `iptables`/`ip6tables` print back for a rule that
        // omits `--on-ip`, so spelling it out keeps the comparison stable.
        assert_eq!(Family::V4.on_ip_spec(), vec!["--on-ip".to_string(), "0.0.0.0".to_string()]);
        assert_eq!(Family::V6.on_ip_spec(), vec!["--on-ip".to_string(), "::".to_string()]);
        assert_eq!(Family::V4.tool(), "iptables");
        assert_eq!(Family::V6.tool(), "ip6tables");
        assert_eq!(Family::V4.ip_flag(), None);
        assert_eq!(Family::V6.ip_flag(), Some("-6"));
    }

    /// The mark must not collide with anything the datapath writes.
    ///
    /// `route4_flow_verdict` stores the flow id in the mark's low byte, so bit 0
    /// is set for every odd flow id. A `fwmark 0x1/0x1` rule (what the old
    /// hand-written script used) would therefore also match ordinary packets of
    /// odd-numbered flows and push them into the local route table — which turns
    /// the `direct` (fail-open) policy into a blackhole.
    #[test]
    fn tproxy_mark_never_collides_with_the_datapath_bits() {
        let parse = |raw: &str| {
            let raw = raw.trim();
            u64::from_str_radix(raw.trim_start_matches("0x"), 16).unwrap()
        };
        let (bits, mask) = TPROXY_MARK.split_once('/').expect("mark must carry a mask");
        let (bits, mask) = (parse(bits), parse(mask));
        assert_eq!(mask, bits, "the mask must select exactly our bit");

        // None of the datapath's fields may overlap.
        assert_eq!(bits & 0x0000_00ff, 0, "overlaps FLOW_ID_MASK (flow id)");
        assert_eq!(bits & 0x0000_7f00, 0, "overlaps FLOW_ACTION_MASK");
        assert_eq!(bits & 0x0000_8000, 0, "overlaps FLOW_ALLOW_REUSE_PORT_MASK");
        assert_eq!(bits & 0xff00_0000, 0, "overlaps FLOW_SOURCE_MASK");

        // ... and, concretely, no flow id can ever produce this mark.
        for flow_id in 0u16..=0xff {
            assert_eq!(bits & u64::from(flow_id), 0, "mark collides with flow id {flow_id}");
        }
    }

    /// A leftover `fwmark 0x1/0x1 lookup 100` must be surfaced, not silently
    /// tolerated: it can hijack unproxied packets of odd flows.
    #[test]
    fn a_legacy_ip_rule_is_reported_but_ours_is_not() {
        let legacy = "32765:\tfrom all fwmark 0x1/0x1 lookup 100";
        assert!(legacy.contains(TPROXY_ROUTE_TABLE_SELECTOR));
        assert!(!legacy.contains(TPROXY_RULE_SELECTOR), "the legacy rule must not look like ours");

        let ours = "32765:\tfrom all fwmark 0x10000/0x10000 lookup 100";
        assert!(ours.contains(TPROXY_ROUTE_TABLE_SELECTOR));
        assert!(ours.contains(TPROXY_RULE_SELECTOR));
    }

    /// The rule we install and the rule we look for must be the same one,
    /// otherwise every reconcile adds a duplicate and never recognises its own
    /// rule (which the netns test caught once).
    #[test]
    fn our_fwmark_rule_and_its_selector_agree() {
        assert_eq!(TPROXY_FWMARK, TPROXY_MARK, "the rule must select the bit the target sets");
        let installed =
            format!("32765:\tfrom all fwmark {TPROXY_FWMARK} lookup {TPROXY_ROUTE_TABLE}");
        assert!(
            installed.contains(TPROXY_RULE_SELECTOR),
            "the installed rule is not recognised by our own selector: {installed}"
        );
    }

    #[test]
    fn canonical_rule_matches_what_iptables_prints_back() {
        // What we generate for flow 10 -> 7892 ...
        let generated = canonical_rule(&join_spec(
            TPROXY_CHAIN,
            &[
                "-p".into(),
                "tcp".into(),
                "-m".into(),
                "mark".into(),
                "--mark".into(),
                "0x0a/0xff".into(),
                "-j".into(),
                "TPROXY".into(),
                "--on-port".into(),
                "7892".into(),
                "--on-ip".into(),
                "0.0.0.0".into(),
                "--tproxy-mark".into(),
                TPROXY_MARK.into(),
            ],
        ));
        // ... must equal what `iptables -S` reports for it. This is the exact
        // shape observed on a live router (v4), including the rewritten mark.
        let printed = canonical_rule(
            "-A LANDSCAPE_TPROXY -p tcp -m mark --mark 0xa/0xff -j TPROXY --on-port 7892 --on-ip 0.0.0.0 --tproxy-mark 0x10000/0x10000",
        );
        assert_eq!(generated, printed);

        // Same for IPv6, where ip6tables prints the omitted `--on-ip` as `::`
        // and the tproxy mark in its expanded form.
        let generated_v6 = canonical_rule(&join_spec(
            TPROXY_CHAIN,
            &[
                "-p".into(),
                "udp".into(),
                "-m".into(),
                "mark".into(),
                "--mark".into(),
                "0x0e/0xff".into(),
                "-j".into(),
                "TPROXY".into(),
                "--on-port".into(),
                "7896".into(),
                "--on-ip".into(),
                "::".into(),
                "--tproxy-mark".into(),
                TPROXY_MARK.into(),
            ],
        ));
        let printed_v6 = canonical_rule(
            "-A LANDSCAPE_TPROXY -p udp -m mark --mark 0xe/0xff -j TPROXY --on-port 7896 --on-ip :: --tproxy-mark 0x10000/0x10000",
        );
        assert_eq!(generated_v6, printed_v6);
    }

    #[test]
    fn default_policy_is_fail_closed() {
        // Security property: a flow classified as proxied must not silently
        // leave through the WAN just because the proxy is unavailable. The
        // default therefore *keeps* the redirect (drop) and fail-open has to be
        // opted into explicitly.
        use landscape_common::proxy::{ProxyPluginConfig, TproxyMissingListener};

        assert_eq!(TproxyMissingListener::default(), TproxyMissingListener::Drop);
        let cfg = ProxyPluginConfig::default();
        assert_eq!(cfg.tproxy_missing_listener, TproxyMissingListener::Drop);
        assert!(cfg.manage_tproxy_delivery, "delivery management should be on by default");

        let policy = TproxyDelivery::new(true, cfg.tproxy_missing_listener);
        assert!(policy.fallback_drop(), "the delivery fabric must fail closed by default");
        let permissive = TproxyDelivery::new(true, TproxyMissingListener::Direct);
        assert!(!permissive.fallback_drop(), "fail-open must be reachable only by explicit opt-in");
    }

    #[test]
    fn listener_ready_sees_a_real_listener() {
        // A bound TCP listener is detected ...
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let bound = listener.local_addr().unwrap().port();
        assert!(listener_ready(bound), "port {bound} is listening but was not detected");

        // ... and a port nothing is bound to is not.
        let free = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let free_port = free.local_addr().unwrap().port();
        drop(free);
        assert!(!listener_ready(free_port), "port {free_port} is not listening");
    }

    /// End-to-end exercise of the real `iptables`/`ip6tables`/`ip` plumbing.
    ///
    /// Needs root and an isolated ruleset, so it is `#[ignore]`d by default:
    ///
    /// ```text
    /// ip netns add tproxy-fabric-test
    /// ip -n tproxy-fabric-test link set lo up
    /// ip netns exec tproxy-fabric-test cargo test -p landscape --lib \
    ///     proxy::tproxy -- --ignored --test-threads=1 --nocapture
    /// ip netns del tproxy-fabric-test
    /// ```
    #[tokio::test]
    #[ignore = "requires root inside a throwaway network namespace"]
    async fn fabric_installs_swaps_and_removes_redirects() {
        let first = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let first_port = first.local_addr().unwrap().port();
        let second = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let second_port = second.local_addr().unwrap().port();

        let fabric = TproxyDelivery::new(true, TproxyMissingListener::Direct);

        // A hand-written redirect for a target we are about to manage: this is
        // exactly the state a pre-existing deployment (systemd unit, hand-run
        // iptables) leaves behind.
        for family in Family::ALL {
            let (ok, out) = fabric
                .ipt(
                    family,
                    &[
                        "-A",
                        "PREROUTING",
                        "-p",
                        "tcp",
                        "-m",
                        "mark",
                        "--mark",
                        "0x0a/0xff",
                        "-j",
                        "TPROXY",
                        "--on-port",
                        &first_port.to_string(),
                        "--tproxy-mark",
                        "0x1/0xffffffff",
                    ],
                )
                .await
                .unwrap();
            assert!(ok, "could not inject the hand-written rule: {out}");
        }

        // 1. install: everything the kernel needs must appear, and the
        //    hand-written duplicates must be adopted instead of delivering
        //    every packet twice.
        fabric.set_targets(BTreeMap::from([(10u8, first_port)])).await;
        let status = fabric.status().await;
        assert_eq!(status.families.len(), 2, "{status:#?}");
        assert!(status.is_consistent(), "{status:#?}");
        for family in &status.families {
            assert!(family.chain_present, "{status:#?}");
            assert!(family.prerouting_hooked, "{status:#?}");
            assert!(family.ip_rule_present, "{status:#?}");
            assert!(family.local_route_present, "{status:#?}");
            // one loopback guard + tcp + udp
            assert_eq!(family.rules.len(), 3, "{status:#?}");
            assert_eq!(family.adopted_rules.len(), 1, "{status:#?}");
            // iptables prints the mark without the leading zero.
            assert!(family.rules.iter().any(|r| r.contains("--mark 0xa/0xff")), "{status:#?}");
        }
        assert_eq!(status.targets.len(), 1, "{status:#?}");
        assert_eq!(status.targets[0].flow_id, 10);
        assert_eq!(status.targets[0].port, first_port);
        assert!(status.targets[0].listener_ready, "{status:#?}");
        assert!(status.targets[0].rule_installed, "{status:#?}");

        // 1b. A leftover hand-written policy rule (`fwmark 0x1/0x1`, which
        //     matches every odd flow id) must be reported, not adopted, and must
        //     stay in place: it is somebody else's rule.
        let (ok, out) =
            run_cmd_status("ip", &["rule", "add", "fwmark", "0x1/0x1", "lookup", "100"])
                .await
                .unwrap();
        assert!(ok, "could not inject the legacy ip rule: {out}");
        fabric.apply().await;
        let status = fabric.status().await;
        assert!(
            status.foreign_ip_rules.iter().any(|r| r.contains("fwmark 0x1/0x1")),
            "the legacy policy rule was not reported: {status:#?}"
        );
        let all_rules = run_cmd("ip", &["rule", "show"]).await.unwrap();
        assert!(all_rules.contains("fwmark 0x1/0x1"), "the legacy rule was removed: {all_rules}");
        // ... while ours is recognised as ours and is not reported as foreign.
        assert!(fabric.ip_rule_present(Family::V4).await);
        assert!(
            !status.foreign_ip_rules.iter().any(|r| r.contains(TPROXY_RULE_SELECTOR)),
            "{status:#?}"
        );
        // Clean up our injected foreign rule so later steps see a known state.
        let _ = run_cmd_status("ip", &["rule", "del", "fwmark", "0x1/0x1", "lookup", "100"]).await;

        // 1b. Steady state must be a no-op: comparing what we generate against
        //     what `iptables -S` prints back has to recognise the rules as
        //     unchanged, otherwise every reconcile would flush the chain and
        //     leave a window without redirect rules.
        let before: Vec<Vec<String>> = status.families.iter().map(|f| f.rules.clone()).collect();
        fabric.apply().await;
        let status = fabric.status().await;
        let after: Vec<Vec<String>> = status.families.iter().map(|f| f.rules.clone()).collect();
        assert_eq!(before, after, "a steady state rewrote the ruleset: {status:#?}");

        // Nothing outside our chains matches the managed target any more.
        for family in Family::ALL {
            let (_, prerouting) = fabric.ipt(family, &["-S", "PREROUTING"]).await.unwrap();
            assert!(
                !prerouting.lines().any(|l| rule_matches_target(l, 10, first_port)),
                "a duplicate redirect survived in {}: {prerouting}",
                family.label()
            );
        }

        // 2. swap: the old target must be replaced, not accumulated.
        fabric.set_targets(BTreeMap::from([(11u8, second_port)])).await;
        let status = fabric.status().await;
        assert!(status.is_consistent(), "{status:#?}");
        for family in &status.families {
            assert!(
                family.rules.iter().any(|r| r.contains("--mark 0xb/0xff")
                    && r.contains(&format!("--on-port {second_port}"))),
                "{status:#?}"
            );
            assert!(
                !family.rules.iter().any(|r| r.contains(&format!("--on-port {first_port}"))),
                "the previous redirect survived the swap in {}: {}",
                family.family,
                family.rules.join(" | ")
            );
        }

        // 3. A redirect we do not manage is reported, never silently destroyed.
        let (ok, out) = fabric
            .ipt(
                Family::V4,
                &[
                    "-A",
                    "PREROUTING",
                    "-p",
                    "tcp",
                    "-m",
                    "mark",
                    "--mark",
                    "0x2a/0xff",
                    "-j",
                    "TPROXY",
                    "--on-port",
                    "38555",
                    "--on-ip",
                    "0.0.0.0",
                    "--tproxy-mark",
                    "0x1/0xffffffff",
                ],
            )
            .await
            .unwrap();
        assert!(ok, "could not inject the foreign rule: {out}");
        fabric.apply().await;
        let status = fabric.status().await;
        assert!(
            status.foreign_tproxy_rules.iter().any(|r| r.contains("--mark 0x2a/0xff")),
            "{status:#?}"
        );
        let (_, rules) = fabric.ipt(Family::V4, &["-S", "PREROUTING"]).await.unwrap();
        assert!(rules.contains("--mark 0x2a/0xff"), "the foreign rule was removed: {rules}");
        assert!(status.is_consistent(), "{status:#?}");

        // 4. teardown: nothing of ours may survive, in either family.
        fabric.teardown().await;
        let status = fabric.status().await;
        assert!(status.last_error.is_none(), "{status:#?}");
        for family in Family::ALL {
            assert!(!fabric.chain_exists(family).await, "{} chain survived", family.label());
            assert!(!fabric.jump_present(family, "PREROUTING").await);
            assert!(!fabric.ip_rule_present(family).await, "{} ip rule survived", family.label());
            assert!(
                !fabric.local_route_present(family).await,
                "{} local route survived",
                family.label()
            );
        }
        // The foreign rule is still there, untouched.
        let (_, rules) = fabric.ipt(Family::V4, &["-S", "PREROUTING"]).await.unwrap();
        assert!(rules.contains("--mark 0x2a/0xff"), "{rules}");
    }
}
