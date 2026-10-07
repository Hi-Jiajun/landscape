//! Keeps LAN clients on the managed resolver.
//!
//! Two halves, and both are required.
//!
//! **The datapath decides.** On this router a direct flow is forwarded by the TC
//! chain with `bpf_redirect` and never reaches netfilter at all - measured on the
//! live box, a LAN client's query to 8.8.8.8 was answered by 8.8.8.8 while the
//! `nat` hijack rule sat installed with its counter frozen. So classification has
//! to happen where the packets are, in `bpf/dns_guard/dns_guard.h`; a packet it
//! matches is handed to the local stack instead of being forwarded.
//!
//! **Netfilter rules on what is handed to it.** Plaintext DNS is hijacked to the
//! managed resolver by [`HIJACK_CHAIN`], which also gives the reply the correct
//! reverse translation, so the client still sees its answer come from the
//! address it asked. DoT and DoQ (853) and any configured DoH address are
//! refused by [`CHAIN`].
//!
//! The hijack rules used to exist without an owner: they appear in no file in
//! this repository and in no script on the box, so a reboot would have silently
//! removed the only thing keeping hardcoded resolvers honest. They are installed
//! from here now, for both address families and both transports, which is also
//! what lets the leak report cite a hijack rule this service owns and
//! reconciles rather than one it merely noticed.
//!
//! What this deliberately does not attempt: DoH to an address nobody listed. It
//! is indistinguishable from any other HTTPS connection without intercepting
//! TLS, and that is a boundary of the design rather than an oversight.

use std::net::IpAddr;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};

use landscape_common::proxy::dataplane::{DnsGuardDataplane, DnsGuardSpec};
use landscape_common::proxy::{DnsGuardConfig, DnsGuardExempt, DnsGuardStatus};
use tokio::sync::Mutex;

/// The chain that refuses encrypted DNS, in [`TABLE`].
const CHAIN: &str = "LANDSCAPE_DNS_GUARD";
/// The chain that hijacks plaintext DNS into the managed resolver, in
/// [`NAT_TABLE`]. Its own chain so its counters are readable on their own, and so
/// removing us cannot take an unrelated rule with it.
const HIJACK_CHAIN: &str = "LANDSCAPE_DNS_HIJACK";
/// The table [`CHAIN`] lives in, and [`HOOK`] belongs to.
const TABLE: &str = "mangle";
/// `REDIRECT` is a NAT target, so the hijack cannot live in `mangle` beside the
/// refusals.
const NAT_TABLE: &str = "nat";
/// Where both chains are hooked. `PREROUTING` is the only point that sees a LAN
/// client's packet before anything has been decided about it.
const HOOK: &str = "PREROUTING";
/// How a refused packet is treated. `DROP`, because `REJECT` belongs to the
/// `filter` table: the client sees the connection time out instead of being told
/// why, which is the price of catching the forwarded and the proxied path with
/// one rule.
const BLOCK_TARGET: &str = "DROP";
/// Serializes our own `iptables` calls; `-w` additionally waits for the
/// system-wide xtables lock rather than failing when something else edits the
/// ruleset.
const IPTABLES_WAIT: &str = "5";
/// DoT and DoQ share this port over TCP and UDP.
const DOT_DOQ_PORT: &str = "853";
/// Plaintext DNS. TCP is included on purpose: it is a normal resolver path, not
/// an optional extra.
const PLAINTEXT_DNS_PORT: &str = "53";
/// The port the managed resolver listens on.
const RESOLVER_PORT: &str = "53";
/// DoH is ordinary HTTPS, so it is matched by address on this port, over TCP and
/// over UDP (HTTP/3).
const DOH_PORT: &str = "443";

/// Address family. Each keeps its own netfilter table and its own datapath
/// entries, so every operation runs once per family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn all() -> [Family; 2] {
        [Family::V4, Family::V6]
    }

    fn tool(self) -> &'static str {
        match self {
            Family::V4 => "iptables",
            Family::V6 => "ip6tables",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Family::V4 => "ipv4",
            Family::V6 => "ipv6",
        }
    }

    /// Whether an address belongs to this family's table.
    fn owns(self, address: &IpAddr) -> bool {
        matches!((self, address), (Family::V4, IpAddr::V4(_)) | (Family::V6, IpAddr::V6(_)))
    }

    /// An exemption is only meaningful where both its ends are in this family's
    /// table; a mixed pair can never match a packet.
    fn owns_exemption(self, entry: &DnsGuardExempt) -> bool {
        self.owns(&entry.client) && self.owns(&entry.destination)
    }
}

/// What the guard is asked to do, flattened from configuration.
#[derive(Debug, Clone, Default)]
struct GuardSpec {
    enabled: bool,
    /// Traffic arriving on this interface is guarded. Matches the interface the
    /// existing DNS redirect hooks, so both cover the same clients.
    lan_iface: String,
    /// Known DoH endpoints to refuse.
    doh_block: Vec<IpAddr>,
    /// Trusted hosts and the one service each may keep using.
    exempt: Vec<DnsGuardExempt>,
    drop_fragments: bool,
    drop_unclassified: bool,
    plaintext_tcp: bool,
}

impl GuardSpec {
    fn from_config(config: &DnsGuardConfig) -> Self {
        Self {
            enabled: config.enable,
            lan_iface: config.lan_iface.clone(),
            doh_block: config.doh_block_ips.clone(),
            exempt: config.exempt.clone(),
            drop_fragments: config.drop_fragments,
            drop_unclassified: config.drop_unclassified,
            plaintext_tcp: config.plaintext_tcp,
        }
    }

    fn dataplane_spec(&self) -> DnsGuardSpec {
        DnsGuardSpec {
            enabled: self.enabled,
            drop_fragments: self.drop_fragments,
            drop_unclassified: self.drop_unclassified,
            doh_block: self.doh_block.clone(),
            exempt: self.exempt.clone(),
            plaintext_tcp: self.plaintext_tcp,
        }
    }
}

/// Owns both halves of the DNS leak guard.
pub struct DnsLeakGuard {
    spec: RwLock<GuardSpec>,
    status: RwLock<DnsGuardStatus>,
    /// Serializes applies: two concurrent applies would interleave their
    /// flush-and-rewrite sequences and could leave the chain half written.
    op: Mutex<()>,
    /// Whether the receive side is currently in place. Read by the status, and
    /// the reason the datapath is not enabled on its own.
    installed: AtomicBool,
    dataplane: Arc<dyn DnsGuardDataplane>,
}

impl DnsLeakGuard {
    pub fn new(dataplane: Arc<dyn DnsGuardDataplane>) -> Arc<Self> {
        Arc::new(Self {
            spec: RwLock::new(GuardSpec::default()),
            status: RwLock::new(DnsGuardStatus::default()),
            op: Mutex::new(()),
            installed: AtomicBool::new(false),
            dataplane,
        })
    }

    pub fn set_config(&self, config: &DnsGuardConfig) {
        *self.spec.write().unwrap_or_else(|e| e.into_inner()) = GuardSpec::from_config(config);
    }

    pub fn is_enabled(&self) -> bool {
        self.spec.read().unwrap_or_else(|e| e.into_inner()).enabled
    }

    /// Bring both halves in line with the configuration.
    ///
    /// Idempotent: chains are flushed and rewritten and the datapath is handed
    /// the whole desired state, so any state converges rather than toggling.
    ///
    /// Order matters, and it is not the same in both directions:
    ///
    /// * **Enabling**, the receive side goes first. Handing a packet to the local
    ///   stack while nothing rules on it would strand plaintext DNS, so if the
    ///   receive side failed for either family the datapath is left alone and
    ///   the failure is reported.
    /// * **Disabling**, the datapath goes first and the receive side is the last
    ///   thing removed. Removing the datapath while the refusals are still
    ///   installed would silently restore the bypass this whole mechanism exists
    ///   to close, for the whole window between the two steps.
    pub async fn apply(&self) {
        let _op = self.op.lock().await;
        let spec = self.spec.read().unwrap_or_else(|e| e.into_inner()).clone();

        let mut status = DnsGuardStatus {
            enabled: spec.enabled,
            lan_iface: spec.lan_iface.clone(),
            doh_blocked: spec.doh_block.len(),
            exempted_hosts: spec.exempt.len(),
            ..Default::default()
        };

        if !spec.enabled {
            self.stop_deciding(&spec, &mut status).await;
            let _ = self.teardown_chains(&mut status).await;
            self.installed.store(false, Ordering::SeqCst);
            *self.status.write().unwrap_or_else(|e| e.into_inner()) = status;
            return;
        }

        // Receive side first: refusals, then the hijack, per family.
        let mut receive_failed = false;
        for family in Family::all() {
            let (rules, error) = self.reconcile_block(family, &spec).await;
            status.rules.extend(rules);
            receive_failed |= Self::note_error(&mut status, family, error);

            let (hijack, error) = self.reconcile_hijack(family, &spec).await;
            status.rules.extend(hijack);
            receive_failed |= Self::note_error(&mut status, family, error);
        }

        if receive_failed {
            // Fail closed on the transition: with the receive side incomplete we
            // do not start deciding, so behaviour is unchanged rather than
            // half-applied.
            status.dataplane_error =
                Some("receive side did not install; the datapath guard was left as it was".into());
            tracing::error!(
                "DNS leak guard: receive side failed, refusing to enable the datapath guard"
            );
            // Still true: the refusals that did install are in the kernel and
            // are enforcing on the proxied path.
            self.installed.store(true, Ordering::SeqCst);
            self.fill_counters(&mut status).await;
            *self.status.write().unwrap_or_else(|e| e.into_inner()) = status;
            return;
        }

        if let Err(e) = self.dataplane.apply(&spec.dataplane_spec()) {
            tracing::error!("DNS leak guard: datapath programming failed: {e}");
            status.dataplane_error = Some(e);
        }

        self.installed.store(true, Ordering::SeqCst);
        tracing::warn!(
            lan_iface = %spec.lan_iface,
            rules = status.rules.len(),
            doh = status.doh_blocked,
            exempt = status.exempted_hosts,
            dataplane = status.dataplane_error.is_none(),
            "DNS leak guard applied: plaintext DNS from the LAN is hijacked to the managed \
             resolver, and encrypted DNS (853, listed DoH endpoints) is refused"
        );
        self.fill_counters(&mut status).await;
        *self.status.write().unwrap_or_else(|e| e.into_inner()) = status;
    }

    /// Record the first error of a family as the status's, and say whether this
    /// family failed.
    fn note_error(status: &mut DnsGuardStatus, family: Family, error: Option<String>) -> bool {
        match error {
            Some(e) => {
                tracing::error!(family = family.label(), "dns guard: {e}");
                if status.last_error.is_none() {
                    status.last_error = Some(format!("{}: {e}", family.label()));
                }
                true
            }
            None => false,
        }
    }

    /// Stop handing packets to the receive side.
    async fn stop_deciding(&self, spec: &GuardSpec, status: &mut DnsGuardStatus) {
        let mut off = spec.dataplane_spec();
        off.enabled = false;
        if let Err(e) = self.dataplane.apply(&off) {
            tracing::error!("DNS leak guard: could not stop the datapath guard: {e}");
            status.dataplane_error = Some(e);
        }
    }

    /// Read the datapath counters into the status.
    ///
    /// Read on every apply as well as on demand: a nonzero handoff count with the
    /// refusal counters at zero is the signature of a half-installed guard, and
    /// it should be visible without anyone going looking for it.
    async fn fill_counters(&self, status: &mut DnsGuardStatus) {
        // The netfilter side's own counters, read back from the kernel.
        let mut refused = 0u64;
        let mut hijacked = 0u64;
        for family in Family::all() {
            refused += count_matching_packets(family, TABLE, CHAIN, BLOCK_TARGET).await;
            hijacked += count_matching_packets(family, NAT_TABLE, HIJACK_CHAIN, "REDIRECT").await;
        }
        status.refused_packets = refused;
        status.hijacked_connections = hijacked;

        match self.dataplane.counters() {
            Ok(counters) => status.counters = counters,
            Err(e) => {
                tracing::warn!("DNS leak guard: counters unavailable: {e}");
                if status.dataplane_error.is_none() {
                    status.dataplane_error = Some(format!("counters unavailable: {e}"));
                }
            }
        }
    }

    /// Remove every chain this installed. Foreign rules are left alone.
    pub async fn teardown(&self) {
        let _op = self.op.lock().await;
        // The status is copied out, updated, then written back rather than held
        // across the `await`: a synchronous lock across an await point can be held
        // by a task that the runtime then needs to poll again, and the failure is
        // a deadlock rather than a wrong value.
        let mut status = self.status.read().unwrap_or_else(|e| e.into_inner()).clone();
        let teardown_result = self.teardown_chains(&mut status).await;
        if let Err(e) = teardown_result {
            tracing::error!("DNS leak guard: teardown incomplete: {e}");
        }
        status.rules.clear();
        *self.status.write().unwrap_or_else(|e| e.into_inner()) = status;
        self.installed.store(false, Ordering::SeqCst);
    }

    async fn teardown_chains(&self, status: &mut DnsGuardStatus) -> Result<(), String> {
        let mut errors = Vec::new();
        for family in Family::all() {
            for (table, chain) in [(TABLE, CHAIN), (NAT_TABLE, HIJACK_CHAIN)] {
                // Detach the jump first, then drop the chain: the other order
                // leaves a jump pointing at a missing chain, which netfilter
                // rejects.
                //
                // The jump has to be deleted by repeating the rule exactly as the
                // kernel has it. `-D ... -j CHAIN` alone does not match a rule
                // that also carries `-i lan`, and the delete then fails while
                // looking like it succeeded - which is how a stale, permanently
                // empty chain came to be hooked into PREROUTING on the live box.
                if let Err(e) = detach_jumps(family, table, chain).await {
                    errors.push(format!("{} {}: {e}", family.label(), chain));
                    continue;
                }
                match run(family, &["-t", table, "-F", chain]).await {
                    Ok(_) => {}
                    // No chain means nothing to flush.
                    Err(e) if e.contains("No chain") => {}
                    Err(e) => errors.push(format!("{} {}: {e}", family.label(), chain)),
                }
                match run(family, &["-t", table, "-X", chain]).await {
                    Ok(_) => {}
                    Err(e) if e.contains("No chain") => {}
                    Err(e) => errors.push(format!("{} {}: {e}", family.label(), chain)),
                }
            }
        }
        if !errors.is_empty() && status.last_error.is_none() {
            status.last_error = Some(errors.join("; "));
        }
        if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
    }

    pub async fn status(&self) -> DnsGuardStatus {
        let mut status = self.status.read().unwrap_or_else(|e| e.into_inner()).clone();
        // Report the datapath's live view, so a caller reading the status sees
        // what the kernel has rather than what the last apply believed.
        self.fill_counters(&mut status).await;
        status
    }

    /// Build the refusal chain for one family and hook it into `PREROUTING`.
    ///
    /// Returns the rules that are actually installed plus the first error, if
    /// any: a step failing half way through leaves rules in the kernel, and
    /// reporting "none installed" would make the status wrong exactly when it
    /// matters.
    async fn reconcile_block(
        &self,
        family: Family,
        spec: &GuardSpec,
    ) -> (Vec<String>, Option<String>) {
        let mut rules: Vec<Vec<String>> = Vec::new();

        // A trusted host's authorised service. First, so a later refusal cannot
        // shadow it.
        for entry in spec.exempt.iter().filter(|entry| family.owns_exemption(entry)) {
            for protocol in entry.protocol.as_iptables_protocols() {
                rules.push(vec![
                    "-s".into(),
                    entry.client.to_string(),
                    "-d".into(),
                    entry.destination.to_string(),
                    "-p".into(),
                    protocol.into(),
                    "--dport".into(),
                    entry.port.to_string(),
                    "-j".into(),
                    "RETURN".into(),
                ]);
            }
        }

        for protocol in ["tcp", "udp"] {
            rules.push(vec![
                "-p".into(),
                protocol.into(),
                "--dport".into(),
                DOT_DOQ_PORT.into(),
                "-j".into(),
                BLOCK_TARGET.into(),
            ]);
        }

        // Known DoH endpoints, over both transports. Ordinary HTTPS, so the
        // address is the only handle; an unlisted one is the documented boundary.
        for address in spec.doh_block.iter().filter(|address| family.owns(address)) {
            for protocol in ["tcp", "udp"] {
                rules.push(vec![
                    "-d".into(),
                    address.to_string(),
                    "-p".into(),
                    protocol.into(),
                    "--dport".into(),
                    DOH_PORT.into(),
                    "-j".into(),
                    BLOCK_TARGET.into(),
                ]);
            }
        }

        self.install(family, TABLE, CHAIN, &rules, &spec.lan_iface, 1).await
    }

    /// Build the plaintext-DNS hijack chain for one family and hook it.
    ///
    /// `--dst-type LOCAL` is the whole exemption story for the router's own
    /// addresses: traffic already addressed to the box is left for `INPUT` to
    /// deal with, which covers every local address in that family (IPv4 LAN,
    /// IPv6 ULA, GUA and link-local) without listing any of them.
    async fn reconcile_hijack(
        &self,
        family: Family,
        spec: &GuardSpec,
    ) -> (Vec<String>, Option<String>) {
        let mut rules: Vec<Vec<String>> = vec![vec![
            "-m".into(),
            "addrtype".into(),
            "--dst-type".into(),
            "LOCAL".into(),
            "-j".into(),
            "RETURN".into(),
        ]];

        // A trusted resolver keeps its own upstream: hijacking it would put the
        // whole LAN's answers behind a resolver that did not ask for it.
        for entry in spec.exempt.iter().filter(|entry| family.owns_exemption(entry)) {
            for protocol in entry.protocol.as_iptables_protocols() {
                rules.push(vec![
                    "-s".into(),
                    entry.client.to_string(),
                    "-d".into(),
                    entry.destination.to_string(),
                    "-p".into(),
                    protocol.into(),
                    "--dport".into(),
                    entry.port.to_string(),
                    "-j".into(),
                    "RETURN".into(),
                ]);
            }
        }

        // Plaintext DNS. UDP always; TCP only once the operator has confirmed the
        // resolver serves it, because redirecting a TCP query to a UDP-only
        // listener is a refused query rather than a managed one.
        let mut protocols = vec!["udp"];
        if spec.plaintext_tcp {
            protocols.push("tcp");
        }
        for protocol in protocols {
            rules.push(vec![
                "-p".into(),
                protocol.into(),
                "--dport".into(),
                PLAINTEXT_DNS_PORT.into(),
                "-j".into(),
                "REDIRECT".into(),
                "--to-ports".into(),
                RESOLVER_PORT.into(),
            ]);
        }

        self.install(family, NAT_TABLE, HIJACK_CHAIN, &rules, &spec.lan_iface, 1).await
    }

    /// Own a chain: create it if missing, flush it, fill it, then hook it once.
    async fn install(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        rules: &[Vec<String>],
        lan_iface: &str,
        hook_position: u32,
    ) -> (Vec<String>, Option<String>) {
        let installed = describe(family, table, chain, rules);

        // `-N` failing because the chain already exists is not an error, so its
        // result is deliberately dropped; the flush below is what makes the rule
        // set the whole truth.
        let _ = run(family, &["-t", table, "-N", chain]).await;
        if let Err(e) = run(family, &["-t", table, "-F", chain]).await {
            return (Vec::new(), Some(e));
        }

        for rule in rules {
            let mut full: Vec<String> = vec!["-t".into(), table.into(), "-A".into(), chain.into()];
            full.extend(rule.iter().cloned());
            if let Err(e) = self.run_spec(family, &full).await {
                return (installed, Some(e));
            }
        }

        match jump_present(family, table, chain).await {
            Ok(true) => {}
            Ok(false) => {
                let spec = vec![
                    "-t".to_string(),
                    table.to_string(),
                    "-I".to_string(),
                    HOOK.to_string(),
                    hook_position.to_string(),
                    "-i".to_string(),
                    lan_iface.to_string(),
                    "-j".to_string(),
                    chain.to_string(),
                ];
                if let Err(e) = self.run_spec(family, &spec).await {
                    return (installed, Some(e));
                }
            }
            Err(e) => return (installed, Some(e)),
        }
        (installed, None)
    }

    async fn run_spec(&self, family: Family, spec: &[String]) -> Result<(), String> {
        let borrowed: Vec<&str> = spec.iter().map(String::as_str).collect();
        run(family, &borrowed).await.map(|_| ())
    }
}

/// Whether our chain is already jumped into from the LAN.
async fn jump_present(family: Family, table: &str, chain: &str) -> Result<bool, String> {
    let output = run(family, &["-t", table, "-S", HOOK]).await?;
    Ok(output.lines().any(|line| line.contains(chain)))
}

/// Remove every jump from `HOOK` into `chain`, repeating each rule exactly as the
/// kernel reports it.
///
/// Matching by target alone is not enough: `-D` compares the whole rule, so a
/// jump carrying `-i lan` is not matched by a spec that omits it. Reading the
/// rules back and deleting what is actually there is order- and shape-
/// independent, and it cannot take a neighbouring rule with it because only
/// lines whose target is exactly this chain are used.
async fn detach_jumps(family: Family, table: &str, chain: &str) -> Result<(), String> {
    let listing = run(family, &["-t", table, "-S", HOOK]).await?;
    for line in listing.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // `-A <hook> ... -j <chain>`; the target must be this chain exactly, not
        // a longer name that merely starts with it.
        if fields.len() < 4 || fields[0] != "-A" || fields[1] != HOOK {
            continue;
        }
        if fields[fields.len() - 1] != chain {
            continue;
        }
        let mut arguments =
            vec!["-t".to_string(), table.to_string(), "-D".to_string(), HOOK.to_string()];
        arguments.extend(fields[2..].iter().map(|field| field.to_string()));
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        run(family, &borrowed).await?;
    }
    Ok(())
}

/// Sum the packet counter of every rule in `chain` whose target is `target`.
///
/// Read from the kernel (`-L -v -n -x`) rather than remembered in this process,
/// so it is the counter the rules themselves kept - which is the whole point of
/// reporting it. A missing chain is zero, not an error: the caller is usually
/// asking in order to decide whether something is wrong, and "absent" is one of
/// the answers.
async fn count_matching_packets(family: Family, table: &str, chain: &str, target: &str) -> u64 {
    let Ok(output) = run(family, &["-t", table, "-L", chain, "-v", "-n", "-x"]).await else {
        return 0;
    };
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let packets = fields.next()?.parse::<u64>().ok()?;
            let _bytes = fields.next()?;
            let row_target = fields.next()?;
            (row_target == target).then_some(packets)
        })
        .sum()
}

/// Readable form of the rules for the status report, tagged with the family's
/// tool and the chain they live in, so a reader can tell IPv4 from IPv6 and the
/// refusal chain from the hijack chain.
fn describe(family: Family, table: &str, chain: &str, rules: &[Vec<String>]) -> Vec<String> {
    rules
        .iter()
        .map(|rule| format!("{} -t {} -A {} {}", family.tool(), table, chain, rule.join(" ")))
        .collect()
}

/// Run one `iptables`/`ip6tables` command.
async fn run(family: Family, arguments: &[&str]) -> Result<String, String> {
    let output = tokio::process::Command::new(family.tool())
        .arg("-w")
        .arg(IPTABLES_WAIT)
        .args(arguments)
        .output()
        .await
        .map_err(|e| format!("cannot run {}: {e}", family.tool()))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::proxy::dataplane::NoopDnsGuardDataplane;
    use landscape_common::proxy::{DnsGuardCounters, DnsGuardProtocol};

    fn guard() -> Arc<DnsLeakGuard> {
        DnsLeakGuard::new(Arc::new(NoopDnsGuardDataplane))
    }

    #[test]
    fn the_guard_is_off_until_asked_for() {
        // It refuses and rewrites client traffic; turning it on should be a
        // decision.
        let guard = guard();
        assert!(!guard.is_enabled());
        assert!(!DnsGuardConfig::default().enable);
        // ... but the two switches that decide what happens to traffic that
        // cannot be classified are not symmetric, and the defaults say so.
        assert!(DnsGuardConfig::default().drop_fragments);
        assert!(!DnsGuardConfig::default().drop_unclassified);
    }

    #[test]
    fn a_family_only_claims_its_own_addresses() {
        let v4: IpAddr = "1.1.1.1".parse().unwrap();
        let v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        assert!(Family::V4.owns(&v4));
        assert!(!Family::V4.owns(&v6));
        assert!(Family::V6.owns(&v6));
        assert!(!Family::V6.owns(&v4));
    }

    #[test]
    fn an_exemption_only_belongs_to_a_family_that_holds_both_ends() {
        let same: DnsGuardExempt = DnsGuardExempt {
            client: "192.168.1.201".parse().unwrap(),
            destination: "223.5.5.5".parse().unwrap(),
            protocol: DnsGuardProtocol::Tcp,
            port: 853,
        };
        assert!(Family::V4.owns_exemption(&same));
        assert!(!Family::V6.owns_exemption(&same));

        // A pair that spans families can never match a packet, so it must not be
        // installed in either table.
        let mixed = DnsGuardExempt {
            destination: "2606:4700:4700::1111".parse().unwrap(),
            ..same
        };
        for family in Family::all() {
            assert!(!family.owns_exemption(&mixed), "{}", family.label());
        }
    }

    #[test]
    fn the_guard_has_its_own_chains_and_ports() {
        // Named constants rather than inline strings, so the report and the
        // kernel command cannot drift apart.
        assert_eq!(CHAIN, "LANDSCAPE_DNS_GUARD");
        assert_eq!(HIJACK_CHAIN, "LANDSCAPE_DNS_HIJACK");
        assert_eq!(TABLE, "mangle");
        assert_eq!(NAT_TABLE, "nat");
        assert_eq!(HOOK, "PREROUTING");
        assert_eq!(DOT_DOQ_PORT, "853");
        assert_eq!(PLAINTEXT_DNS_PORT, "53");
        assert_eq!(RESOLVER_PORT, "53");
        assert_eq!(DOH_PORT, "443");
    }

    #[test]
    fn the_config_flattens_without_losing_the_switches() {
        let config = DnsGuardConfig {
            enable: true,
            lan_iface: "br-lan".into(),
            doh_block_ips: vec!["1.1.1.1".parse().unwrap()],
            exempt: vec![DnsGuardExempt {
                client: "192.168.1.201".parse().unwrap(),
                destination: "223.5.5.5".parse().unwrap(),
                protocol: DnsGuardProtocol::Both,
                port: 853,
            }],
            drop_fragments: false,
            plaintext_tcp: true,
            drop_unclassified: true,
        };
        let spec = GuardSpec::from_config(&config);
        assert!(spec.enabled);
        assert_eq!(spec.lan_iface, "br-lan");
        assert_eq!(spec.doh_block.len(), 1);
        assert_eq!(spec.exempt.len(), 1);
        assert!(!spec.drop_fragments);
        assert!(spec.drop_unclassified);
        assert!(spec.plaintext_tcp);

        // The datapath half must see exactly what the netfilter half was given.
        let dp = spec.dataplane_spec();
        assert!(dp.enabled);
        assert_eq!(dp.doh_block, spec.doh_block);
        assert_eq!(dp.exempt, spec.exempt);
        assert_eq!(dp.drop_fragments, spec.drop_fragments);
        assert_eq!(dp.drop_unclassified, spec.drop_unclassified);
        assert_eq!(dp.plaintext_tcp, spec.plaintext_tcp);
    }

    #[test]
    fn a_protocol_covers_the_transports_it_says_it_does() {
        assert_eq!(DnsGuardProtocol::Tcp.as_iptables_protocols(), vec!["tcp"]);
        assert_eq!(DnsGuardProtocol::Udp.as_iptables_protocols(), vec!["udp"]);
        assert_eq!(DnsGuardProtocol::Both.as_iptables_protocols(), vec!["tcp", "udp"]);
        // ... and the datapath half agrees, using protocol numbers where
        // netfilter uses names.
        assert_eq!(DnsGuardProtocol::Tcp.as_l4_protocols(), vec![6]);
        assert_eq!(DnsGuardProtocol::Udp.as_l4_protocols(), vec![17]);
        assert_eq!(DnsGuardProtocol::Both.as_l4_protocols(), vec![6, 17]);
    }

    #[test]
    fn counters_start_at_zero_rather_than_being_absent() {
        // Zero is a real reading (nothing has been handed off), so the status must
        // not need a separate "unknown" state to say it.
        assert_eq!(DnsGuardCounters::default(), DnsGuardCounters::default());
        let status = DnsGuardStatus::default();
        assert_eq!(status.counters.handoff_dot, 0);
        assert!(status.dataplane_error.is_none());
    }
}
