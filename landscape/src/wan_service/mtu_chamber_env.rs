//! The exception namespace that produces IPv6 Packet Too Big errors.
//!
//! The datapath forwards with `bpf_redirect`, so the kernel's forwarding path -
//! the only place that error is generated - never runs for client traffic, and a
//! packet over the egress MTU disappears without a word. Turning forwarding on
//! in the main namespace would give the kernel a general forwarding path (and a
//! second, uncontrolled way for a packet to travel), which is why this is a
//! namespace of its own instead: it exists only to run that one check.
//!
//! What it is, in the terms the design has to hold to:
//!
//! * **not a router.** It has no route to a real network, one veth back to the
//!   main namespace, and a dummy whose only purpose is to carry the egress's
//!   MTU. `FORWARD` is DROP; `OUTPUT` is DROP except for neighbour discovery
//!   with its peer and the Packet Too Big itself. An admitted packet that was
//!   somehow forwarded would find nowhere to go;
//! * **it speaks as the router.** It carries copies of the LAN interfaces' IPv6
//!   addresses, so the kernel picks the error's source address by the same
//!   RFC 6724 rules a real router would, per client. Measured on 2026-10-07:
//!   with the veth's own address instead, a client gets no usable error;
//! * **it cannot claim those addresses out loud.** Only neighbour discovery
//!   addressed to the peer's link-local address may leave, so the copies are
//!   never advertised on the wire and the main namespace never sees a claim on
//!   an address it owns;
//! * **MTU bound to the egress.** The dummy's MTU is this WAN interface's own
//!   MTU, read at setup, so the number in the error is the number that was
//!   verified rather than a constant that happens to be right today.
//!
//! Every step is done with `ip` and read back afterwards: the commands say what
//! was intended, the read-back is what is trusted, and a namespace that does not
//! read back as intended is torn down rather than enabled.

use std::net::{IpAddr, Ipv6Addr};

use landscape_common::wan_service::mtu_chamber::{MtuChamberSettings, MtuChamberWiring};

use crate::netlink::address::{addresses_by_iface_name, get_existing_linklocal};
use crate::netlink::link::get_iface_by_name;

/// Which link-local scope a copy of a LAN address must not have: the chamber has
/// its own link-local addresses, and a link-local cannot be the source of an
/// error about a global destination anyway.
fn is_copyable_source(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unicast_link_local() && !v6.is_unspecified(),
        IpAddr::V4(_) => false,
    }
}

/// Interface names have 15 bytes including the terminator.
fn name_within_limit(name: &str) -> String {
    name.chars().take(15).collect()
}

/// The namespace and its interfaces, as they exist on the host.
#[derive(Debug, Clone)]
pub struct MtuChamberEnv {
    pub ns: String,
    pub veth_main: String,
    pub veth_chamber: String,
    pub egress: String,
    pub wan_iface: String,
    pub wan_mtu: u16,
    /// The main-namespace end of the veth: the divert target.
    pub veth_main_ifindex: u32,
    /// The chamber's own link-local address, used only as a neighbour for the
    /// handover - never as the source of an error.
    pub chamber_link_local: Ipv6Addr,
    /// The LAN addresses the chamber may speak with.
    pub sources: Vec<Ipv6Addr>,
}

/// The chamber's shape, derived from the live interfaces.
///
/// This is what has to stay in step with reality, so it is also what the
/// reconcile compares: the egress's effective MTU, and the set of addresses the
/// chamber has to be able to speak with. Both are read from the kernel on every
/// pass rather than remembered, because both change under this code - the WAN
/// device is 1500 until PPPoE sets it, and a LAN prefix changes when the ISP
/// delegates a different one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtuChamberProbe {
    /// The number to compare against and to advertise.
    pub effective_mtu: u16,
    /// The device's own MTU, kept so the two can be logged together.
    pub device_mtu: u16,
    /// The configured clamp, the other input to the minimum.
    pub clamp_size: u16,
    /// The addresses a chamber would have to speak with. `None` when no chamber
    /// is configured: this is the only field that needs IPv6 to exist, and the
    /// stage that counts does not.
    pub sources: Option<Vec<Ipv6Addr>>,
}

impl MtuChamberEnv {
    /// The datapath-facing wiring for a chamber that is up and verified.
    pub fn wiring(&self, ttl_ms: u32, burst: u32) -> MtuChamberWiring {
        let mut sources =
            [[0u8; 16]; landscape_common::wan_service::mtu_chamber::MTU_CHAMBER_MAX_SOURCES];
        let mut count = 0usize;
        for source in &self.sources {
            if count >= sources.len() {
                break;
            }
            sources[count] = source.octets();
            count += 1;
        }
        MtuChamberWiring {
            veth_ifindex: self.veth_main_ifindex,
            source_count: count as u32,
            ttl_ms,
            burst,
            nexthop: self.chamber_link_local.octets(),
            sources,
        }
    }

    /// How the chamber is described in the log and in the leak report.
    pub fn describe(&self) -> String {
        format!(
            "netns {} on {} (advertising mtu {}), speaking as {}, divert target {}",
            self.ns,
            self.wan_iface,
            self.wan_mtu,
            self.sources.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", "),
            self.veth_main_ifindex
        )
    }
}

impl Drop for MtuChamberEnv {
    fn drop(&mut self) {
        // Synchronous and best effort: this is the abort path (a cancelled task
        // cannot await), and a leftover namespace must not survive into the next
        // start. `bring_up` also removes any leftover before creating its own.
        let _ = std::process::Command::new("ip").args(["netns", "del", &self.ns]).output();
    }
}

// ---------------------------------------------------------------------------
// Shell plumbing
// ---------------------------------------------------------------------------

async fn sh(program: &str, args: &[String]) -> Result<String, String> {
    let out = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("{program} {}: {e}", args.join(" ")))?;
    if !out.status.success() {
        return Err(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

async fn ip(args: &[&str]) -> Result<String, String> {
    let owned: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    sh("ip", &owned).await
}

/// `ip` in the chamber, without the caller having to remember the flag.
async fn ip_ns(ns: &str, args: &[&str]) -> Result<String, String> {
    let mut full = vec!["-n".to_string(), ns.to_string()];
    full.extend(args.iter().map(|a| a.to_string()));
    sh("ip", &full).await
}

async fn in_ns(ns: &str, program: &str, args: &[&str]) -> Result<String, String> {
    let mut full =
        vec!["netns".to_string(), "exec".to_string(), ns.to_string(), program.to_string()];
    full.extend(args.iter().map(|a| a.to_string()));
    // `ip netns exec` is what makes a bare program run inside the namespace.
    sh("ip", &full).await
}

async fn in_ns_lenient(ns: &str, program: &str, args: &[&str]) -> String {
    in_ns(ns, program, args).await.unwrap_or_default()
}

async fn sysctl_in(ns: &str, key: &str, value: &str) -> Result<(), String> {
    in_ns(ns, "sysctl", &["-qw", &format!("{key}={value}")]).await.map(|_| ())
}

/// The link address of an interface in the main namespace.
async fn read_mac(iface: &str) -> Result<String, String> {
    let text = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .map_err(|e| format!("read {iface}'s address: {e}"))?;
    let mac = text.trim().to_string();
    if mac.is_empty() { Err(format!("{iface} has no link address")) } else { Ok(mac) }
}

/// The link address of an interface inside a namespace.
async fn read_mac_in_ns(ns: &str, iface: &str) -> Result<String, String> {
    let text = ip_ns(ns, &["-o", "link", "show", iface]).await?;
    let mac = text
        .split_whitespace()
        .skip_while(|field| *field != "link/ether")
        .nth(1)
        .ok_or_else(|| format!("{iface} in {ns} has no link/ether in {:?}", text.trim()))?;
    Ok(mac.to_string())
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

/// The interface's own L3 MTU: the number the egress MTU stage compares against
/// and the number the chamber's stand-in egress is given. Read from the kernel
/// rather than configured, so the two can never disagree.
pub async fn read_iface_mtu(iface: &str) -> Option<u16> {
    let path = format!("/sys/class/net/{iface}/mtu");
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Read the LAN addresses the chamber has to be able to speak as.
async fn collect_sources(iface_names: &[String]) -> Result<Vec<(Ipv6Addr, u8)>, String> {
    let mut out = Vec::new();
    for name in iface_names {
        let addresses = addresses_by_iface_name(name.clone()).await;
        if addresses.is_empty() {
            return Err(format!(
                "{name} has no addresses; the chamber needs the LAN's own IPv6 addresses, and without them a client would not accept the error"
            ));
        }
        for info in addresses {
            if let IpAddr::V6(v6) = info.address
                && is_copyable_source(&info.address)
            {
                out.push((v6, info.prefix_len));
            }
        }
    }
    if out.is_empty() {
        return Err(format!("none of {iface_names:?} has a global or unique-local IPv6 address"));
    }
    out.sort_by_key(|(address, prefix)| (address.octets(), *prefix));
    out.dedup();
    Ok(out)
}

/// Parse `inet6 fe80::.../64` out of `ip -n <ns> -6 addr show dev <iface> scope link`.
fn parse_link_local(text: &str) -> Option<Ipv6Addr> {
    for line in text.lines() {
        if !line.trim_start().starts_with("inet6 fe80:") {
            continue;
        }
        let field = line.split_whitespace().find(|f| f.starts_with("fe80:"))?;
        return field.split('/').next()?.parse().ok();
    }
    None
}

/// Derive the chamber's shape from the live interfaces.
///
/// Read fresh every pass, because the two inputs both move: the WAN device is
/// 1500 until PPPoE has set it to the negotiated MTU, and the LAN's global
/// prefix changes when the ISP delegates a different one. An earlier version of
/// this read both once at startup and latched whatever a restart happened to look
/// like - measured on 2026-10-07, it came up advertising 1500 and speaking as one
/// address, which is exactly the wrong number and an incomplete set.
///
/// The MTU is the **minimum** of the device's own and the configured clamp. The
/// clamp is already this system's statement of how large a packet the egress
/// carries - it is what the MSS clamp enforces - so the stage and the chamber
/// must not disagree with it; and the device's number is the link's own, so the
/// error can never advertise more than either. That makes the transient 1500
/// harmless rather than something to wait out.
pub async fn probe(
    wan_iface: &str,
    settings: Option<&MtuChamberSettings>,
    clamp_size: u16,
) -> Result<MtuChamberProbe, String> {
    let device_mtu = read_iface_mtu(wan_iface)
        .await
        .ok_or_else(|| format!("cannot read the MTU of {wan_iface}"))?;
    // The sources are only needed when there is a chamber to speak as them, and
    // reading them is what fails on a LAN with no IPv6 at all. Without a chamber
    // that failure must not take the counters down with it: the counters are the
    // evidence for whether the remedy is worth having, so they outlive it.
    let sources = match settings {
        Some(settings) => Some(
            collect_sources(&settings.lan_iface_names)
                .await?
                .into_iter()
                .map(|(address, _)| address)
                .collect(),
        ),
        None => None,
    };
    Ok(MtuChamberProbe {
        effective_mtu: device_mtu.min(clamp_size),
        device_mtu,
        clamp_size,
        sources,
    })
}

/// Bring the chamber up, or leave nothing behind.
///
/// The result is read back from the kernel, not assumed from the commands: a
/// namespace that did not become what it was supposed to be is torn down and
/// reported, because the alternative is a divert target that silently eats the
/// packets it was supposed to answer.
pub async fn bring_up(
    wan_iface: &str,
    wan_ifindex: u32,
    settings: &MtuChamberSettings,
    probe: &MtuChamberProbe,
    sources: &[Ipv6Addr],
) -> Result<MtuChamberEnv, String> {
    settings.validate()?;

    // Taken from the probe rather than re-derived, so the number the stage
    // compares against, the number the dummy carries, and the number the error
    // advertises are one reading instead of three that can disagree.
    let wan_mtu = probe.effective_mtu;
    if sources.is_empty() {
        return Err(
            "the chamber needs at least one LAN address to speak as, and the probe found none"
                .to_string(),
        );
    }
    // Read only for the prefixes; the addresses themselves are the probe's, so
    // that the set the read-back checks is the set that was decided on.
    let by_prefix = collect_sources(&settings.lan_iface_names).await?;
    let sources: Vec<Ipv6Addr> = sources.to_vec();

    // Names carry the WAN interface's index so two WANs cannot collide, and stay
    // inside the 15-byte limit.
    let ns = name_within_limit(&format!("lsmtu{}", wan_ifindex));
    let veth_main = name_within_limit(&format!("lsm{}a", wan_ifindex));
    let veth_chamber = name_within_limit(&format!("lsm{}b", wan_ifindex));
    let egress = name_within_limit(&format!("lsm{}e", wan_ifindex));

    // A previous run that died without cleaning up would make `ip link add` fail
    // with a name collision; removing it first is the only way to be sure the
    // namespace that ends up running is the one this code configured.
    let _ = ip(&["netns", "del", &ns]).await;

    let build = async {
        ip(&["netns", "add", &ns]).await?;
        ip(&["link", "add", &veth_main, "type", "veth", "peer", "name", &veth_chamber]).await?;
        ip(&["link", "set", &veth_chamber, "netns", &ns]).await?;
        ip(&["link", "set", &veth_main, "up"]).await?;

        ip_ns(&ns, &["link", "set", "lo", "up"]).await?;
        ip_ns(&ns, &["link", "set", &veth_chamber, "up"]).await?;

        let chamber_ll = {
            let mut found = None;
            for _ in 0..10 {
                let text =
                    ip_ns(&ns, &["-6", "addr", "show", "dev", &veth_chamber, "scope", "link"])
                        .await
                        .unwrap_or_default();
                if let Some(ll) = parse_link_local(&text) {
                    found = Some(ll);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            found.ok_or_else(|| format!("{veth_chamber} did not get a link-local address"))?
        };

        let main_ll = {
            let mut found = None;
            for _ in 0..10 {
                if let Some(ll) = get_existing_linklocal(&veth_main) {
                    found = Some(ll);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            found.ok_or_else(|| format!("{veth_main} did not get a link-local address"))?
        };

        // The two ends learn each other's link address statically, so the main
        // namespace's firewall never has to admit this link and no neighbour
        // discovery crosses it.
        //
        // They cannot learn it the ordinary way: the main namespace's INPUT
        // policy is DROP with exceptions only for `lo` and the LAN, so a
        // neighbour advertisement arriving on this veth is dropped and both
        // neighbour tables sit at FAILED. Measured on 2026-10-07: the divert
        // reported every oversized packet as handed over, the chamber received
        // none of them, and the cause was the unresolved neighbour on this side.
        let main_mac = read_mac(&veth_main).await?;
        let chamber_mac = read_mac_in_ns(&ns, &veth_chamber).await?;
        ip(&[
            "-6",
            "neigh",
            "replace",
            &chamber_ll.to_string(),
            "lladdr",
            &chamber_mac,
            "dev",
            &veth_main,
            "nud",
            "permanent",
        ])
        .await?;
        ip_ns(
            &ns,
            &[
                "-6",
                "neigh",
                "replace",
                &main_ll.to_string(),
                "lladdr",
                &main_mac,
                "dev",
                &veth_chamber,
                "nud",
                "permanent",
            ],
        )
        .await?;

        // The addresses the chamber speaks as. `nodad` because the address is
        // already in use in the main namespace on the LAN link, and DAD here
        // would only produce a claim nobody asked for; `noprefixroute` because
        // the route back to the client must go through the main namespace, not
        // straight out of this link.
        for (address, prefix) in &by_prefix {
            ip_ns(
                &ns,
                &[
                    "-6",
                    "addr",
                    "add",
                    &format!("{address}/{prefix}"),
                    "dev",
                    &veth_chamber,
                    "nodad",
                    "noprefixroute",
                ],
            )
            .await?;
        }

        // Back to the client through the main namespace, by prefix.
        let mut routed: Vec<(Ipv6Addr, u8)> = Vec::new();
        for (address, prefix) in &by_prefix {
            if routed.iter().any(|(a, p)| a == address && p == prefix) {
                continue;
            }
            let network = network_of(*address, *prefix);
            ip_ns(
                &ns,
                &[
                    "-6",
                    "route",
                    "add",
                    &format!("{network}/{prefix}"),
                    "via",
                    &main_ll.to_string(),
                    "dev",
                    &veth_chamber,
                    "metric",
                    "1",
                ],
            )
            .await?;
            routed.push((network, *prefix));
        }

        // The stand-in for the real egress: it carries that egress's MTU, so the
        // kernel's forwarding check compares against the number this path was
        // authorised for. A dummy, not a blackhole: a blackhole never runs the
        // check at all.
        ip_ns(&ns, &["link", "add", &egress, "type", "dummy"]).await?;
        ip_ns(&ns, &["link", "set", &egress, "mtu", &wan_mtu.to_string()]).await?;
        ip_ns(&ns, &["link", "set", &egress, "up"]).await?;
        // Everything this namespace does not know about leaves by the dummy -
        // which goes nowhere - so the check runs and then the packet is gone. The
        // LAN prefixes above are more specific and keep their route.
        ip_ns(&ns, &["-6", "route", "add", "default", "dev", &egress, "metric", "1024"]).await?;

        // The three things that make it an error generator and not a router.
        sysctl_in(&ns, "net.ipv6.conf.all.forwarding", "1").await?;
        in_ns(&ns, "ip6tables", &["-F", "FORWARD"]).await?;
        in_ns(&ns, "ip6tables", &["-P", "FORWARD", "DROP"]).await?;

        // Emitting: neighbour discovery addressed to the peer, the Packet Too
        // Big, and nothing else. The peer rule is a /128 rather than the whole
        // link-local scope, so this namespace cannot talk to any other
        // link-local entity; the two neighbours are static, so in normal
        // operation not even that is used. The policy is what stops the copies of
        // the LAN addresses from being advertised on the wire as if this
        // namespace owned them.
        in_ns(&ns, "ip6tables", &["-F", "OUTPUT"]).await?;
        in_ns(
            &ns,
            "ip6tables",
            &["-A", "OUTPUT", "-o", &veth_chamber, "-d", &format!("{main_ll}/128"), "-j", "ACCEPT"],
        )
        .await?;
        in_ns(
            &ns,
            "ip6tables",
            &[
                "-A",
                "OUTPUT",
                "-o",
                &veth_chamber,
                "-p",
                "ipv6-icmp",
                "--icmpv6-type",
                "2",
                "-j",
                "ACCEPT",
            ],
        )
        .await?;
        in_ns(&ns, "ip6tables", &["-A", "OUTPUT", "-j", "DROP"]).await?;
        in_ns(&ns, "ip6tables", &["-P", "OUTPUT", "DROP"]).await?;

        // IPv4 has no purpose in here; close it the same way so that a stray
        // v4 packet cannot be forwarded either.
        in_ns(&ns, "iptables", &["-F", "FORWARD"]).await?;
        in_ns(&ns, "iptables", &["-P", "FORWARD", "DROP"]).await?;
        in_ns(&ns, "iptables", &["-P", "OUTPUT", "DROP"]).await?;

        // Both link-locals travel out of the build so the read-back can assert
        // the static neighbours that were installed from them.
        Ok::<(Ipv6Addr, Ipv6Addr), String>((chamber_ll, main_ll))
    }
    .await;

    // Any failure so far leaves a namespace behind; drop it before returning.
    let (chamber_link_local, main_link_local) = match build {
        Ok(lls) => lls,
        Err(e) => {
            let _ = ip(&["netns", "del", &ns]).await;
            return Err(e);
        }
    };

    // Read back. The commands above say what was intended; this is what is.
    let iface = get_iface_by_name(&veth_main)
        .await
        .ok_or_else(|| format!("{veth_main} does not exist after setup"))?;

    let mut problems: Vec<String> = Vec::new();

    let addr_text = in_ns_lenient(&ns, "ip", &["-6", "addr", "show", "dev", &veth_chamber]).await;
    let present = sources.iter().filter(|a| addr_text.contains(&a.to_string())).count();
    if present != sources.len() {
        problems.push(format!(
            "only {present} of {} LAN addresses are on {veth_chamber}",
            sources.len()
        ));
    }

    let route_text = in_ns_lenient(&ns, "ip", &["-6", "route", "show"]).await;
    if !route_text.contains(&format!("default dev {egress}")) {
        problems
            .push(format!("no default route out {egress}: the egress MTU check would never run"));
    }
    for (address, prefix) in &by_prefix {
        let network = network_of(*address, *prefix);
        if !route_text.contains(&format!("{network}/{prefix} via")) {
            problems
                .push(format!("no route for {network}/{prefix} back through the main namespace"));
        }
    }

    let forwarding = in_ns_lenient(&ns, "sysctl", &["-n", "net.ipv6.conf.all.forwarding"]).await;
    if forwarding.trim() != "1" {
        problems.push(format!(
            "net.ipv6.conf.all.forwarding is {:?} in {ns}; without it nothing is emitted at all",
            forwarding.trim()
        ));
    }

    let egress_mtu = ip_ns(&ns, &["-o", "link", "show", &egress])
        .await
        .unwrap_or_default()
        .split_whitespace()
        .skip_while(|f| *f != "mtu")
        .nth(1)
        .and_then(|v| v.parse::<u16>().ok());
    if egress_mtu != Some(wan_mtu) {
        problems.push(format!(
            "{egress} has MTU {egress_mtu:?}, not the egress's {wan_mtu}: the error would advertise a number this path never verified"
        ));
    }

    let rules = in_ns_lenient(&ns, "ip6tables", &["-S"]).await;
    for (what, needle) in [
        ("FORWARD policy DROP", "-P FORWARD DROP"),
        ("OUTPUT policy DROP", "-P OUTPUT DROP"),
        ("the Packet Too Big may leave", "--icmpv6-type 2"),
    ] {
        if !rules.contains(needle) {
            problems.push(format!("{what} is not in place ({needle})"));
        }
    }

    // The neighbours are the one part of this that failed silently in the field:
    // the divert counted every packet as handed over while the chamber received
    // none, because the main namespace's INPUT policy had dropped the neighbour
    // advertisement and the entry was FAILED. A static entry is what removes the
    // exchange, and this is what proves it is there.
    let main_neigh = ip(&["-6", "neigh", "show", "dev", &veth_main]).await.unwrap_or_default();
    if !main_neigh.contains(&chamber_link_local.to_string()) || !main_neigh.contains("PERMANENT") {
        problems.push(format!(
            "the chamber's link-local address is not a permanent neighbour on {veth_main}, so \
             the divert would have nowhere to send a packet: {main_neigh:?}"
        ));
    }
    let chamber_neigh =
        in_ns_lenient(&ns, "ip", &["-6", "neigh", "show", "dev", &veth_chamber]).await;
    if !chamber_neigh.contains(&main_link_local.to_string()) || !chamber_neigh.contains("PERMANENT")
    {
        problems.push(format!(
            "the main namespace's link-local address is not a permanent neighbour in {ns}, so no \
             error could be sent back: {chamber_neigh:?}"
        ));
    }

    if !problems.is_empty() {
        let _ = ip(&["netns", "del", &ns]).await;
        return Err(format!("the chamber did not come up as intended: {}", problems.join("; ")));
    }

    Ok(MtuChamberEnv {
        ns,
        veth_main,
        veth_chamber,
        egress,
        wan_iface: wan_iface.to_string(),
        wan_mtu,
        veth_main_ifindex: iface.index,
        chamber_link_local,
        sources,
    })
}

/// The network address of `address/prefix`.
fn network_of(address: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    if prefix == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    let bits = u128::from(address);
    let mask = if prefix >= 128 { u128::MAX } else { !(u128::MAX >> prefix) };
    Ipv6Addr::from(bits & mask)
}

/// The interface names a chamber for `wan_ifindex` uses, for teardown-time checks.
pub fn chamber_names(wan_ifindex: u32) -> (String, String, String, String) {
    (
        name_within_limit(&format!("lsmtu{}", wan_ifindex)),
        name_within_limit(&format!("lsm{}a", wan_ifindex)),
        name_within_limit(&format!("lsm{}b", wan_ifindex)),
        name_within_limit(&format!("lsm{}e", wan_ifindex)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_addresses_that_can_source_a_global_error_are_copied() {
        assert!(is_copyable_source(&IpAddr::V6("fd10:1667:7678:1::1".parse().unwrap())));
        assert!(is_copyable_source(&IpAddr::V6("240e:398:adf3:9132::1".parse().unwrap())));
        // A link-local cannot be the source of an error about a global
        // destination, and the chamber generates its own anyway.
        assert!(!is_copyable_source(&IpAddr::V6("fe80::280:ff:fe00:16".parse().unwrap())));
        assert!(!is_copyable_source(&IpAddr::V6("::1".parse().unwrap())));
        assert!(!is_copyable_source(&IpAddr::V4("192.168.1.1".parse().unwrap())));
    }

    #[test]
    fn names_stay_inside_the_kernel_limit() {
        for name in [
            name_within_limit(&format!("lsmtu{}", 999999)),
            chamber_names(12345).0,
            chamber_names(12345).1,
            chamber_names(12345).2,
            chamber_names(12345).3,
        ] {
            assert!(name.len() <= 15, "{name} is {} bytes", name.len());
        }
    }

    #[test]
    fn a_prefix_route_is_computed_from_the_address_not_guessed() {
        let address: Ipv6Addr = "240e:398:adf3:9132::1".parse().unwrap();
        assert_eq!(network_of(address, 64), "240e:398:adf3:9132::".parse::<Ipv6Addr>().unwrap());
        let ula: Ipv6Addr = "fd10:1667:7678:1::1".parse().unwrap();
        assert_eq!(network_of(ula, 64), "fd10:1667:7678:1::".parse::<Ipv6Addr>().unwrap());
        // A /128 host route is its own network.
        assert_eq!(network_of(address, 128), address);
        assert_eq!(network_of(address, 0), Ipv6Addr::UNSPECIFIED);
    }

    #[test]
    fn the_link_local_is_parsed_from_what_ip_actually_prints() {
        let text = "\
2: lsm2b: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP qlen 1000
    inet6 fe80::dc2c:34ff:fe9a:1b2c/64 scope link
       valid_lft forever preferred_lft forever";
        assert_eq!(
            parse_link_local(text),
            Some("fe80::dc2c:34ff:fe9a:1b2c".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(parse_link_local("no link local here"), None);
    }
}
