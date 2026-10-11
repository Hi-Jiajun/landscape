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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

/// The IPv4 counterpart: the LAN interface's own addresses, which are the ones a
/// client already treats as its gateway.
///
/// Loopback and the link-local range are excluded for the same reason as IPv6:
/// neither can be the source of an ICMP error a client would accept, and
/// 169.254.0.0/16 in particular means "this link has no configuration".
fn is_copyable_source4(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified(),
        IpAddr::V6(_) => false,
    }
}

/// The IPv4 addresses the exception link uses for its own two ends.
///
/// Deliberately out of the link-local range: this is a point-to-point pair inside
/// one host, neither end is ever routed to, and the range exists for exactly
/// "this link, no configuration of its own". The client's traffic never sees
/// either one - what it sees as the error's source is a copy of the LAN's own
/// gateway address, never these.
const CHAMBER_LINK_MAIN4: Ipv4Addr = Ipv4Addr::new(169, 254, 255, 1);
const CHAMBER_LINK_SIDE4: Ipv4Addr = Ipv4Addr::new(169, 254, 255, 2);

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
    /// The chamber's IPv4 address on the veth, for the neighbour rewrite.
    pub nexthop4: Ipv4Addr,
    /// The LAN IPv4 addresses the chamber may speak with - the addresses a client
    /// already has as its default gateway.
    pub sources4: Vec<Ipv4Addr>,
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
        let mut sources4 =
            [[0u8; 4]; landscape_common::wan_service::mtu_chamber::MTU_CHAMBER_MAX_SOURCES];
        let mut count4 = 0usize;
        for source in &self.sources4 {
            if count4 >= sources4.len() {
                break;
            }
            sources4[count4] = source.octets();
            count4 += 1;
        }
        MtuChamberWiring {
            veth_ifindex: self.veth_main_ifindex,
            source_count: count as u32,
            ttl_ms,
            burst,
            nexthop: self.chamber_link_local.octets(),
            sources,
            nexthop4: self.nexthop4.octets(),
            sources4,
            source_count4: count4 as u32,
        }
    }

    /// How the chamber is described in the log and in the leak report.
    pub fn describe(&self) -> String {
        format!(
            "netns {} on {} (advertising mtu {}), speaking as {}{}{}, divert target {}",
            self.ns,
            self.wan_iface,
            self.wan_mtu,
            self.sources.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", "),
            if self.sources.is_empty() || self.sources4.is_empty() { "" } else { " / " },
            self.sources4.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", "),
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

/// The IPv4 addresses the chamber has to be able to speak as.
///
/// Missing IPv4 is not an error the way missing IPv6 is: a LAN can legitimately
/// be IPv6-only, and the chamber simply does not answer IPv4 errors there. The
/// datapath agrees - it will not divert a family the chamber has no address for.
async fn collect_sources4(iface_names: &[String]) -> Vec<(Ipv4Addr, u8)> {
    let mut out = Vec::new();
    for name in iface_names {
        for info in addresses_by_iface_name(name.clone()).await {
            if let IpAddr::V4(v4) = info.address
                && is_copyable_source4(&info.address)
            {
                out.push((v4, info.prefix_len));
            }
        }
    }
    out.sort_by_key(|(address, prefix)| (address.octets(), *prefix));
    out.dedup();
    out
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
    let by_prefix4 = collect_sources4(&settings.lan_iface_names).await;
    let sources4: Vec<Ipv4Addr> = by_prefix4.iter().map(|(a, _)| *a).collect();

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

        // The addresses the chamber speaks as go on **before** the link is up.
        //
        // Adding an address to an interface that is already up makes the kernel
        // announce it, and an announcement of the LAN's own gateway address on this
        // link is exactly the claim the design must never make. Adding them while
        // the link is down, then bringing it up with `arp_notify` off, is what
        // keeps the copies silent. The two ends also learn each other statically,
        // so nothing needs to be discovered either.
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
        for (address, prefix) in &by_prefix4 {
            ip_ns(
                &ns,
                &[
                    "-4",
                    "addr",
                    "add",
                    &format!("{address}/{prefix}"),
                    "dev",
                    &veth_chamber,
                    "noprefixroute",
                ],
            )
            .await?;
        }

        ip_ns(&ns, &["link", "set", &veth_chamber, "up"]).await?;
        sysctl_in(&ns, &format!("net.ipv4.conf.{veth_chamber}.arp_notify"), "0").await?;
        sysctl_in(&ns, &format!("net.ipv4.conf.{veth_chamber}.arp_ignore"), "1").await?;
        sysctl_in(&ns, &format!("net.ipv4.conf.{veth_chamber}.arp_announce"), "2").await?;

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

        // The IPv4 neighbours, statically for the same reason: the main
        // namespace's INPUT policy would drop an ARP reply arriving on this veth
        // exactly as it drops a neighbour advertisement, and an unresolved
        // neighbour is a divert that goes nowhere.
        let nexthop4 = *by_prefix4.first().map(|(address, _)| address).ok_or_else(|| {
            "the chamber has no IPv4 address to speak as, so it cannot answer an IPv4 error"
                .to_string()
        })?;
        // This link's own two ends, and the static ARP that lets each find the
        // other without a single frame of address resolution crossing it.
        ip(&["-4", "addr", "add", &format!("{CHAMBER_LINK_MAIN4}/32"), "dev", &veth_main]).await?;
        ip_ns(
            &ns,
            &["-4", "addr", "add", &format!("{CHAMBER_LINK_SIDE4}/32"), "dev", &veth_chamber],
        )
        .await?;
        // A /32 is not a subnet, so IPv4 has to be told explicitly that the peer
        // really is on this link before it will accept it as a gateway - unlike
        // IPv6, whose link-local addresses are on-link by construction. Measured
        // on 2026-10-07: without this, the client's prefix route is refused with
        // "Nexthop has invalid gateway" and the whole chamber stays down, which is
        // the read-back doing its job rather than a silent half-built chamber.
        ip_ns(
            &ns,
            &[
                "-4",
                "route",
                "add",
                &format!("{CHAMBER_LINK_MAIN4}/32"),
                "dev",
                &veth_chamber,
                "scope",
                "link",
            ],
        )
        .await?;
        ip_ns(
            &ns,
            &[
                "-4",
                "neigh",
                "replace",
                &CHAMBER_LINK_MAIN4.to_string(),
                "lladdr",
                &main_mac,
                "dev",
                &veth_chamber,
                "nud",
                "permanent",
            ],
        )
        .await?;
        ip(&[
            "-4",
            "neigh",
            "replace",
            &CHAMBER_LINK_SIDE4.to_string(),
            "lladdr",
            &chamber_mac,
            "dev",
            &veth_main,
            "nud",
            "permanent",
        ])
        .await?;
        // What the datapath's divert resolves: the next hop is the chamber's copy
        // of the LAN address, so the main namespace needs its link address for it.
        ip(&[
            "-4",
            "neigh",
            "replace",
            &nexthop4.to_string(),
            "lladdr",
            &chamber_mac,
            "dev",
            &veth_main,
            "nud",
            "permanent",
        ])
        .await?;

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

        // The IPv4 route back to the client, through the main namespace, by
        // prefix. Same shape as the IPv6 one: the error must leave by the link the
        // admitted packet arrived on, not straight out of this one.
        let mut routed4: Vec<(Ipv4Addr, u8)> = Vec::new();
        for (address, prefix) in &by_prefix4 {
            if routed4.iter().any(|(a, p)| a == address && p == prefix) {
                continue;
            }
            let network = network_of4(*address, *prefix);
            ip_ns(
                &ns,
                &[
                    "-4",
                    "route",
                    "add",
                    &format!("{network}/{prefix}"),
                    "via",
                    &CHAMBER_LINK_MAIN4.to_string(),
                    "dev",
                    &veth_chamber,
                    "metric",
                    "1",
                ],
            )
            .await?;
            routed4.push((network, *prefix));
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
        // The IPv4 default, and a documentation-range address on the dummy so the
        // route is unambiguously usable. That address is inside this namespace
        // only: nothing routes to it, and the OUTPUT policy below would refuse
        // anything but the error even if something tried.
        ip_ns(&ns, &["-4", "addr", "add", "192.0.2.1/32", "dev", &egress]).await?;
        ip_ns(&ns, &["-4", "route", "add", "default", "dev", &egress, "metric", "1024"]).await?;

        // The things that make it an error generator and not a router, for both
        // families. Forwarding has to be on: the error comes from the forwarding
        // path, and with it off the kernel emits nothing at all.
        sysctl_in(&ns, "net.ipv6.conf.all.forwarding", "1").await?;
        sysctl_in(&ns, "net.ipv4.ip_forward", "1").await?;
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

        // The IPv4 half of the same three rules: the fragmentation-needed error
        // may leave, and nothing else may. The peer rule the IPv6 side needs has
        // no IPv4 counterpart because the neighbours are static - ARP is not a
        // packet iptables decides on, and nothing here needs to resolve anything.
        in_ns(&ns, "iptables", &["-F", "FORWARD"]).await?;
        in_ns(&ns, "iptables", &["-P", "FORWARD", "DROP"]).await?;
        in_ns(&ns, "iptables", &["-F", "OUTPUT"]).await?;
        in_ns(
            &ns,
            "iptables",
            &[
                "-A",
                "OUTPUT",
                "-o",
                &veth_chamber,
                "-p",
                "icmp",
                "--icmp-type",
                "3",
                "-j",
                "ACCEPT",
            ],
        )
        .await?;
        in_ns(&ns, "iptables", &["-A", "OUTPUT", "-j", "DROP"]).await?;
        in_ns(&ns, "iptables", &["-P", "OUTPUT", "DROP"]).await?;

        // The addresses the read-back asserts the static neighbours against.
        Ok::<(Ipv6Addr, Ipv6Addr, Ipv4Addr), String>((chamber_ll, main_ll, nexthop4))
    }
    .await;

    // Any failure so far leaves a namespace behind; drop it before returning.
    let (chamber_link_local, main_link_local, nexthop4) = match build {
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

    // The IPv4 half of every one of those assertions, made again rather than
    // inferred from the IPv6 result: the same link carries both families but they
    // fail differently, and "the v6 side works" says nothing about whether the v4
    // neighbours resolved.
    let main_neigh4 = ip(&["-4", "neigh", "show", "dev", &veth_main]).await.unwrap_or_default();
    if !main_neigh4.contains(&nexthop4.to_string()) || !main_neigh4.contains("PERMANENT") {
        problems.push(format!(
            "the chamber's IPv4 address is not a permanent neighbour on {veth_main}, so an IPv4 \
             divert would have nowhere to send a packet: {main_neigh4:?}"
        ));
    }
    let chamber_neigh4 =
        in_ns_lenient(&ns, "ip", &["-4", "neigh", "show", "dev", &veth_chamber]).await;
    if !chamber_neigh4.contains(&CHAMBER_LINK_MAIN4.to_string())
        || !chamber_neigh4.contains("PERMANENT")
    {
        problems.push(format!(
            "{CHAMBER_LINK_MAIN4} is not a permanent neighbour in {ns}, so an IPv4 error could \
             not be sent back: {chamber_neigh4:?}"
        ));
    }

    let addr4_text = in_ns_lenient(&ns, "ip", &["-4", "addr", "show", "dev", &veth_chamber]).await;
    let present4 =
        by_prefix4.iter().filter(|(address, _)| addr4_text.contains(&address.to_string())).count();
    if present4 != by_prefix4.len() {
        problems.push(format!(
            "only {present4} of {} LAN IPv4 addresses are on {veth_chamber}",
            by_prefix4.len()
        ));
    }

    let forwarding4 = in_ns_lenient(&ns, "sysctl", &["-n", "net.ipv4.ip_forward"]).await;
    if forwarding4.trim() != "1" {
        problems.push(format!(
            "net.ipv4.ip_forward is {:?} in {ns}; without it nothing is emitted for IPv4 at all",
            forwarding4.trim()
        ));
    }

    let route4_text = in_ns_lenient(&ns, "ip", &["-4", "route", "show"]).await;
    if !route4_text.contains(&format!("default dev {egress}")) {
        problems.push(format!(
            "no IPv4 default route out {egress}: the IPv4 egress MTU check would never run"
        ));
    }
    for (address, prefix) in &by_prefix4 {
        let network = network_of4(*address, *prefix);
        if !route4_text.contains(&format!("{network}/{prefix} via")) {
            problems.push(format!(
                "no IPv4 route for {network}/{prefix} back through the main namespace"
            ));
        }
    }

    let rules4 = in_ns_lenient(&ns, "iptables", &["-S"]).await;
    for (what, needle) in [
        ("IPv4 FORWARD policy DROP", "-P FORWARD DROP"),
        ("IPv4 OUTPUT policy DROP", "-P OUTPUT DROP"),
        ("the fragmentation-needed error may leave", "--icmp-type 3"),
    ] {
        if !rules4.contains(needle) {
            problems.push(format!("{what} is not in place ({needle})"));
        }
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
        nexthop4,
        sources4,
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

/// The network address of `address/prefix`, for IPv4.
fn network_of4(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let bits = u32::from(address);
    let mask = if prefix >= 32 { u32::MAX } else { !(u32::MAX >> prefix) };
    Ipv4Addr::from(bits & mask)
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
    fn only_addresses_that_can_source_an_ipv4_error_are_copied() {
        // The LAN's gateway address is the one a client expects its error from.
        assert!(is_copyable_source4(&IpAddr::V4("192.168.1.1".parse().unwrap())));
        assert!(is_copyable_source4(&IpAddr::V4("10.0.0.1".parse().unwrap())));
        // Neither of these can be the source of an error about a global
        // destination, and 169.254 in particular means "this link has no
        // configuration" - which is this chamber's own link.
        assert!(!is_copyable_source4(&IpAddr::V4("127.0.0.1".parse().unwrap())));
        assert!(!is_copyable_source4(&IpAddr::V4("169.254.1.1".parse().unwrap())));
        assert!(!is_copyable_source4(&IpAddr::V4("0.0.0.0".parse().unwrap())));
        assert!(!is_copyable_source4(&IpAddr::V6("fd10::1".parse().unwrap())));
    }

    #[test]
    fn an_ipv4_prefix_route_is_computed_from_the_address_not_guessed() {
        let address: Ipv4Addr = "192.168.1.1".parse().unwrap();
        assert_eq!(network_of4(address, 24), "192.168.1.0".parse::<Ipv4Addr>().unwrap());
        // A /32 host route is its own network, and /0 is everything.
        assert_eq!(network_of4(address, 32), address);
        assert_eq!(network_of4(address, 0), Ipv4Addr::UNSPECIFIED);
        let wide: Ipv4Addr = "10.1.2.3".parse().unwrap();
        assert_eq!(network_of4(wide, 8), "10.0.0.0".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn the_exception_link_keeps_its_own_addresses_out_of_the_clients_subnet() {
        // The two ends of the exception link must not sit in a client's subnet:
        // if they did, the copied gateway address and the link's own would be
        // ambiguous, and a client could have a route to a router address that is
        // not the router.
        for address in [CHAMBER_LINK_MAIN4, CHAMBER_LINK_SIDE4] {
            assert!(address.is_link_local(), "{address} should stay in 169.254.0.0/16");
        }
        assert_ne!(CHAMBER_LINK_MAIN4, CHAMBER_LINK_SIDE4);
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
