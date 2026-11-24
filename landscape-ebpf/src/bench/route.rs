//! Route data-plane per-packet cost across IPv4 and IPv6 LAN-to-WAN paths.
//!
//! Covers the core dimensions targeted for route optimization:
//!
//! - `baseline_v4` / `baseline_v6`: production packet scan + L3 context read +
//!   broadcast guard (`scan_route_packet` + `route4/6_read_context_from_scan`).
//! - `lan_cache_hit_v4` / `lan_cache_hit_v6`: steady-state LAN cache hit via
//!   `route4/6_search_cache_in_lan` (including the realistic `WAN_CACHE` miss
//!   that precedes `LAN_CACHE`), measured for both L3/PPPoE targets
//!   (`has_mac = 0`) and Ethernet targets (`has_mac = 1`, gateway `ip_mac`
//!   lookup + L2 MAC rewrite).
//! - `lan_cold_resolve_v4` / `lan_cold_resolve_v6`: uncached policy verdict +
//!   ECMP slot selection (`match_flow_id` MAC/IP LPM -> `flow_ip_map` LPM +
//!   `flow_dns_map` LRU hash priority arbitration -> `rt_slot_map` 16-slot
//!   hash), measured at both `small (8)` and `large (1024)` prefix/DNS rule
//!   counts, and for both IP-prefix hits and higher-priority DNS overrides.
//! - `lan_cold_full_v4` / `lan_cold_full_v6`: full uncached LAN-ingress lookup
//!   chain (`route4/6_search_cache_in_lan` miss + `rt4/6_lan_map` LPM check
//!   miss + `flow_verdict` + `rt_slot_map` pick) at 1024 entries.
//!
//! Run with:
//! `cargo test -p landscape-ebpf --lib --features bpf-test bench::route:: -- --ignored --nocapture`

use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use etherparse::PacketBuilder;
use landscape_common::{
    flow::{
        FlowMarkInfo, L4ProtoMatch,
        ip_mark::{IpConfig, IpMarkInfo, PortMarkInfo},
        mark::{FlowMark, FlowMarkAction},
    },
    net::MacAddr,
    sys_service::route_service::{RouteTargetInfo, WanRouteTarget},
};
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput, ProgramMut,
    skel::{OpenSkel as _, SkelBuilder as _},
};

use super::bench_route::{BenchRouteSkel, BenchRouteSkelBuilder};
use crate::{
    LANDSCAPE_IPV4_TYPE, LANDSCAPE_IPV6_TYPE,
    maps::{
        Route4ConnKey, Route6ConnKey, RouteConnValue,
        flow::types::FlowMatchKey,
        flow_dns::{create_flow_dns_inner_map_v4, create_flow_dns_inner_map_v6},
        flow_wanip::{
            create_inner_flow_match_map_v4, create_inner_flow_match_map_v6,
            set_flow_l4_rules_with_maps,
        },
        route::{
            cache::CONN_PIN_CACHE, replace_wan_route_slots_v4_with_map,
            replace_wan_route_slots_v6_with_map,
        },
    },
    tests::{
        helper::map::{
            LAN_CACHE, LAN_ROUTE_TYPE, WAN_CACHE, as_bytes, create_route4_cache_inner_map,
            create_route4_conn_inner_map, create_route6_cache_inner_map,
            create_route6_conn_inner_map, insert_ip_mac_v4, insert_ip_mac_v6,
            insert_route4_lan_entry, insert_route6_lan_entry, lookup_inner_map, put_rt4_cache_full,
            put_rt4_cache_value, put_rt6_cache_full, put_rt6_cache_value, seed_flow_match_mac,
        },
        isolated_pin_root,
        pkt::{simple_ipv4_tcp, simple_ipv6_tcp_syn},
    },
};

const REPEAT: u32 = 256;
const WARMUP_BATCHES: usize = 5;
const TIMING_BATCHES: usize = 50;

const SMALL_RULES: usize = 8;
const LARGE_RULES: usize = 1024;

const WAN1_IFINDEX: u32 = 11;
const WAN2_IFINDEX: u32 = 12;
const LAN_IFINDEX: u32 = 10;

/// Source flow matched via `flow_match_map` (subnet IP match overrides MAC match).
const MATCHED_SRC_FLOW_ID: u32 = 2;
const MAC_FALLBACK_FLOW_ID: u32 = 1;

/// Policy marks resolved by `route4/6_flow_verdict`:
/// - `MARK_CACHE_HIT` (0x0303): steady-state cached verdict (Flow 3)
/// - `MARK_IP_HIT`    (0x0304): LPM destination prefix hit (Flow 4, prio 200)
/// - `MARK_DNS_WIN`   (0x0305): DNS hash override (Flow 5, prio 50 <= 200)
/// - `MARK_DISTRACT`  (0x0302): ancestor/sibling distractor rules (Flow 2)
const MARK_CACHE_HIT: u32 = 0x0303;
const MARK_IP_HIT: u32 = 0x0304;
const MARK_DNS_WIN: u32 = 0x0305;
const MARK_L4_PORT_WIN: u32 = 0x0306;
const MARK_FIVETUPLE_HIT: u32 = 0x0307;
const MARK_DISTRACT: u32 = 0x0302;

/// `simple_ipv4_tcp` and `simple_ipv6_tcp_syn` emit source MAC `02:00:00:00:00:01`.
const PKT_SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const ROUTER_SRC_MAC: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01];
const GW_DST_MAC_STR: &str = "02:11:22:33:44:55";
const ROUTER_DEV_MAC_STR: &str = "02:aa:bb:cc:dd:ee";

const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(192, 168, 101, 10);
const HOT_PPPOE_DST_V4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
const HOT_ETH_DST_V4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 11);
const HOT_FIVETUPLE_DST_V4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 12);
const COLD_IP_DST_V4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 42);
const COLD_DNS_DST_V4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 84);
const WAN_GW_V4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);

fn client_v6() -> Ipv6Addr {
    Ipv6Addr::from_str("fd00:101::10").unwrap()
}

fn hot_pppoe_dst_v6() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:113::10").unwrap()
}

fn hot_eth_dst_v6() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:113::11").unwrap()
}

fn hot_fivetuple_dst_v6() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:113::12").unwrap()
}

fn cold_ip_dst_v6() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:abcd:1234::42").unwrap()
}

fn cold_dns_dst_v6() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:abcd:1234::84").unwrap()
}

fn wan_gw_v6() -> Ipv6Addr {
    Ipv6Addr::from_str("fe80::1").unwrap()
}

fn flow_mark_from_raw(raw: u32) -> FlowMark {
    let flow_id = (raw & 0xff) as u8;
    FlowMark::new(FlowMarkAction::Redirect, flow_id, false)
}

fn read_sink(map: &impl MapCore) -> u64 {
    let raw = map
        .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)
        .expect("read bench_sink")
        .expect("bench_sink entry missing");
    u64::from_ne_bytes(raw.as_slice().try_into().unwrap())
}

fn zero_sink(map: &impl MapCore) {
    map.update(&0u32.to_ne_bytes(), &0u64.to_ne_bytes(), MapFlags::ANY).expect("zero bench_sink");
}

fn sample_batch(prog: &ProgramMut<'_>, packet: &[u8]) -> u128 {
    let out = prog
        .test_run(ProgramInput {
            data_in: Some(packet),
            repeat: REPEAT,
            ..Default::default()
        })
        .expect("test_run");
    assert_eq!(out.return_value as i32, 0, "bench_route program returned non-OK");
    out.duration.as_nanos()
}

fn measure_checked(
    prog: &ProgramMut<'_>,
    packet: &[u8],
    expected_per_run: u64,
    sink: &impl MapCore,
) -> (u128, u128) {
    zero_sink(sink);
    for _ in 0..WARMUP_BATCHES {
        sample_batch(prog, packet);
    }
    assert_eq!(
        read_sink(sink),
        (WARMUP_BATCHES as u64 * REPEAT as u64) * expected_per_run,
        "sink mismatch: not every run hit the expected route path/mark"
    );

    let mut samples = Vec::with_capacity(TIMING_BATCHES);
    for _ in 0..TIMING_BATCHES {
        samples.push(sample_batch(prog, packet));
    }
    samples.sort_unstable();
    (*samples.first().unwrap(), samples[samples.len() / 2])
}

fn report(name: &str, (min, med): (u128, u128), base: (u128, u128)) {
    let per_min = min.saturating_sub(base.0) as f64;
    let per_med = med.saturating_sub(base.1) as f64;
    println!("{name:<28} per-pkt(min/med) {per_min:>7.2}/{per_med:>7.2} ns");
}

#[allow(clippy::field_reassign_with_default)]
fn seed_flow_match_subnet_v4(map: &impl MapCore, net: Ipv4Addr, prefix_len: u8, flow_id: u32) {
    let mut key = FlowMatchKey::default();
    key.prefixlen = 32 + u32::from(prefix_len);
    key.l3_protocol = LANDSCAPE_IPV4_TYPE;
    key.is_match_ip = 1;
    key.set_src_ipv4_be(net.to_bits());
    map.update(as_bytes(&key), as_bytes(&flow_id), MapFlags::ANY)
        .expect("insert v4 subnet flow_match entry");
}

#[allow(clippy::field_reassign_with_default)]
fn seed_flow_match_subnet_v6(map: &impl MapCore, net: Ipv6Addr, prefix_len: u8, flow_id: u32) {
    let mut key = FlowMatchKey::default();
    key.prefixlen = 32 + u32::from(prefix_len);
    key.l3_protocol = LANDSCAPE_IPV6_TYPE;
    key.is_match_ip = 1;
    key.set_src_ipv6(net);
    map.update(as_bytes(&key), as_bytes(&flow_id), MapFlags::ANY)
        .expect("insert v6 subnet flow_match entry");
}

/// Build `total` IPv4 destination LPM rules (`total >= 8`), nesting ancestor
/// prefixes (`/8` -> `/14` -> `/16` -> `/20` -> `/22` -> `/24` hit) and `/28`
/// child branches around `198.51.100.0/24` so the kernel LPM trie traverses
/// realistic internal branch nodes and backtracks to the `/24` match.
fn build_ip4_rules(total: usize) -> Vec<IpMarkInfo> {
    assert!(total >= SMALL_RULES);
    let distract = flow_mark_from_raw(MARK_DISTRACT);
    let hit = flow_mark_from_raw(MARK_IP_HIT);

    let mut rules = vec![
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(198, 0, 0, 0)),
                prefix: 8,
            },
            priority: 500,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(198, 48, 0, 0)),
                prefix: 14,
            },
            priority: 400,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 0, 0)),
                prefix: 16,
            },
            priority: 350,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 96, 0)),
                prefix: 20,
            },
            priority: 300,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
                prefix: 22,
            },
            priority: 250,
        },
        IpMarkInfo {
            mark: hit,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
                prefix: 24,
            },
            priority: 200,
        },
        // Deeper /28 children that do NOT cover .42 or .84 force deeper trie walk.
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
                prefix: 28,
            },
            priority: 150,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 128)),
                prefix: 28,
            },
            priority: 150,
        },
    ];

    for i in 0..(total - SMALL_RULES) {
        let b1 = ((i >> 8) & 0xff) as u8;
        let b2 = (i & 0xff) as u8;
        rules.push(IpMarkInfo {
            mark: distract,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(100, b1, b2, 0)),
                prefix: 24,
            },
            priority: 300,
        });
    }
    assert_eq!(rules.len(), total);
    rules
}

/// Build `total` IPv4 DNS rule entries (`total >= 1`): `COLD_DNS_DST_V4` wins
/// priority arbitration (`50 <= 200`), while `COLD_IP_DST_V4` misses.
fn build_dns4_rules(total: usize) -> Vec<FlowMarkInfo> {
    assert!(total >= 1);
    let mut rules = Vec::with_capacity(total);
    rules.push(FlowMarkInfo {
        ip: IpAddr::V4(COLD_DNS_DST_V4),
        mark: MARK_DNS_WIN,
        priority: 50,
    });
    for i in 1..total {
        let b1 = ((i >> 8) & 0xff) as u8;
        let b2 = (i & 0xff) as u8;
        rules.push(FlowMarkInfo {
            ip: IpAddr::V4(Ipv4Addr::new(198, 18, b1, b2)),
            mark: MARK_DISTRACT,
            priority: 100,
        });
    }
    rules
}

/// IPv6 twin of [`build_ip4_rules`]: nested prefixes `/32` -> `/40` -> `/48` ->
/// `/56` -> `/60` -> `/64` (hit) plus `/80` children under `2001:db8:abcd:1234::/64`.
fn build_ip6_rules(total: usize) -> Vec<IpMarkInfo> {
    assert!(total >= SMALL_RULES);
    let distract = flow_mark_from_raw(MARK_DISTRACT);
    let hit = flow_mark_from_raw(MARK_IP_HIT);

    let parse = |s: &str| IpAddr::V6(Ipv6Addr::from_str(s).unwrap());
    let mut rules = vec![
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig { ip: parse("2001:db8::"), prefix: 32 },
            priority: 500,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig { ip: parse("2001:db8:ab00::"), prefix: 40 },
            priority: 400,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig { ip: parse("2001:db8:abcd::"), prefix: 48 },
            priority: 350,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig { ip: parse("2001:db8:abcd:1200::"), prefix: 56 },
            priority: 300,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig { ip: parse("2001:db8:abcd:1230::"), prefix: 60 },
            priority: 250,
        },
        IpMarkInfo {
            mark: hit,
            cidr: IpConfig { ip: parse("2001:db8:abcd:1234::"), prefix: 64 },
            priority: 200,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig { ip: parse("2001:db8:abcd:1234:1000::"), prefix: 80 },
            priority: 150,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig { ip: parse("2001:db8:abcd:1234:8000::"), prefix: 80 },
            priority: 150,
        },
    ];

    for i in 0..(total - SMALL_RULES) {
        let seg2 = 0x2000u16.wrapping_add((i >> 8) as u16);
        let seg3 = (i & 0xff) as u16;
        let ip = Ipv6Addr::new(0x2001, 0x0db8, seg2, seg3, 0, 0, 0, 0);
        rules.push(IpMarkInfo {
            mark: distract,
            cidr: IpConfig { ip: IpAddr::V6(ip), prefix: 64 },
            priority: 300,
        });
    }
    assert_eq!(rules.len(), total);
    rules
}

fn build_dns6_rules(total: usize) -> Vec<FlowMarkInfo> {
    assert!(total >= 1);
    let mut rules = Vec::with_capacity(total);
    rules.push(FlowMarkInfo {
        ip: IpAddr::V6(cold_dns_dst_v6()),
        mark: MARK_DNS_WIN,
        priority: 50,
    });
    for i in 1..total {
        let ip = Ipv6Addr::new(0x2001, 0x0db8, 0x9999, (i >> 16) as u16, i as u16, 0, 0, 1);
        rules.push(FlowMarkInfo {
            ip: IpAddr::V6(ip),
            mark: MARK_DISTRACT,
            priority: 100,
        });
    }
    rules
}

fn build_l4_port_rules() -> Vec<PortMarkInfo> {
    let distract = flow_mark_from_raw(MARK_DISTRACT);
    let win = flow_mark_from_raw(MARK_L4_PORT_WIN);
    let mut rules = Vec::with_capacity(SMALL_RULES);
    for idx in 0..7u16 {
        let port = 10000 + idx * 100;
        rules.push(PortMarkInfo {
            mark: distract,
            protocol: L4ProtoMatch::Udp,
            start_port: port,
            end_port: port + 10,
            priority: 10 + idx,
        });
    }
    rules.push(PortMarkInfo {
        mark: win,
        protocol: L4ProtoMatch::Tcp,
        start_port: 65499,
        end_port: 65499,
        priority: 20,
    });
    rules
}

fn ipv4_tcp_port(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(PKT_SRC_MAC, [0x02, 0, 0, 0, 0, 2])
        .ipv4(src.octets(), dst.octets(), 64)
        .tcp(sport, dport, 0x1020_3040, 4096);
    let payload = [0x11_u8, 0x22, 0x33, 0x44];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).expect("build ipv4 tcp port packet");
    packet
}

fn ipv6_tcp_port(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(PKT_SRC_MAC, [0x02, 0, 0, 0, 0, 2])
        .ipv6(src.octets(), dst.octets(), 64)
        .tcp(sport, dport, 0x1020_3040, 4096);
    let payload = [0x11_u8, 0x22, 0x33, 0x44];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).expect("build ipv6 tcp port packet");
    packet
}

fn seed_ecmp_slots_v4(skel: &BenchRouteSkel<'_>) {
    let mut wan1 = RouteTargetInfo::dummy(WAN1_IFINDEX, "ppp0", IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    wan1.mac = None;
    wan1.is_docker = false;
    wan1.gateway_ip = IpAddr::V4(WAN_GW_V4);

    let mut wan2 = RouteTargetInfo::dummy(WAN2_IFINDEX, "ppp1", IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    wan2.mac = None;
    wan2.is_docker = false;
    wan2.gateway_ip = IpAddr::V4(WAN_GW_V4);

    for flow_id in [0u32, 2, 3, 4] {
        let single = [(WanRouteTarget::link(2, wan1.clone()), 1u32)];
        replace_wan_route_slots_v4_with_map(
            &skel.maps.rt4_slot_map,
            &skel.maps.rt4_flow_targets,
            flow_id,
            &single,
        );
    }
    // Dual-WAN ECMP 1:1 across 256 slots on Flow 5, Flow 6, and Flow 7 (FiveTuple).
    let dual = [(WanRouteTarget::link(2, wan1), 1u32), (WanRouteTarget::link(3, wan2), 1u32)];
    for flow_id in [5u32, 6, 7] {
        replace_wan_route_slots_v4_with_map(
            &skel.maps.rt4_slot_map,
            &skel.maps.rt4_flow_targets,
            flow_id,
            &dual,
        );
    }
    skel.maps
        .rt_flow_mode_map
        .update(&7u32.to_ne_bytes(), &[1u8], MapFlags::ANY)
        .expect("set flow 7 five_tuple mode");
}

fn seed_ecmp_slots_v6(skel: &BenchRouteSkel<'_>) {
    let mut wan1 = RouteTargetInfo::dummy(WAN1_IFINDEX, "ppp0", IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    wan1.mac = None;
    wan1.is_docker = false;
    wan1.gateway_ip = IpAddr::V6(wan_gw_v6());

    let mut wan2 = RouteTargetInfo::dummy(WAN2_IFINDEX, "ppp1", IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    wan2.mac = None;
    wan2.is_docker = false;
    wan2.gateway_ip = IpAddr::V6(wan_gw_v6());

    for flow_id in [0u32, 2, 3, 4] {
        let single = [(WanRouteTarget::link(2, wan1.clone()), 1u32)];
        replace_wan_route_slots_v6_with_map(
            &skel.maps.rt6_slot_map,
            &skel.maps.rt6_flow_targets,
            flow_id,
            &single,
        );
    }
    let dual = [(WanRouteTarget::link(2, wan1), 1u32), (WanRouteTarget::link(3, wan2), 1u32)];
    for flow_id in [5u32, 6, 7] {
        replace_wan_route_slots_v6_with_map(
            &skel.maps.rt6_slot_map,
            &skel.maps.rt6_flow_targets,
            flow_id,
            &dual,
        );
    }
    skel.maps
        .rt_flow_mode_map
        .update(&7u32.to_ne_bytes(), &[1u8], MapFlags::ANY)
        .expect("set flow 7 five_tuple mode");
}

#[test]
#[ignore = "bench"]
fn route_v4_lookup_cost() {
    let pin_root = isolated_pin_root("bench-route-v4");
    let mut builder = BenchRouteSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root).expect("set pin_root_path");
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).expect("open bench_route");
    let skel = open.load().expect("load bench_route");

    // 1. Seed WAN_CACHE (populated with distractors so WAN_CACHE miss is realistic)
    //    and LAN_CACHE (hot PPPoE L3 entry + hot Ethernet L2 entry + distractors).
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    create_route4_conn_inner_map(&skel.maps.rt4_conn_map);
    for i in 0..16u8 {
        put_rt4_cache_value(
            &skel.maps.rt4_cache_map,
            WAN_CACHE,
            Ipv4Addr::new(192, 168, 200, i),
            Ipv4Addr::new(203, 0, 113, 100 + i),
            WAN1_IFINDEX,
            false,
            MARK_DISTRACT,
        );
        put_rt4_cache_value(
            &skel.maps.rt4_cache_map,
            LAN_CACHE,
            Ipv4Addr::new(192, 168, 201, i),
            Ipv4Addr::new(203, 0, 113, 150 + i),
            WAN1_IFINDEX,
            false,
            MARK_DISTRACT,
        );
    }
    put_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        CLIENT_V4,
        HOT_PPPOE_DST_V4,
        WAN1_IFINDEX,
        false,
        MARK_CACHE_HIT,
    );
    put_rt4_cache_full(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        CLIENT_V4,
        HOT_ETH_DST_V4,
        WAN1_IFINDEX,
        true,
        MARK_CACHE_HIT,
        false,
        WAN_GW_V4,
        ROUTER_SRC_MAC,
    );
    insert_ip_mac_v4(
        &skel.maps.ip_mac_v4,
        WAN_GW_V4,
        MacAddr::from_str(GW_DST_MAC_STR).unwrap(),
        MacAddr::from_str(ROUTER_DEV_MAC_STR).unwrap(),
        WAN1_IFINDEX,
    );
    // Steady-state FiveTuple entry: LAN_CACHE holds `ifindex = 0` + `MARK_FIVETUPLE_HIT`
    // while `rt4_conn_map[0]` pins the 5-tuple to `WAN2_IFINDEX`.
    put_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        CLIENT_V4,
        HOT_FIVETUPLE_DST_V4,
        0,
        false,
        MARK_FIVETUPLE_HIT,
    );
    {
        let conn_inner = lookup_inner_map(&skel.maps.rt4_conn_map, CONN_PIN_CACHE);
        let conn_key = Route4ConnKey {
            saddr: CLIENT_V4.to_bits().to_be(),
            daddr: HOT_FIVETUPLE_DST_V4.to_bits().to_be(),
            sport: 12345u16.to_be(),
            dport: 443u16.to_be(),
            l4_proto: 6,
            _pad: [0; 3],
        };
        let conn_val = RouteConnValue {
            mark_value: MARK_FIVETUPLE_HIT,
            ifindex: WAN2_IFINDEX,
        };
        conn_inner
            .update(as_bytes(&conn_key), as_bytes(&conn_val), MapFlags::ANY)
            .expect("seed v4 five_tuple conn entry");
    }

    // 2. Seed local LAN subnets in `rt4_lan_map` (missed on WAN destinations).
    for vlan in [1u8, 101, 102, 105] {
        insert_route4_lan_entry(
            &skel.maps.rt4_lan_map,
            24,
            Ipv4Addr::new(192, 168, vlan, 0),
            Ipv4Addr::new(192, 168, vlan, 1),
            LAN_ROUTE_TYPE,
            LAN_IFINDEX,
            true,
            ROUTER_SRC_MAC,
        );
    }

    // 3. Seed `flow_match_map` (MAC fallback -> flow 1, /24 subnet -> flow 2, + distractors).
    seed_flow_match_mac(&skel.maps.flow_match_map, PKT_SRC_MAC, MAC_FALLBACK_FLOW_ID);
    seed_flow_match_subnet_v4(
        &skel.maps.flow_match_map,
        Ipv4Addr::new(192, 168, 101, 0),
        24,
        MATCHED_SRC_FLOW_ID,
    );
    for i in 0..16u8 {
        seed_flow_match_subnet_v4(
            &skel.maps.flow_match_map,
            Ipv4Addr::new(10, i, 0, 0),
            16,
            MAC_FALLBACK_FLOW_ID,
        );
    }

    // 4. Seed 16-slot ECMP `rt4_slot_map`.
    seed_ecmp_slots_v4(&skel);

    let hot_pppoe_pkt = simple_ipv4_tcp(CLIENT_V4, HOT_PPPOE_DST_V4);
    let hot_eth_pkt = simple_ipv4_tcp(CLIENT_V4, HOT_ETH_DST_V4);
    let hot_five_tuple_pkt = simple_ipv4_tcp(CLIENT_V4, HOT_FIVETUPLE_DST_V4);
    let cold_ip_pkt = simple_ipv4_tcp(CLIENT_V4, COLD_IP_DST_V4);
    let cold_dns_pkt = simple_ipv4_tcp(CLIENT_V4, COLD_DNS_DST_V4);
    let cold_l4_port_pkt = ipv4_tcp_port(CLIENT_V4, COLD_IP_DST_V4, 12345, 65499);
    let sink = &skel.maps.bench_sink;

    let base_v4 = measure_checked(&skel.progs.bench_route4_baseline, &hot_pppoe_pkt, 1, sink);
    let cache_pppoe_v4 = measure_checked(
        &skel.progs.bench_route4_lan_cache_hit,
        &hot_pppoe_pkt,
        u64::from(MARK_CACHE_HIT),
        sink,
    );
    let cache_eth_v4 = measure_checked(
        &skel.progs.bench_route4_lan_cache_hit,
        &hot_eth_pkt,
        u64::from(MARK_CACHE_HIT),
        sink,
    );
    let five_tuple_hit_v4 = measure_checked(
        &skel.progs.bench_route4_lan_five_tuple_hit,
        &hot_five_tuple_pkt,
        u64::from(MARK_FIVETUPLE_HIT),
        sink,
    );

    // Small policy rule fill (8 IP prefixes + 8 DNS entries).
    create_inner_flow_match_map_v4(
        &skel.maps.flow4_ip_map,
        MATCHED_SRC_FLOW_ID,
        &build_ip4_rules(SMALL_RULES),
    )
    .expect("seed small flow4_ip_map");
    create_flow_dns_inner_map_v4(
        &skel.maps.flow4_dns_map,
        MATCHED_SRC_FLOW_ID,
        &build_dns4_rules(SMALL_RULES),
    );

    let cold_small_ip_v4 = measure_checked(
        &skel.progs.bench_route4_lan_cold_resolve,
        &cold_ip_pkt,
        u64::from(MARK_IP_HIT),
        sink,
    );
    let cold_small_dns_v4 = measure_checked(
        &skel.progs.bench_route4_lan_cold_resolve,
        &cold_dns_pkt,
        u64::from(MARK_DNS_WIN),
        sink,
    );

    // Large policy rule fill (1024 IP prefixes + 1024 DNS entries).
    create_inner_flow_match_map_v4(
        &skel.maps.flow4_ip_map,
        MATCHED_SRC_FLOW_ID,
        &build_ip4_rules(LARGE_RULES),
    )
    .expect("seed 1k flow4_ip_map");
    create_flow_dns_inner_map_v4(
        &skel.maps.flow4_dns_map,
        MATCHED_SRC_FLOW_ID,
        &build_dns4_rules(LARGE_RULES),
    );

    let cold_1k_ip_v4 = measure_checked(
        &skel.progs.bench_route4_lan_cold_resolve,
        &cold_ip_pkt,
        u64::from(MARK_IP_HIT),
        sink,
    );
    let cold_1k_dns_v4 = measure_checked(
        &skel.progs.bench_route4_lan_cold_resolve,
        &cold_dns_pkt,
        u64::from(MARK_DNS_WIN),
        sink,
    );
    let cold_full_1k_v4 = measure_checked(
        &skel.progs.bench_route4_lan_cold_full,
        &cold_dns_pkt,
        u64::from(MARK_DNS_WIN),
        sink,
    );

    // Seed L4 port rules after default-mode (`l4_meta == 0`) measurements so
    // default fastpath numbers remain isolated, then measure L4 port match.
    set_flow_l4_rules_with_maps(
        &skel.maps.flow_l4_rule_map,
        &skel.maps.flow_l4_meta_map,
        MATCHED_SRC_FLOW_ID,
        &build_l4_port_rules(),
    )
    .expect("seed v4 flow_l4_rule_map");
    let l4_port_cold_v4 = measure_checked(
        &skel.progs.bench_route4_lan_l4_port_cold,
        &cold_l4_port_pkt,
        u64::from(MARK_L4_PORT_WIN),
        sink,
    );

    println!("--- Route IPv4 baseline (kernel repeat={REPEAT}) ---");
    println!(
        "{:<28} per-pkt(min/med) {:>7.2}/{:>7.2} ns",
        "baseline_v4", base_v4.0 as f64, base_v4.1 as f64
    );
    println!("--- Route IPv4 lookup cost (kernel repeat={REPEAT}, baseline-subtracted) ---");
    report("lan_cache_hit_v4(pppoe)", cache_pppoe_v4, base_v4);
    report("lan_cache_hit_v4(eth_mac)", cache_eth_v4, base_v4);
    report("lan_five_tuple_hit_v4", five_tuple_hit_v4, base_v4);
    report("lan_cold_resolve_v4(8,ip)", cold_small_ip_v4, base_v4);
    report("lan_cold_resolve_v4(8,dns)", cold_small_dns_v4, base_v4);
    report("lan_cold_resolve_v4(1k,ip)", cold_1k_ip_v4, base_v4);
    report("lan_cold_resolve_v4(1k,dns)", cold_1k_dns_v4, base_v4);
    report("lan_cold_full_v4(1k,dns)", cold_full_1k_v4, base_v4);
    report("lan_l4_port_cold_v4(8,tcp)", l4_port_cold_v4, base_v4);
}

#[test]
#[ignore = "bench"]
fn route_v6_lookup_cost() {
    let pin_root = isolated_pin_root("bench-route-v6");
    let mut builder = BenchRouteSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root).expect("set pin_root_path");
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).expect("open bench_route");
    let skel = open.load().expect("load bench_route");

    let client = client_v6();
    let hot_pppoe = hot_pppoe_dst_v6();
    let hot_eth = hot_eth_dst_v6();
    let hot_five_tuple = hot_fivetuple_dst_v6();
    let cold_ip = cold_ip_dst_v6();
    let cold_dns = cold_dns_dst_v6();
    let gw6 = wan_gw_v6();

    // 1. Seed WAN_CACHE + LAN_CACHE for IPv6.
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    create_route6_conn_inner_map(&skel.maps.rt6_conn_map);
    for i in 0..16u16 {
        put_rt6_cache_value(
            &skel.maps.rt6_cache_map,
            WAN_CACHE,
            Ipv6Addr::new(0xfd00, 0x200, 0, 0, 0, 0, 0, i + 1),
            Ipv6Addr::new(0x2001, 0x0db8, 0x200, 0, 0, 0, 0, i + 1),
            WAN1_IFINDEX,
            false,
            MARK_DISTRACT,
        );
        put_rt6_cache_value(
            &skel.maps.rt6_cache_map,
            LAN_CACHE,
            Ipv6Addr::new(0xfd00, 0x201, 0, 0, 0, 0, 0, i + 1),
            Ipv6Addr::new(0x2001, 0x0db8, 0x201, 0, 0, 0, 0, i + 1),
            WAN1_IFINDEX,
            false,
            MARK_DISTRACT,
        );
    }
    put_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        client,
        hot_pppoe,
        WAN1_IFINDEX,
        false,
        MARK_CACHE_HIT,
    );
    put_rt6_cache_full(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        client,
        hot_eth,
        WAN1_IFINDEX,
        true,
        MARK_CACHE_HIT,
        false,
        gw6,
        ROUTER_SRC_MAC,
    );
    insert_ip_mac_v6(
        &skel.maps.ip_mac_v6,
        gw6,
        MacAddr::from_str(GW_DST_MAC_STR).unwrap(),
        MacAddr::from_str(ROUTER_DEV_MAC_STR).unwrap(),
        WAN1_IFINDEX,
    );
    put_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        client,
        hot_five_tuple,
        0,
        false,
        MARK_FIVETUPLE_HIT,
    );
    {
        let conn_inner = lookup_inner_map(&skel.maps.rt6_conn_map, CONN_PIN_CACHE);
        let conn_key = Route6ConnKey {
            saddr: client.to_bits().to_be_bytes(),
            daddr: hot_five_tuple.to_bits().to_be_bytes(),
            sport: 12345u16.to_be(),
            dport: 443u16.to_be(),
            l4_proto: 6,
            _pad: [0; 3],
        };
        let conn_val = RouteConnValue {
            mark_value: MARK_FIVETUPLE_HIT,
            ifindex: WAN2_IFINDEX,
        };
        conn_inner
            .update(as_bytes(&conn_key), as_bytes(&conn_val), MapFlags::ANY)
            .expect("seed v6 five_tuple conn entry");
    }

    // 2. Seed local LAN /64 prefixes in `rt6_lan_map`.
    for vlan in [1u16, 101, 102, 105] {
        insert_route6_lan_entry(
            &skel.maps.rt6_lan_map,
            64,
            Ipv6Addr::new(0xfd00, vlan, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xfd00, vlan, 0, 0, 0, 0, 0, 1),
            LAN_ROUTE_TYPE,
            LAN_IFINDEX,
            true,
            ROUTER_SRC_MAC,
        );
    }

    // 3. Seed `flow_match_map` (MAC fallback -> flow 1, /64 subnet -> flow 2, + distractors).
    seed_flow_match_mac(&skel.maps.flow_match_map, PKT_SRC_MAC, MAC_FALLBACK_FLOW_ID);
    seed_flow_match_subnet_v6(
        &skel.maps.flow_match_map,
        Ipv6Addr::from_str("fd00:101::").unwrap(),
        64,
        MATCHED_SRC_FLOW_ID,
    );
    for i in 0..16u16 {
        seed_flow_match_subnet_v6(
            &skel.maps.flow_match_map,
            Ipv6Addr::new(0xfd00, 0x300 + i, 0, 0, 0, 0, 0, 0),
            64,
            MAC_FALLBACK_FLOW_ID,
        );
    }

    // 4. Seed 16-slot ECMP `rt6_slot_map`.
    seed_ecmp_slots_v6(&skel);

    let hot_pppoe_pkt = simple_ipv6_tcp_syn(client, hot_pppoe);
    let hot_eth_pkt = simple_ipv6_tcp_syn(client, hot_eth);
    let hot_five_tuple_pkt = simple_ipv6_tcp_syn(client, hot_five_tuple);
    let cold_ip_pkt = simple_ipv6_tcp_syn(client, cold_ip);
    let cold_dns_pkt = simple_ipv6_tcp_syn(client, cold_dns);
    let cold_l4_port_pkt = ipv6_tcp_port(client, cold_ip, 12345, 65499);
    let sink = &skel.maps.bench_sink;

    let base_v6 = measure_checked(&skel.progs.bench_route6_baseline, &hot_pppoe_pkt, 1, sink);
    let cache_pppoe_v6 = measure_checked(
        &skel.progs.bench_route6_lan_cache_hit,
        &hot_pppoe_pkt,
        u64::from(MARK_CACHE_HIT),
        sink,
    );
    let cache_eth_v6 = measure_checked(
        &skel.progs.bench_route6_lan_cache_hit,
        &hot_eth_pkt,
        u64::from(MARK_CACHE_HIT),
        sink,
    );
    let five_tuple_hit_v6 = measure_checked(
        &skel.progs.bench_route6_lan_five_tuple_hit,
        &hot_five_tuple_pkt,
        u64::from(MARK_FIVETUPLE_HIT),
        sink,
    );

    // Small policy rule fill (8 IPv6 prefixes + 8 DNS entries).
    create_inner_flow_match_map_v6(
        &skel.maps.flow6_ip_map,
        MATCHED_SRC_FLOW_ID,
        &build_ip6_rules(SMALL_RULES),
    )
    .expect("seed small flow6_ip_map");
    create_flow_dns_inner_map_v6(
        &skel.maps.flow6_dns_map,
        MATCHED_SRC_FLOW_ID,
        &build_dns6_rules(SMALL_RULES),
    );

    let cold_small_ip_v6 = measure_checked(
        &skel.progs.bench_route6_lan_cold_resolve,
        &cold_ip_pkt,
        u64::from(MARK_IP_HIT),
        sink,
    );
    let cold_small_dns_v6 = measure_checked(
        &skel.progs.bench_route6_lan_cold_resolve,
        &cold_dns_pkt,
        u64::from(MARK_DNS_WIN),
        sink,
    );

    // Large policy rule fill (1024 IPv6 prefixes + 1024 DNS entries).
    create_inner_flow_match_map_v6(
        &skel.maps.flow6_ip_map,
        MATCHED_SRC_FLOW_ID,
        &build_ip6_rules(LARGE_RULES),
    )
    .expect("seed 1k flow6_ip_map");
    create_flow_dns_inner_map_v6(
        &skel.maps.flow6_dns_map,
        MATCHED_SRC_FLOW_ID,
        &build_dns6_rules(LARGE_RULES),
    );

    let cold_1k_ip_v6 = measure_checked(
        &skel.progs.bench_route6_lan_cold_resolve,
        &cold_ip_pkt,
        u64::from(MARK_IP_HIT),
        sink,
    );
    let cold_1k_dns_v6 = measure_checked(
        &skel.progs.bench_route6_lan_cold_resolve,
        &cold_dns_pkt,
        u64::from(MARK_DNS_WIN),
        sink,
    );
    let cold_full_1k_v6 = measure_checked(
        &skel.progs.bench_route6_lan_cold_full,
        &cold_dns_pkt,
        u64::from(MARK_DNS_WIN),
        sink,
    );

    set_flow_l4_rules_with_maps(
        &skel.maps.flow_l4_rule_map,
        &skel.maps.flow_l4_meta_map,
        MATCHED_SRC_FLOW_ID,
        &build_l4_port_rules(),
    )
    .expect("seed v6 flow_l4_rule_map");
    let l4_port_cold_v6 = measure_checked(
        &skel.progs.bench_route6_lan_l4_port_cold,
        &cold_l4_port_pkt,
        u64::from(MARK_L4_PORT_WIN),
        sink,
    );

    println!("--- Route IPv6 baseline (kernel repeat={REPEAT}) ---");
    println!(
        "{:<28} per-pkt(min/med) {:>7.2}/{:>7.2} ns",
        "baseline_v6", base_v6.0 as f64, base_v6.1 as f64
    );
    println!("--- Route IPv6 lookup cost (kernel repeat={REPEAT}, baseline-subtracted) ---");
    report("lan_cache_hit_v6(pppoe)", cache_pppoe_v6, base_v6);
    report("lan_cache_hit_v6(eth_mac)", cache_eth_v6, base_v6);
    report("lan_five_tuple_hit_v6", five_tuple_hit_v6, base_v6);
    report("lan_cold_resolve_v6(8,ip)", cold_small_ip_v6, base_v6);
    report("lan_cold_resolve_v6(8,dns)", cold_small_dns_v6, base_v6);
    report("lan_cold_resolve_v6(1k,ip)", cold_1k_ip_v6, base_v6);
    report("lan_cold_resolve_v6(1k,dns)", cold_1k_dns_v6, base_v6);
    report("lan_cold_full_v6(1k,dns)", cold_full_1k_v6, base_v6);
    report("lan_l4_port_cold_v6(8,tcp)", l4_port_cold_v6, base_v6);
}
