//! The unclassified-destination policy, exercised through the real verdict.
//!
//! The contract this locks: a destination that nothing classified goes to a
//! managed tier or is refused, never silently direct - while everything that
//! *was* classified keeps its own behaviour. The cases below are exactly the
//! traffic that must not be caught by the new gate, because catching any of them
//! would break the household: explicit direct, LAN destinations, and the managed
//! DNS hand-off.
//!
//! These run the production `tc_route4_lan_ingress` against synthetic packets in
//! an isolated pin root, so they prove the verdict path rather than the map.

use super::*;
use crate::maps::route::RouteUnclassifiedCfg;

/// Programme the policy map. One array entry, key 0.
fn set_policy(skel: &TcLanIngressIntroSkel<'_>, cfg: RouteUnclassifiedCfg) {
    skel.maps
        .route_unclassified_cfg_map
        .update(&0u32.to_ne_bytes(), cfg.as_bytes(), MapFlags::ANY)
        .expect("write route_unclassified_cfg_map");
}

fn policy_off() -> RouteUnclassifiedCfg {
    RouteUnclassifiedCfg {
        enabled: 0,
        action: RouteUnclassifiedCfg::PASSTHROUGH,
        _pad: 0,
        flow_id: 0,
    }
}

fn policy_drop() -> RouteUnclassifiedCfg {
    RouteUnclassifiedCfg {
        enabled: 1,
        action: RouteUnclassifiedCfg::DROP,
        _pad: 0,
        flow_id: 0,
    }
}

fn policy_tier(flow_id: u32) -> RouteUnclassifiedCfg {
    RouteUnclassifiedCfg {
        enabled: 1,
        action: RouteUnclassifiedCfg::FLOW,
        _pad: 0,
        flow_id,
    }
}

/// A destination that no rule and no destination-IP entry claims, reaching the
/// verdict as `KeepGoing` with flow 0 - the state the live route cache held for
/// the destinations that leaked.
fn unclassified_dst() -> Ipv4Addr {
    // TEST-NET-3: routable-looking, and certainly not in any of the test's
    // classification maps.
    Ipv4Addr::from_str("198.51.100.7").unwrap()
}

fn sent_to_unclassified() -> Vec<u8> {
    simple_ipv4_tcp(client_addr(), unclassified_dst())
}

#[test]
fn passthrough_keeps_the_previous_behaviour_and_the_cache_says_flow_zero() {
    // The state before the policy existed, locked deliberately: the packet is
    // forwarded through flow 0's slots and the cache records flow 0. This is what
    // the leak looked like on the wire, so a change here should be visible.
    load_skel!("tc-lan-unclass-passthrough", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_wan_slots(&skel, 0, TARGET_IFINDEX, false, None);
    set_policy(&skel, policy_off());

    let pkt = sent_to_unclassified();
    let (ret, _out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "with the policy off the packet still goes out");
    let cache = lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        unclassified_dst(),
    )
    .expect("the verdict is cached");
    assert_eq!(cache & 0xffff, 0, "an unclassified destination caches as flow 0");
}

#[test]
fn drop_refuses_an_unclassified_destination() {
    load_skel!("tc-lan-unclass-drop", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    // Flow 0 has a target, so "passthrough" would have forwarded this packet: the
    // drop must come from the policy and not from a missing target.
    seed_wan_slots(&skel, 0, TARGET_IFINDEX, false, None);
    set_policy(&skel, policy_drop());

    let pkt = sent_to_unclassified();
    let (ret, _out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "the policy must refuse it in the datapath");
    assert!(
        lookup_rt4_cache_value(
            &skel.maps.rt4_cache_map,
            LAN_CACHE,
            client_addr(),
            unclassified_dst()
        )
        .is_none(),
        "a refused packet must not be cached as a forward"
    );
}

#[test]
fn the_fallback_tier_is_what_gets_cached() {
    // Applying the policy on the verdict is what makes the cache agree with the
    // policy: the fast path can only be right if what it stored is the tier.
    load_skel!("tc-lan-unclass-tier", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_wan_slots(&skel, 14, TARGET_IFINDEX, false, None);
    set_policy(&skel, policy_tier(14));

    let pkt = sent_to_unclassified();
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "it must still leave, through the fallback");
    assert_eq!(mark & 0xff, 14, "the packet must carry the fallback tier");
    let cache = lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        unclassified_dst(),
    )
    .expect("the verdict is cached");
    assert_eq!(cache & 0xff, 14, "the cache must hold the tier, not flow 0");
}

#[test]
fn a_fallback_tier_with_no_target_is_refused_not_forwarded_directly() {
    // The fail-closed direction: if the fallback cannot be delivered, the packet
    // must not quietly take the direct path instead. Flow 0 has a target here, so
    // a naive implementation would fall through to it.
    load_skel!("tc-lan-unclass-tier-missing", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_wan_slots(&skel, 0, TARGET_IFINDEX, false, None);
    set_policy(&skel, policy_tier(14));

    let pkt = sent_to_unclassified();
    let (ret, _out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "an undeliverable fallback must refuse, not go direct");
}

#[test]
fn an_explicit_direct_rule_is_not_touched_by_the_policy() {
    // 0x0100 is `Direct`: a rule said "this destination goes direct". The policy
    // is about destinations nothing classified, so it must leave this alone.
    load_skel!("tc-lan-unclass-explicit-direct", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_flow_rule(&skel, unclassified_dst(), FLOW_DIRECT_MARK);
    seed_wan_slots(&skel, 0, TARGET_IFINDEX, false, None);
    set_policy(&skel, policy_drop());

    let pkt = sent_to_unclassified();
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "an explicit direct destination must still go out");
    assert_eq!(mark & 0xffff, 0x0100, "its Direct mark must survive");
}

#[test]
fn a_lan_destination_is_not_touched_by_the_policy() {
    // LAN-internal traffic never reaches the verdict, and it must not: the policy
    // is for managed LAN-to-outside traffic.
    load_skel!("tc-lan-unclass-lan-dst", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    let lan_peer = Ipv4Addr::from_str("192.168.1.50").unwrap();
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        lan_peer,
        lan_peer,
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );
    seed_wan_slots(&skel, 0, TARGET_IFINDEX, false, None);
    set_policy(&skel, policy_drop());

    let pkt = simple_ipv4_tcp(client_addr(), lan_peer);
    let (ret, _out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_ne!(ret, RET_SHOT, "a LAN destination must not be refused by this policy");
}

#[test]
fn the_managed_dns_handoff_is_not_touched_by_the_policy() {
    // The DNS guard hands a managed plaintext query to the local stack with the
    // flow id cleared, which looks exactly like a verdict of flow 0. The DNS path
    // returns before the verdict, so this pins that ordering: if the gate ever
    // moved in front of the hand-off it would refuse every plaintext query.
    load_skel!("tc-lan-unclassified-dns-handoff", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_wan_slots(&skel, 0, TARGET_IFINDEX, false, None);
    set_policy(&skel, policy_drop());

    // Enable the DNS guard so a query to an external resolver is handed to the
    // stack instead of being classified.
    let dns_cfg = crate::maps::dns_guard::types::DnsGuardConfig {
        enabled: 1,
        plaintext_tcp: 0,
        drop_fragments: 0,
        drop_unclassified: 0,
        generation: 1,
    };
    skel.maps
        .dns_guard_config_map
        .update(&0u32.to_ne_bytes(), dns_cfg.as_bytes(), MapFlags::ANY)
        .expect("write dns_guard_config_map");

    let resolver = Ipv4Addr::from_str("8.8.8.8").unwrap();
    let pkt = simple_ipv4_udp(client_addr(), resolver);

    let (ret, _out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(
        ret, RET_OK,
        "a managed plaintext DNS query must be handed to the stack, not refused"
    );
}
