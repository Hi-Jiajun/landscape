use std::{mem::MaybeUninit, net::Ipv6Addr, str::FromStr};

use etherparse::{
    Ethernet2Header, IpFragOffset, Ipv6FragmentHeader, Ipv6Header, PacketHeaders, UdpHeader,
    ether_type, ip_number,
};
use libbpf_rs::{
    MapCore, ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::IntoBytes;

use crate::{
    maps::nat::{StaticNatMappingV6Item, add_static_nat6_mapping},
    skel::{tc_nat6::TcNat6SkelBuilder, xdp_nat6::XdpNat6SkelBuilder},
    tests::TestSkb,
};

const IFINDEX: u32 = 6;
const TC_ACT_UNSPEC: i32 = -1;
const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;
const XDP_DROP: u32 = 1;
const XDP_PASS: u32 = 2;
const XDP_PIPE_META_LEN: usize = 12;
const INGRESS_STATIC_MARK: u32 = 1;
const INGRESS_CACHE_MASK: u32 = 0x0000_00ff;

fn wan_ip() -> Ipv6Addr {
    Ipv6Addr::from_str("2409:8888:6666:4f21::").unwrap()
}

fn lan_host() -> Ipv6Addr {
    Ipv6Addr::from_str("fd00:1234:5678:abc5::100").unwrap()
}

fn wan_npt_addr() -> Ipv6Addr {
    Ipv6Addr::from_str("2409:8888:6666:4f25::100").unwrap()
}

fn remote() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:2::1").unwrap()
}

fn build_ipv6_udp_fragments(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    sport: u16,
    dport: u16,
    frag_id: u32,
) -> (Vec<u8>, Vec<u8>) {
    let payload_first = [0x11u8; 8];
    let payload_second = [0x22u8; 16];
    let mut full_payload = Vec::with_capacity(payload_first.len() + payload_second.len());
    full_payload.extend_from_slice(&payload_first);
    full_payload.extend_from_slice(&payload_second);

    let ipv6_for_csum = Ipv6Header {
        traffic_class: 0,
        flow_label: Default::default(),
        payload_length: (UdpHeader::LEN + full_payload.len()) as u16,
        next_header: ip_number::UDP,
        hop_limit: 64,
        source: src.octets(),
        destination: dst.octets(),
    };
    let udp = UdpHeader::with_ipv6_checksum(sport, dport, &ipv6_for_csum, &full_payload).unwrap();

    let mut first_body = Vec::with_capacity(UdpHeader::LEN + payload_first.len());
    udp.write(&mut first_body).unwrap();
    first_body.extend_from_slice(&payload_first);

    let make_frag = |offset_units: u16, more: bool, body: &[u8]| -> Vec<u8> {
        let mut ipv6 = Ipv6Header {
            traffic_class: 0,
            flow_label: Default::default(),
            payload_length: 0,
            next_header: ip_number::IPV6_FRAGMENTATION_HEADER,
            hop_limit: 64,
            source: src.octets(),
            destination: dst.octets(),
        };
        ipv6.set_payload_length(Ipv6FragmentHeader::LEN + body.len()).unwrap();
        let frag = Ipv6FragmentHeader::new(
            ip_number::UDP,
            IpFragOffset::try_new(offset_units).unwrap(),
            more,
            frag_id,
        );
        let eth = Ethernet2Header {
            source: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            destination: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            ether_type: ether_type::IPV6,
        };
        let mut pkt = Vec::new();
        eth.write(&mut pkt).unwrap();
        ipv6.write(&mut pkt).unwrap();
        frag.write(&mut pkt).unwrap();
        pkt.extend_from_slice(body);
        pkt
    };

    let first = make_frag(0, true, &first_body);
    let second = make_frag((first_body.len() / 8) as u16, false, &payload_second);
    (first, second)
}

fn xdp_packet_data(output: &[u8]) -> &[u8] {
    if output.get(12..14) == Some(&[0x86, 0xdd]) { output } else { &output[XDP_PIPE_META_LEN..] }
}

fn xdp_meta_mark(output: &[u8], frame_len: usize) -> Option<u32> {
    if output.len() == frame_len + XDP_PIPE_META_LEN {
        Some(u32::from_ne_bytes(output[..4].try_into().unwrap()))
    } else {
        assert_eq!(output.len(), frame_len, "unexpected XDP output length");
        None
    }
}

fn ipv6_addrs(frame: &[u8]) -> (Ipv6Addr, Ipv6Addr) {
    let parsed = PacketHeaders::from_ethernet_slice(frame).expect("parse Ethernet+IPv6 output");
    let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = parsed.net else {
        panic!("expected IPv6 header in output");
    };
    (ipv6.source.into(), ipv6.destination.into())
}

#[test]
fn unauthorized_wan_first_fragments_do_not_pollute_frag6_cache_wan() {
    let (spoofed_first, _) = build_ipv6_udp_fragments(remote(), wan_npt_addr(), 44444, 8080, 0x101);

    // TC ingress must drop unauthorized first fragment and leave frag6_cache_wan empty.
    {
        let mut builder = TcNat6SkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v6-tc-frag6-spoof");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = builder.open(&mut open_object).unwrap();
        {
            let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
            rodata.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(wan_ip()));
            rodata.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(60);
        }
        let skel = open_skel.load().unwrap();

        let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
        let mut out = vec![0u8; spoofed_first.len()];
        let res = skel
            .progs
            .tc_nat_wan_ingress_v6
            .test_run(ProgramInput {
                data_in: Some(&spoofed_first),
                context_in: Some(ctx.as_mut_bytes()),
                data_out: Some(&mut out),
                ..Default::default()
            })
            .expect("TC ingress test_run failed");
        assert_eq!(res.return_value as i32, TC_ACT_SHOT);
        assert_eq!(
            skel.maps.frag6_cache_wan.keys().count(),
            0,
            "unauthorized TC WAN first fragment must not pollute frag6_cache_wan",
        );
    }

    // XDP ingress must drop unauthorized first fragment and leave frag6_cache_wan empty.
    {
        let mut builder = XdpNat6SkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v6-xdp-frag6-spoof");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = builder.open(&mut open_object).unwrap();
        {
            let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
            rodata.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(wan_ip()));
            rodata.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(60);
            rodata.current_ifindex = IFINDEX;
        }
        let skel = open_skel.load().unwrap();

        let mut out = vec![0u8; spoofed_first.len() + XDP_PIPE_META_LEN];
        let res = skel
            .progs
            .ingress_nat_v6
            .test_run(ProgramInput {
                data_in: Some(&spoofed_first),
                data_out: Some(&mut out),
                ..Default::default()
            })
            .expect("XDP ingress test_run failed");
        assert_eq!(res.return_value, XDP_DROP);
        assert_eq!(
            skel.maps.frag6_cache_wan.keys().count(),
            0,
            "unauthorized XDP WAN first fragment must not pollute frag6_cache_wan",
        );
    }
}

#[test]
fn authorized_static_and_dynamic_first_fragments_populate_frag6_cache_in_tc_and_xdp() {
    // 1. TC path: static mapping ingress + dynamic egress/ingress first & follow-up fragments.
    {
        let mut builder = TcNat6SkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v6-tc-frag6-auth");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = builder.open(&mut open_object).unwrap();
        {
            let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
            rodata.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(wan_ip()));
            rodata.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(60);
        }
        let skel = open_skel.load().unwrap();

        add_static_nat6_mapping(
            &skel.maps.nat6_static_map,
            vec![StaticNatMappingV6Item { port: 8080, lan_ip: lan_host(), l4_protocol: 17 }],
        );

        let (st_first, st_second) =
            build_ipv6_udp_fragments(remote(), wan_npt_addr(), 44444, 8080, 0x201);
        for (idx, pkt) in [&st_first, &st_second].iter().enumerate() {
            let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
            let mut ctx_out = TestSkb::default();
            let mut out = vec![0u8; pkt.len()];
            let res = skel
                .progs
                .tc_nat_wan_ingress_v6
                .test_run(ProgramInput {
                    data_in: Some(pkt),
                    context_in: Some(ctx.as_mut_bytes()),
                    context_out: Some(ctx_out.as_mut_bytes()),
                    data_out: Some(&mut out),
                    ..Default::default()
                })
                .expect("TC static frag test_run failed");
            assert_eq!(res.return_value as i32, TC_ACT_OK, "static frag #{idx} must pass");
            assert_eq!(ctx_out.mark & INGRESS_CACHE_MASK, INGRESS_STATIC_MARK);
            assert_eq!(ipv6_addrs(&out).1, lan_host());
        }
        assert_eq!(skel.maps.frag6_cache_wan.keys().count(), 1);

        let (dyn_eg_first, dyn_eg_second) =
            build_ipv6_udp_fragments(lan_host(), remote(), 51515, 5353, 0x202);
        for (idx, pkt) in [&dyn_eg_first, &dyn_eg_second].iter().enumerate() {
            let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
            let mut out = vec![0u8; pkt.len()];
            let res = skel
                .progs
                .tc_nat_wan_egress_v6
                .test_run(ProgramInput {
                    data_in: Some(pkt),
                    context_in: Some(ctx.as_mut_bytes()),
                    data_out: Some(&mut out),
                    ..Default::default()
                })
                .expect("TC dynamic egress frag test_run failed");
            assert_eq!(res.return_value as i32, TC_ACT_UNSPEC, "egress frag #{idx} must pass");
            assert_eq!(ipv6_addrs(&out).0, wan_npt_addr());
        }
        assert_eq!(skel.maps.frag6_cache_lan.keys().count(), 1);

        let (dyn_in_first, dyn_in_second) =
            build_ipv6_udp_fragments(remote(), wan_npt_addr(), 5353, 51515, 0x203);
        for (idx, pkt) in [&dyn_in_first, &dyn_in_second].iter().enumerate() {
            let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
            let mut out = vec![0u8; pkt.len()];
            let res = skel
                .progs
                .tc_nat_wan_ingress_v6
                .test_run(ProgramInput {
                    data_in: Some(pkt),
                    context_in: Some(ctx.as_mut_bytes()),
                    data_out: Some(&mut out),
                    ..Default::default()
                })
                .expect("TC dynamic ingress frag test_run failed");
            assert_eq!(res.return_value as i32, TC_ACT_OK, "dynamic ingress frag #{idx} must pass");
            assert_eq!(ipv6_addrs(&out).1, lan_host());
        }
        assert_eq!(skel.maps.frag6_cache_wan.keys().count(), 2);
    }

    // 2. XDP path: static mapping ingress + dynamic egress/ingress first & follow-up fragments.
    {
        let mut builder = XdpNat6SkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v6-xdp-frag6-auth");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = builder.open(&mut open_object).unwrap();
        {
            let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
            rodata.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(wan_ip()));
            rodata.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(60);
            rodata.current_ifindex = IFINDEX;
        }
        let skel = open_skel.load().unwrap();

        add_static_nat6_mapping(
            &skel.maps.nat6_static_map,
            vec![StaticNatMappingV6Item { port: 8080, lan_ip: lan_host(), l4_protocol: 17 }],
        );

        let (st_first, st_second) =
            build_ipv6_udp_fragments(remote(), wan_npt_addr(), 44444, 8080, 0x301);
        for (idx, pkt) in [&st_first, &st_second].iter().enumerate() {
            let mut out = vec![0u8; pkt.len() + XDP_PIPE_META_LEN];
            let res = skel
                .progs
                .ingress_nat_v6
                .test_run(ProgramInput {
                    data_in: Some(pkt),
                    data_out: Some(&mut out),
                    ..Default::default()
                })
                .expect("XDP static frag test_run failed");
            assert_eq!(res.return_value, XDP_PASS, "XDP static frag #{idx} must pass");
            let out_data = res.data.as_deref().unwrap();
            assert_eq!(
                xdp_meta_mark(out_data, pkt.len()).map(|m| m & INGRESS_CACHE_MASK),
                Some(INGRESS_STATIC_MARK),
            );
            assert_eq!(ipv6_addrs(xdp_packet_data(out_data)).1, lan_host());
        }
        assert_eq!(skel.maps.frag6_cache_wan.keys().count(), 1);

        let (dyn_eg_first, dyn_eg_second) =
            build_ipv6_udp_fragments(lan_host(), remote(), 51515, 5353, 0x302);
        for (idx, pkt) in [&dyn_eg_first, &dyn_eg_second].iter().enumerate() {
            let mut out = vec![0u8; pkt.len() + XDP_PIPE_META_LEN];
            let res = skel
                .progs
                .egress_nat_v6
                .test_run(ProgramInput {
                    data_in: Some(pkt),
                    data_out: Some(&mut out),
                    ..Default::default()
                })
                .expect("XDP dynamic egress frag test_run failed");
            assert_eq!(res.return_value, XDP_PASS, "XDP egress frag #{idx} must pass");
            let out_data = res.data.as_deref().unwrap();
            assert_eq!(ipv6_addrs(xdp_packet_data(out_data)).0, wan_npt_addr());
        }
        assert_eq!(skel.maps.frag6_cache_lan.keys().count(), 1);

        let (dyn_in_first, dyn_in_second) =
            build_ipv6_udp_fragments(remote(), wan_npt_addr(), 5353, 51515, 0x303);
        for (idx, pkt) in [&dyn_in_first, &dyn_in_second].iter().enumerate() {
            let mut out = vec![0u8; pkt.len() + XDP_PIPE_META_LEN];
            let res = skel
                .progs
                .ingress_nat_v6
                .test_run(ProgramInput {
                    data_in: Some(pkt),
                    data_out: Some(&mut out),
                    ..Default::default()
                })
                .expect("XDP dynamic ingress frag test_run failed");
            assert_eq!(res.return_value, XDP_PASS, "XDP dynamic ingress frag #{idx} must pass");
            let out_data = res.data.as_deref().unwrap();
            assert_eq!(ipv6_addrs(xdp_packet_data(out_data)).1, lan_host());
        }
        assert_eq!(skel.maps.frag6_cache_wan.keys().count(), 2);
    }
}
