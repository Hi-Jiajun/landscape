#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "landscape.h"
#include "chain/tc_stage.h"
#include "chain/tc_wan_exit_maps.h"
#include "firewall/firewall_share.h"
#include "scanner/skb_scanner4.h"
#include "scanner/skb_scanner6.h"
#include "fragment/frag4.h"
#include "fragment/frag6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

static __always_inline int fw_do_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< fw_do_egress <<<"

    bool is_v4;
    if (current_pkg_type(skb, current_l3_offset, &is_v4) != TC_ACT_OK) return TC_ACT_OK;

    if (is_v4) {
        struct scan_ipv4_idx idx = {};
        if (scan_ipv4_into_idx(skb, current_l3_offset, &idx) != LD_SCAN_OK) return TC_ACT_OK;

        struct iphdr *iph;
        if (VALIDATE_READ_DATA(skb, &iph, current_l3_offset, sizeof(*iph))) return TC_ACT_OK;
        __be32 saddr = iph->saddr;
        __be32 daddr = iph->daddr;

        bool is_icmpx = false;
        if (idx.fragment_type < FRAG_MIDDLE && idx.l4_protocol == IPPROTO_ICMP)
            is_icmpx = scan_ipv4_upgrade_icmp(skb, current_l3_offset, &idx, &saddr);

        if (likely(!is_icmpx)) {
            __be16 sport = 0, dport = 0;
            if (idx.fragment_type == FRAG_FIRST &&
                (idx.l4_protocol == IPPROTO_TCP || idx.l4_protocol == IPPROTO_UDP)) {
                __be16 *ports;
                if (VALIDATE_READ_DATA(skb, &ports, idx.l4_offset, sizeof(__be16) * 2))
                    return TC_ACT_SHOT;
                sport = ports[0];
                dport = ports[1];
            }
            if (frag4_track(&idx, saddr, daddr, &sport, &dport) != TC_ACT_OK) return TC_ACT_SHOT;
        }

        struct ipv4_lpm_key block_search_key = {
            .prefixlen = 32,
            .addr = daddr,
        };
        if (unlikely(bpf_map_lookup_elem(&firewall_block_ip4_map, &block_search_key)))
            return TC_ACT_SHOT;

        if (likely(!is_icmpx && (idx.l4_protocol == IPPROTO_TCP || idx.l4_protocol == IPPROTO_UDP))) {
            struct ct_tuple4 reply_k = {
                .src_ip = daddr,
                .dst_ip = saddr,
                .src_port = dport,
                .dst_port = sport,
                .protocol = idx.l4_protocol,
            };
            struct ct_entry ent = {
                .last_seen_ns = bpf_ktime_get_ns(),
                .packets = 1,
                .bytes = skb->len,
                .state = 1,
            };
            bpf_map_update_elem(&firewall_state4_map, &reply_k, &ent, BPF_ANY);
        }
    } else {
        struct scan_ipv6_idx idx = {};
        if (scan_ipv6_into_idx(skb, current_l3_offset, &idx) != LD_SCAN_OK) return TC_ACT_OK;

        struct ipv6hdr *ip6h;
        if (VALIDATE_READ_DATA(skb, &ip6h, current_l3_offset, sizeof(*ip6h))) return TC_ACT_OK;
        struct in6_addr saddr = ip6h->saddr;
        struct in6_addr daddr = ip6h->daddr;

        bool is_icmpx = false;
        if (idx.fragment_type < FRAG_MIDDLE && idx.l4_protocol == IPPROTO_ICMPV6)
            is_icmpx = scan_ipv6_upgrade_icmp(skb, current_l3_offset, &idx, &saddr);

        if (likely(!is_icmpx)) {
            __be16 sport = 0, dport = 0;
            if (idx.fragment_type == FRAG_FIRST &&
                (idx.l4_protocol == IPPROTO_TCP || idx.l4_protocol == IPPROTO_UDP)) {
                __be16 *ports;
                if (VALIDATE_READ_DATA(skb, &ports, idx.l4_offset, sizeof(__be16) * 2))
                    return TC_ACT_SHOT;
                sport = ports[0];
                dport = ports[1];
            }
            if (frag6_track(&idx, &saddr, &daddr, &sport, &dport) != TC_ACT_OK) return TC_ACT_SHOT;
        }

        struct ipv6_lpm_key block_search_key = {
            .prefixlen = 128,
        };
        __builtin_memcpy(&block_search_key.addr, &daddr, sizeof(block_search_key.addr));
        if (unlikely(bpf_map_lookup_elem(&firewall_block_ip6_map, &block_search_key)))
            return TC_ACT_SHOT;

        if (likely(!is_icmpx && (idx.l4_protocol == IPPROTO_TCP || idx.l4_protocol == IPPROTO_UDP))) {
            struct ct_tuple6 reply_k = {
                .src_ip = daddr,
                .dst_ip = saddr,
                .src_port = dport,
                .dst_port = sport,
                .protocol = idx.l4_protocol,
            };
            struct ct_entry ent = {
                .last_seen_ns = bpf_ktime_get_ns(),
                .packets = 1,
                .bytes = skb->len,
                .state = 1,
            };
            bpf_map_update_elem(&firewall_state6_map, &reply_k, &ent, BPF_ANY);
        }
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int fw_do_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< fw_do_ingress <<<"

    bool is_v4;
    if (current_pkg_type(skb, current_l3_offset, &is_v4) != TC_ACT_OK) return TC_ACT_OK;

    if (is_v4) {
        struct scan_ipv4_idx idx = {};
        if (scan_ipv4_into_idx(skb, current_l3_offset, &idx) != LD_SCAN_OK) return TC_ACT_OK;

        struct iphdr *iph;
        if (VALIDATE_READ_DATA(skb, &iph, current_l3_offset, sizeof(*iph))) return TC_ACT_OK;
        __be32 saddr = iph->saddr;
        __be32 daddr = iph->daddr;

        bool is_icmpx = false;
        if (idx.fragment_type < FRAG_MIDDLE && idx.l4_protocol == IPPROTO_ICMP)
            is_icmpx = scan_ipv4_upgrade_icmp(skb, current_l3_offset, &idx, &saddr);

        if (likely(!is_icmpx)) {
            __be16 sport = 0, dport = 0;
            if (idx.fragment_type == FRAG_FIRST &&
                (idx.l4_protocol == IPPROTO_TCP || idx.l4_protocol == IPPROTO_UDP)) {
                __be16 *ports;
                if (VALIDATE_READ_DATA(skb, &ports, idx.l4_offset, sizeof(__be16) * 2))
                    return TC_ACT_SHOT;
                sport = ports[0];
                dport = ports[1];
            }
            if (frag4_track(&idx, saddr, daddr, &sport, &dport) != TC_ACT_OK) return TC_ACT_SHOT;
        }

        struct ipv4_lpm_key block_search_key = {
            .prefixlen = 32,
            .addr = saddr,
        };
        if (unlikely(bpf_map_lookup_elem(&firewall_block_ip4_map, &block_search_key)))
            return TC_ACT_SHOT;

        if (likely(!is_icmpx && (idx.l4_protocol == IPPROTO_TCP || idx.l4_protocol == IPPROTO_UDP))) {
            struct ct_tuple4 match_k = {
                .src_ip = saddr,
                .dst_ip = daddr,
                .src_port = sport,
                .dst_port = dport,
                .protocol = idx.l4_protocol,
            };
            struct ct_entry *ent = bpf_map_lookup_elem(&firewall_state4_map, &match_k);
            if (ent) {
                ent->last_seen_ns = bpf_ktime_get_ns();
                ent->packets++;
                ent->bytes += skb->len;
            }
        }
    } else {
        struct scan_ipv6_idx idx = {};
        if (scan_ipv6_into_idx(skb, current_l3_offset, &idx) != LD_SCAN_OK) return TC_ACT_OK;

        struct ipv6hdr *ip6h;
        if (VALIDATE_READ_DATA(skb, &ip6h, current_l3_offset, sizeof(*ip6h))) return TC_ACT_OK;
        struct in6_addr saddr = ip6h->saddr;
        struct in6_addr daddr = ip6h->daddr;

        bool is_icmpx = false;
        if (idx.fragment_type < FRAG_MIDDLE && idx.l4_protocol == IPPROTO_ICMPV6)
            is_icmpx = scan_ipv6_upgrade_icmp(skb, current_l3_offset, &idx, &saddr);

        if (likely(!is_icmpx)) {
            __be16 sport = 0, dport = 0;
            if (idx.fragment_type == FRAG_FIRST &&
                (idx.l4_protocol == IPPROTO_TCP || idx.l4_protocol == IPPROTO_UDP)) {
                __be16 *ports;
                if (VALIDATE_READ_DATA(skb, &ports, idx.l4_offset, sizeof(__be16) * 2))
                    return TC_ACT_SHOT;
                sport = ports[0];
                dport = ports[1];
            }
            if (frag6_track(&idx, &saddr, &daddr, &sport, &dport) != TC_ACT_OK) return TC_ACT_SHOT;
        }

        struct ipv6_lpm_key block_search_key = {
            .prefixlen = 128,
        };
        __builtin_memcpy(&block_search_key.addr, &saddr, sizeof(block_search_key.addr));
        if (unlikely(bpf_map_lookup_elem(&firewall_block_ip6_map, &block_search_key)))
            return TC_ACT_SHOT;

        if (likely(!is_icmpx && (idx.l4_protocol == IPPROTO_TCP || idx.l4_protocol == IPPROTO_UDP))) {
            // Allow DHCPv6 client inbound (UDP port 546)
            if (idx.l4_protocol == IPPROTO_UDP && bpf_ntohs(dport) == 546)
                return TC_ACT_OK;

            struct ct_tuple6 match_k = {
                .src_ip = saddr,
                .dst_ip = daddr,
                .src_port = sport,
                .dst_port = dport,
                .protocol = idx.l4_protocol,
            };
            struct ct_entry *ent = bpf_map_lookup_elem(&firewall_state6_map, &match_k);
            if (ent) {
                ent->last_seen_ns = bpf_ktime_get_ns();
                ent->packets++;
                ent->bytes += skb->len;
            } else {
                struct port_allow_key pkey = {
                    .port = dport,
                    .protocol = idx.l4_protocol,
                };
                if (!bpf_map_lookup_elem(&firewall_allow_ports_map, &pkey)) {
                    // Default open ports for Landscape management (e.g. 6443)
                    if (bpf_ntohs(dport) != 6443) {
                        return TC_ACT_SHOT;
                    }
                }
            }
        }
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

SEC("tc/egress")
int tc_firewall_wan_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< tc_firewall_wan_egress <<<"

    if (unlikely(fw_do_egress(skb) == TC_ACT_SHOT)) return TC_ACT_SHOT;

    TC_CHAIN_WAN_EGRESS(skb);
    bpf_tail_call(skb, &tc_pipe_exits_wan_egress, TC_NEXT_SLOT);
    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int tc_firewall_wan_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< tc_firewall_wan_ingress <<<"

    if (unlikely(fw_do_ingress(skb) == TC_ACT_SHOT)) return TC_ACT_SHOT;

    TC_CHAIN_WAN_INGRESS(skb);
    bpf_tail_call(skb, &tc_pipe_exits_wan_ingress, TC_NEXT_SLOT);
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}
