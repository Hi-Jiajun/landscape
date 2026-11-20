#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "base/pppoe_def.h"
#include "chain/tc_cb.h"
#include "chain/tc_stage.h"
#include "chain/tc_wan_exit_maps.h"

char LICENSE[] SEC("license") = "GPL";

struct pppoe_egress_tmpl {
    unsigned char dmac[6];
    unsigned char smac[6];
    __be16 eth_proto;
    __u8 ver_type;
    __u8 code;
    __be16 session_id;
    __be16 length;
    __be16 protocol;
} __attribute__((packed));

// Only the Ethernet header is written by the program; the PPPoE session
// header is filled in by bpf_skb_pppoe_encap().
struct pppoe_l2_tmpl {
    unsigned char dmac[6];
    unsigned char smac[6];
    __be16 eth_proto;
} __attribute__((packed));

const volatile struct pppoe_egress_tmpl pppoe_tmpl = {};

// The kernel writes the PPPoE session header (version/type/code/sid/length
// and the PPP protocol) from the session id, and sets skb->protocol to
// ETH_P_PPP_SES so the packet reaches the PPPoE GRO/GSO handlers.
// Requires the bpf_skb_pppoe_encap() kfunc.
extern int bpf_skb_pppoe_encap(struct __sk_buff *skb, __be16 sid, __u64 flags) __ksym;

#define PPPOE_INNER_MTU 1492U
#define PPPOE_MAX_INNER_ETH_LEN (14U + PPPOE_INNER_MTU)

static __always_inline int tc_pppoe_inner_l4_proto(struct __sk_buff *skb, bool is_v6,
                                                   __u8 *l4_proto, __u32 *l4_off) {
    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;

    if (!is_v6) {
        struct iphdr *iph = (struct iphdr *)(data + sizeof(struct ethhdr));
        __u8 ihl = 0;
        if (likely((char *)(iph + 1) <= data_end)) {
            ihl = iph->ihl;
            *l4_proto = iph->protocol;
        } else {
            if (skb->len < sizeof(struct ethhdr) + sizeof(struct iphdr)) return -1;
            struct iphdr iph_copy;
            if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &iph_copy, sizeof(iph_copy)) < 0)
                return -1;
            ihl = iph_copy.ihl;
            *l4_proto = iph_copy.protocol;
        }
        if (ihl < 5) return -1;
        *l4_off = sizeof(struct ethhdr) + ((__u32)ihl * 4U);
        return 0;
    }

    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + sizeof(struct ethhdr));
    __u8 nexthdr = 0;
    if (likely((char *)(ip6h + 1) <= data_end)) {
        nexthdr = ip6h->nexthdr;
    } else {
        if (skb->len < sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) return -1;
        if (bpf_skb_load_bytes(skb,
                               sizeof(struct ethhdr) + __builtin_offsetof(struct ipv6hdr, nexthdr),
                               &nexthdr, sizeof(nexthdr)) < 0)
            return -1;
    }

    __u32 ext_off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    for (int i = 0; i < 6; i++) {
        if (nexthdr == 0 || nexthdr == 43 || nexthdr == 60) {
            __u8 hdr[2];
            if (bpf_skb_load_bytes(skb, ext_off, hdr, sizeof(hdr)) < 0) return -1;
            nexthdr = hdr[0];
            ext_off += ((__u32)hdr[1] + 1U) * 8U;
        } else if (nexthdr == 44) {
            if (bpf_skb_load_bytes(skb, ext_off, &nexthdr, sizeof(nexthdr)) < 0) return -1;
            ext_off += 8U;
        } else {
            break;
        }
    }

    *l4_proto = nexthdr;
    *l4_off = ext_off;
    return 0;
}

// Family-agnostic PPPoE encap: the per-family entry program passes the
// family flag (the chain root already forked on the L3 protocol), and
// the hop slot likewise comes from the entry.
static __always_inline int tc_pppoe_encap(struct __sk_buff *skb, bool is_v6) {
    if (skb->gso_segs <= 1 && skb->len > PPPOE_MAX_INNER_ETH_LEN) return TC_ACT_SHOT;

    __u8 l4_proto = 0;
    __u32 l4_off = 0;
    if (tc_pppoe_inner_l4_proto(skb, is_v6, &l4_proto, &l4_off) < 0) return TC_ACT_SHOT;

    // TCP GSO requires flags == 0 so skb_decrease_gso_size() shrinks gso_size by 8B.
    // Non-TCP GSO (SKB_GSO_UDP_L4) requires BPF_F_ADJ_ROOM_FIXED_GSO (otherwise -ENOTSUPP),
    // which keeps gso_size unchanged; reject superpackets whose per-segment size would
    // exceed the 1492B PPPoE inner MTU after adding the 8B PPPoE header.
    if (skb->gso_segs > 1 && l4_proto != IPPROTO_TCP) {
        __u32 l4_hdr_len = (l4_proto == IPPROTO_UDP) ? (__u32)sizeof(struct udphdr) : 0U;
        if (l4_off > PPPOE_MAX_INNER_ETH_LEN || l4_hdr_len > PPPOE_MAX_INNER_ETH_LEN - l4_off)
            return TC_ACT_SHOT;
        __u32 seg_hdr_len = l4_off + l4_hdr_len;
        if (skb->gso_size == 0 || skb->gso_size > PPPOE_MAX_INNER_ETH_LEN - seg_hdr_len)
            return TC_ACT_SHOT;
    }

    __u64 flags = (l4_proto == IPPROTO_TCP) ? 0ULL : (__u64)BPF_F_ADJ_ROOM_FIXED_GSO;

    // kfunc: insert the 8 byte PPPoE session header, derive the PPP
    // protocol from the inner IP version, set skb->protocol.
    if (bpf_skb_pppoe_encap(skb, pppoe_tmpl.session_id, flags) < 0) return TC_ACT_SHOT;

    struct pppoe_l2_tmpl l2 = {
        .dmac = {pppoe_tmpl.dmac[0], pppoe_tmpl.dmac[1], pppoe_tmpl.dmac[2], pppoe_tmpl.dmac[3],
                 pppoe_tmpl.dmac[4], pppoe_tmpl.dmac[5]},
        .smac = {pppoe_tmpl.smac[0], pppoe_tmpl.smac[1], pppoe_tmpl.smac[2], pppoe_tmpl.smac[3],
                 pppoe_tmpl.smac[4], pppoe_tmpl.smac[5]},
        .eth_proto = pppoe_tmpl.eth_proto,
    };

    if (bpf_skb_store_bytes(skb, 0, &l2, sizeof(l2), 0) < 0) return TC_ACT_SHOT;

    return TC_ACT_OK;
}

// Terminal per-link egress stage: encapsulates only the packets that
// traversed this link's chain, with this link's session template.
SEC("tc/egress")
int tc_pppoe_wan_egress_v4(struct __sk_buff *skb) {
    if (tc_pppoe_encap(skb, false) != TC_ACT_OK) return TC_ACT_SHOT;

    TC_FROM_LAN_CHAIN_NEXT(skb, TC_SLOT_V4);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}

SEC("tc/egress")
int tc_pppoe_wan_egress_v6(struct __sk_buff *skb) {
    if (tc_pppoe_encap(skb, true) != TC_ACT_OK) return TC_ACT_SHOT;

    TC_FROM_LAN_CHAIN_NEXT(skb, TC_SLOT_V6);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}
