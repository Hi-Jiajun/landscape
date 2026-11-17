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

// Family-agnostic PPPoE encap: the per-family entry program passes the
// family flag (the chain root already forked on the L3 protocol), and
// the hop slot likewise comes from the entry.
static __always_inline void tc_pppoe_encap(struct __sk_buff *skb, bool is_v6) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return;

    (void)is_v6;

    // kfunc: insert the 8 byte PPPoE session header, derive the PPP
    // protocol from the inner IP version, set skb->protocol.
    if (bpf_skb_pppoe_encap(skb, pppoe_tmpl.session_id, 0) < 0) return;

    struct pppoe_l2_tmpl l2 = {
        .dmac = {pppoe_tmpl.dmac[0], pppoe_tmpl.dmac[1], pppoe_tmpl.dmac[2], pppoe_tmpl.dmac[3],
                 pppoe_tmpl.dmac[4], pppoe_tmpl.dmac[5]},
        .smac = {pppoe_tmpl.smac[0], pppoe_tmpl.smac[1], pppoe_tmpl.smac[2], pppoe_tmpl.smac[3],
                 pppoe_tmpl.smac[4], pppoe_tmpl.smac[5]},
        .eth_proto = pppoe_tmpl.eth_proto,
    };

    bpf_skb_store_bytes(skb, 0, &l2, sizeof(l2), 0);
}

// Terminal per-link egress stage: encapsulates only the packets that
// traversed this link's chain, with this link's session template.
SEC("tc/egress")
int tc_pppoe_wan_egress_v4(struct __sk_buff *skb) {
    tc_pppoe_encap(skb, false);

    TC_FROM_LAN_CHAIN_NEXT(skb, TC_SLOT_V4);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}

SEC("tc/egress")
int tc_pppoe_wan_egress_v6(struct __sk_buff *skb) {
    tc_pppoe_encap(skb, true);

    TC_FROM_LAN_CHAIN_NEXT(skb, TC_SLOT_V6);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}
