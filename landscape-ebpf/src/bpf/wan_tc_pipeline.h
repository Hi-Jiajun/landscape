#ifndef __LD_WAN_TC_PIPELINE_H__
#define __LD_WAN_TC_PIPELINE_H__

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "landscape.h"

#define INGRESS_STAGE_MSS 0
#define INGRESS_STAGE_PPPOE 1
#define INGRESS_STAGE_FIREWALL 2
#define INGRESS_STAGE_NAT 3
#define INGRESS_STAGE_WAN_ROUTE 4
#define INGRESS_STAGE_COUNT 5

#define EGRESS_STAGE_WAN_ROUTE 0
#define EGRESS_STAGE_MSS 1
#define EGRESS_STAGE_NAT 2
#define EGRESS_STAGE_FIREWALL 3
#define EGRESS_STAGE_PPPOE 4
#define EGRESS_STAGE_COUNT 5

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, INGRESS_STAGE_COUNT);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} ingress_stage_progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, EGRESS_STAGE_COUNT);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} egress_stage_progs SEC(".maps");

static __always_inline int wan_tc_pipeline_tailcall_ingress_from(struct __sk_buff *skb, u32 stage) {
    switch (stage) {
    default:
        bpf_tail_call(skb, &ingress_stage_progs, INGRESS_STAGE_MSS);
        bpf_tail_call(skb, &ingress_stage_progs, INGRESS_STAGE_PPPOE);
        bpf_tail_call(skb, &ingress_stage_progs, INGRESS_STAGE_FIREWALL);
        bpf_tail_call(skb, &ingress_stage_progs, INGRESS_STAGE_NAT);
        bpf_tail_call(skb, &ingress_stage_progs, INGRESS_STAGE_WAN_ROUTE);
        return TC_ACT_UNSPEC;
    case INGRESS_STAGE_MSS:
        bpf_tail_call(skb, &ingress_stage_progs, INGRESS_STAGE_PPPOE);
        bpf_tail_call(skb, &ingress_stage_progs, INGRESS_STAGE_FIREWALL);
        bpf_tail_call(skb, &ingress_stage_progs, INGRESS_STAGE_NAT);
        bpf_tail_call(skb, &ingress_stage_progs, INGRESS_STAGE_WAN_ROUTE);
        return TC_ACT_UNSPEC;
    case INGRESS_STAGE_PPPOE:
        bpf_tail_call(skb, &ingress_stage_progs, INGRESS_STAGE_FIREWALL);
        bpf_tail_call(skb, &ingress_stage_progs, INGRESS_STAGE_NAT);
        bpf_tail_call(skb, &ingress_stage_progs, INGRESS_STAGE_WAN_ROUTE);
        return TC_ACT_UNSPEC;
    case INGRESS_STAGE_FIREWALL:
        bpf_tail_call(skb, &ingress_stage_progs, INGRESS_STAGE_NAT);
        bpf_tail_call(skb, &ingress_stage_progs, INGRESS_STAGE_WAN_ROUTE);
        return TC_ACT_UNSPEC;
    case INGRESS_STAGE_NAT:
        bpf_tail_call(skb, &ingress_stage_progs, INGRESS_STAGE_WAN_ROUTE);
        return TC_ACT_UNSPEC;
    case INGRESS_STAGE_WAN_ROUTE:
        return TC_ACT_UNSPEC;
    }
}

static __always_inline int wan_tc_pipeline_tailcall_egress_from(struct __sk_buff *skb, u32 stage) {
    switch (stage) {
    default:
        bpf_tail_call(skb, &egress_stage_progs, EGRESS_STAGE_WAN_ROUTE);
        bpf_tail_call(skb, &egress_stage_progs, EGRESS_STAGE_MSS);
        bpf_tail_call(skb, &egress_stage_progs, EGRESS_STAGE_NAT);
        bpf_tail_call(skb, &egress_stage_progs, EGRESS_STAGE_FIREWALL);
        bpf_tail_call(skb, &egress_stage_progs, EGRESS_STAGE_PPPOE);
        return TC_ACT_UNSPEC;
    case EGRESS_STAGE_WAN_ROUTE:
        bpf_tail_call(skb, &egress_stage_progs, EGRESS_STAGE_MSS);
        bpf_tail_call(skb, &egress_stage_progs, EGRESS_STAGE_NAT);
        bpf_tail_call(skb, &egress_stage_progs, EGRESS_STAGE_FIREWALL);
        bpf_tail_call(skb, &egress_stage_progs, EGRESS_STAGE_PPPOE);
        return TC_ACT_UNSPEC;
    case EGRESS_STAGE_MSS:
        bpf_tail_call(skb, &egress_stage_progs, EGRESS_STAGE_NAT);
        bpf_tail_call(skb, &egress_stage_progs, EGRESS_STAGE_FIREWALL);
        bpf_tail_call(skb, &egress_stage_progs, EGRESS_STAGE_PPPOE);
        return TC_ACT_UNSPEC;
    case EGRESS_STAGE_NAT:
        bpf_tail_call(skb, &egress_stage_progs, EGRESS_STAGE_FIREWALL);
        bpf_tail_call(skb, &egress_stage_progs, EGRESS_STAGE_PPPOE);
        return TC_ACT_UNSPEC;
    case EGRESS_STAGE_FIREWALL:
        bpf_tail_call(skb, &egress_stage_progs, EGRESS_STAGE_PPPOE);
        return TC_ACT_UNSPEC;
    case EGRESS_STAGE_PPPOE:
        return TC_ACT_UNSPEC;
    }
}

static __always_inline int wan_tc_pipeline_continue_ingress(struct __sk_buff *skb, u32 stage,
                                                            int action) {
    return action == TC_ACT_UNSPEC ? wan_tc_pipeline_tailcall_ingress_from(skb, stage) : action;
}

static __always_inline int wan_tc_pipeline_continue_egress(struct __sk_buff *skb, u32 stage,
                                                           int action) {
    return action == TC_ACT_UNSPEC ? wan_tc_pipeline_tailcall_egress_from(skb, stage) : action;
}

#endif
