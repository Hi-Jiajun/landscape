// SPDX-License-Identifier: GPL-2.0-or-later
/* Route data-plane micro-benchmarks (IPv4 and IPv6 LAN-to-WAN paths).
 *
 * Variants invoke the production functions from route4_path.h / route6_path.h
 * directly via single-shot SEC("tc") entrypoints under kernel-side `repeat`
 * batching:
 *
 *  - baseline_v4 / baseline_v6:
 *      scan_route_packet + route4/6_read_context_from_scan + broadcast guard
 *  - lan_cache_hit_v4 / lan_cache_hit_v6:
 *      route4/6_search_cache_in_lan hitting LAN_CACHE (after a production
 *      WAN_CACHE miss), covering both L3/PPPoE targets (has_mac = 0) and
 *      Ethernet targets (has_mac = 1, gateway MAC lookup + L2 header store)
 *  - lan_cold_resolve_v4 / lan_cold_resolve_v6:
 *      route4/6_flow_verdict (match_flow_id MAC + IP LPM + flow_ip_map LPM +
 *      flow_dns_map LRU hash + priority arbitration) followed by
 *      route4/6_pick_wan_and_send_by_flow_id (256-slot ECMP hash lookup)
 *  - lan_cold_full_v4 / lan_cold_full_v6:
 *      complete uncached LAN-ingress lookup sequence: cache search miss +
 *      rt4/6_lan_map LPM check miss + flow_verdict + slot pick (omitting
 *      cache insertion so every kernel-side repeat stays cold)
 *  - lan_five_tuple_hit_v4 / lan_five_tuple_hit_v6:
 *      steady-state FiveTuple ECMP packet hitting LAN_CACHE (ifindex == 0) +
 *      lazy L4 port parse + rt4/6_conn_map LRU lookup + rt4/6_flow_targets
 *      pinned target lookup + redirect
 *  - lan_l4_port_cold_v4 / lan_l4_port_cold_v6:
 *      cold packet on a flow with active L4 port-range rules (flow_l4_meta_map
 *      + flow_l4_rule_map bounded scan overriding destination IP prefix mark)
 *
 * Every entrypoint returns TC_ACT_OK so BPF_PROG_TEST_RUN never attempts a
 * live netdev redirect, while bench_sink accumulates the resolved flow_mark
 * (or BENCH_FAIL on any unexpected verdict) so Rust asserts every single run
 * took the exact expected branch.
 */
#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "route/route4_context.h"
#include "route/route4_path.h"
#include "route/route6_context.h"
#include "route/route6_path.h"

#define BENCH_FAIL 0xdeadbeefULL

const volatile u32 current_l3_offset = 14;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} bench_sink SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

static __always_inline void bench_sink_add(u64 value) {
    u32 index = 0;
    u64 *acc = bpf_map_lookup_elem(&bench_sink, &index);
    if (acc) *acc += value;
}

static __always_inline int bench_read4(struct __sk_buff *skb, struct route4_context *context) {
    struct route_view view = {0};
    if (scan_route_packet(skb, current_l3_offset, &view) != TC_ACT_OK) return 0;
    if (route4_read_context_from_scan(skb, &view, context) != TC_ACT_OK) return 0;
    if (unlikely(is_broadcast_ip4(context->daddr))) return 0;
    return 1;
}

static __always_inline int bench_read6(struct __sk_buff *skb, struct route6_context *context) {
    struct route_view view = {0};
    if (scan_route_packet(skb, current_l3_offset, &view) != TC_ACT_OK) return 0;
    if (route6_read_context_from_scan(skb, &view, context) != TC_ACT_OK) return 0;
    if (unlikely(is_broadcast_ip6(context->daddr.in6_u.u6_addr8))) return 0;
    return 1;
}

/* -- IPv4 benchmarks ------------------------------------------------------ */

SEC("tc")
int bench_route4_baseline(struct __sk_buff *skb) {
    struct route4_context context = {0};

    if (!bench_read4(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    bench_sink_add(1);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route4_lan_cache_hit(struct __sk_buff *skb) {
    struct route4_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read4(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = route4_search_cache_in_lan(skb, current_l3_offset, &context, &flow_mark);
    bench_sink_add(rc == TC_ACT_REDIRECT && flow_mark != 0 ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route4_lan_cold_resolve(struct __sk_buff *skb) {
    struct route4_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read4(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (route4_flow_verdict(skb, current_l3_offset, &context, &flow_mark) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = route4_pick_wan_and_send_by_flow_id(skb, current_l3_offset, &context, flow_mark);
    bench_sink_add(rc == TC_ACT_REDIRECT && flow_mark != 0 ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route4_lan_cold_full(struct __sk_buff *skb) {
    struct route4_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read4(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (route4_search_cache_in_lan(skb, current_l3_offset, &context, &flow_mark) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (tc_route4_lan_redirect_check_in_lan(skb, current_l3_offset, &context) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (route4_flow_verdict(skb, current_l3_offset, &context, &flow_mark) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = route4_pick_wan_and_send_by_flow_id(skb, current_l3_offset, &context, flow_mark);
    bench_sink_add(rc == TC_ACT_REDIRECT && flow_mark != 0 ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route4_lan_five_tuple_hit(struct __sk_buff *skb) {
    struct route4_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read4(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = route4_search_cache_in_lan(skb, current_l3_offset, &context, &flow_mark);
    bench_sink_add(rc == TC_ACT_REDIRECT && flow_mark != 0 ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route4_lan_l4_port_cold(struct __sk_buff *skb) {
    struct route4_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read4(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (route4_flow_verdict(skb, current_l3_offset, &context, &flow_mark) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = route4_pick_wan_and_send_by_flow_id(skb, current_l3_offset, &context, flow_mark);
    bench_sink_add(rc == TC_ACT_REDIRECT && flow_mark != 0 ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

/* -- IPv6 benchmarks ------------------------------------------------------ */

SEC("tc")
int bench_route6_baseline(struct __sk_buff *skb) {
    struct route6_context context = {0};

    if (!bench_read6(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    bench_sink_add(1);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route6_lan_cache_hit(struct __sk_buff *skb) {
    struct route6_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read6(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = route6_search_cache_in_lan(skb, current_l3_offset, &context, &flow_mark);
    bench_sink_add(rc == TC_ACT_REDIRECT && flow_mark != 0 ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route6_lan_cold_resolve(struct __sk_buff *skb) {
    struct route6_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read6(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (route6_flow_verdict(skb, current_l3_offset, &context, &flow_mark) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = route6_pick_wan_and_send_by_flow_id(skb, current_l3_offset, &context, flow_mark);
    bench_sink_add(rc == TC_ACT_REDIRECT && flow_mark != 0 ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route6_lan_cold_full(struct __sk_buff *skb) {
    struct route6_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read6(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (route6_search_cache_in_lan(skb, current_l3_offset, &context, &flow_mark) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (tc_route6_lan_redirect_check_in_lan(skb, current_l3_offset, &context) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (route6_flow_verdict(skb, current_l3_offset, &context, &flow_mark) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = route6_pick_wan_and_send_by_flow_id(skb, current_l3_offset, &context, flow_mark);
    bench_sink_add(rc == TC_ACT_REDIRECT && flow_mark != 0 ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route6_lan_five_tuple_hit(struct __sk_buff *skb) {
    struct route6_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read6(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = route6_search_cache_in_lan(skb, current_l3_offset, &context, &flow_mark);
    bench_sink_add(rc == TC_ACT_REDIRECT && flow_mark != 0 ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route6_lan_l4_port_cold(struct __sk_buff *skb) {
    struct route6_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read6(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (route6_flow_verdict(skb, current_l3_offset, &context, &flow_mark) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = route6_pick_wan_and_send_by_flow_id(skb, current_l3_offset, &context, flow_mark);
    bench_sink_add(rc == TC_ACT_REDIRECT && flow_mark != 0 ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}
