#ifndef __LD_ROUTE_MODE_H__
#define __LD_ROUTE_MODE_H__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define ROUTE_BALANCE_DST_IP 0
#define ROUTE_BALANCE_FIVE_TUPLE 1

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u8);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rt_flow_mode_map SEC(".maps");

struct route_flow_target_key {
    __u32 flow_id;
    __u32 ifindex;
} _route_flow_target_key;

struct route_conn_value {
    __u32 mark_value;
    __u32 ifindex;
} _route_conn_value;

static __always_inline bool route_flow_is_five_tuple(u32 flow_id) {
    u8 *mode = bpf_map_lookup_elem(&rt_flow_mode_map, &flow_id);
    return mode != NULL && *mode == ROUTE_BALANCE_FIVE_TUPLE;
}

static __always_inline u32 route_avalanche32(u32 h) {
    h ^= h >> 16;
    h *= 0x85ebca6bU;
    h ^= h >> 13;
    h *= 0xc2b2ae35U;
    h ^= h >> 16;
    return h;
}

#endif /* __LD_ROUTE_MODE_H__ */
