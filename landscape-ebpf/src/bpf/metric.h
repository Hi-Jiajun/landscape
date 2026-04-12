#ifndef __LD_METRIC_SHARE_H__
#define __LD_METRIC_SHARE_H__
#include <bpf/bpf_helpers.h>
#include "landscape.h"

struct net_metric_key {
    union u_inet_addr src_addr;
    union u_inet_addr dst_addr;
    u16 src_port;
    u16 dst_port;
    u8 l4_proto;
    u8 l3_proto;
    u8 flow_id;
    u8 trace_id;
} __net_metric_key;

struct net_metric_value {
    u64 pkt_num;
    u64 pkt_sizes;
} __net_metric_value;

struct each_metric_bucket_map {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(key_size, sizeof(struct net_metric_key));
    __uint(value_size, sizeof(struct net_metric_value));
    __uint(max_entries, 65536);
} __each_metric_bucket_map SEC(".maps");

//
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, u32);
    __uint(max_entries, 8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct each_metric_bucket_map);
} metric_bucket_map SEC(".maps");

#endif /* __LD_METRIC_SHARE_H__ */
