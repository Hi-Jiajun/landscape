#ifndef __LD_FIREWALL_SHARE_H__
#define __LD_FIREWALL_SHARE_H__
#include <bpf/bpf_helpers.h>
#include "../landscape.h"

struct firewall_action {
    __u32 mark;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct firewall_action);
    __uint(max_entries, 65535);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} firewall_block_ip4_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv6_lpm_key);
    __type(value, struct firewall_action);
    __uint(max_entries, 65535);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} firewall_block_ip6_map SEC(".maps");

enum fw_ct_state {
    FW_STATE_NONE = 0,
    FW_STATE_SYN_SENT = 1,
    FW_STATE_ESTABLISHED = 2,
    FW_STATE_FIN_WAIT = 3,
    FW_STATE_CLOSED = 4,
    FW_STATE_UDP = 5,
    FW_STATE_ICMP = 6,
};

struct ct_tuple4 {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8   protocol;
    __u8   _pad[3];
};

struct ct_tuple6 {
    union u_inet_addr src_ip;
    union u_inet_addr dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8   protocol;
    __u8   _pad[3];
};

struct ct_entry {
    __u64 last_seen_ns;
    __u32 packets;
    __u32 bytes;
    __u8  state;
    __u8  flags;
    __u8  _pad[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ct_tuple4);
    __type(value, struct ct_entry);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} firewall_state4_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ct_tuple6);
    __type(value, struct ct_entry);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} firewall_state6_map SEC(".maps");

#define CT_TIMEOUT_SYN_SENT_NS  (30ULL * 1000000000ULL)    // 30 seconds
#define CT_TIMEOUT_ESTAB_NS     (7200ULL * 1000000000ULL)  // 2 hours
#define CT_TIMEOUT_FIN_WAIT_NS  (60ULL * 1000000000ULL)    // 60 seconds
#define CT_TIMEOUT_UDP_NS       (180ULL * 1000000000ULL)   // 3 minutes
#define CT_TIMEOUT_ICMP_NS      (30ULL * 1000000000ULL)    // 30 seconds

struct ratelimit_entry {
    __u64 last_time_ns;
    __u32 tokens;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct ratelimit_entry);
    __uint(max_entries, 16384);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} firewall_ratelimit4_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, union u_inet_addr);
    __type(value, struct ratelimit_entry);
    __uint(max_entries, 16384);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} firewall_ratelimit6_map SEC(".maps");

struct firewall_global_cfg {
    __u8 allow_wan_ping;     // 1 = allow (default), 0 = drop unsolicited ping from WAN
    __u8 syn_flood_protect;  // 1 = enabled (default), 0 = disabled
    __u8 _pad[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct firewall_global_cfg);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} firewall_config_map SEC(".maps");

struct port_allow_key {
    __be16 port;
    __u8   protocol;
    __u8   _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_allow_key);
    __type(value, __u8);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} firewall_allow_ports_map SEC(".maps");

#define FIREWALL_CREATE_CONN 1
#define FIREWALL_DELETE_CONN 2

struct firewall_conn_metric_event {
    union u_inet_addr src_addr;
    union u_inet_addr dst_addr;
    u16 src_port;
    u16 dst_port;
    u64 create_time;
    u64 time;
    u64 ingress_bytes;
    u64 ingress_packets;
    u64 egress_bytes;
    u64 egress_packets;
    u8 l4_proto;
    u8 l3_proto;
    u8 flow_id;
    u8 trace_id;
} __firewall_conn_metric_event;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} firewall_conn_metric_events SEC(".maps");

#endif /* __LD_FIREWALL_SHARE_H__ */
