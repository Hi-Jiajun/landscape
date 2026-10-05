#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "landscape.h"
#include "chain/tc_stage.h"
#include "chain/tc_wan_exit_maps.h"
#include "firewall/firewall_share.h"
#include "scanner/skb_scanner4.h"
#include "scanner/skb_scanner6.h"
#include "scanner/skb_read.h"
#include "fragment/frag4.h"
#include "fragment/frag6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

static __always_inline bool is_port_allowed(__be16 dport, __u8 proto) {
    u16 port_host = bpf_ntohs(dport);
    // Standard management & service fallback: Landscape Web UI (6443, 6300), Nginx (80, 443)
    if (proto == IPPROTO_TCP && (port_host == 6443 || port_host == 6300 || port_host == 80 || port_host == 443)) {
        return true;
    }
    struct port_allow_key exact_key = {
        .port = dport,
        .protocol = proto,
        ._pad = 0,
    };
    if (bpf_map_lookup_elem(&firewall_allow_ports_map, &exact_key)) {
        return true;
    }
    struct port_allow_key any_key = {
        .port = dport,
        .protocol = 0,
        ._pad = 0,
    };
    if (bpf_map_lookup_elem(&firewall_allow_ports_map, &any_key)) {
        return true;
    }
    return false;
}

static __always_inline bool check_rate_limit4(__be32 src_ip) {
    u64 now = bpf_ktime_get_ns();
    struct ratelimit_entry *entry = bpf_map_lookup_elem(&firewall_ratelimit4_map, &src_ip);
    if (!entry) {
        struct ratelimit_entry new_entry = {
            .last_time_ns = now,
            .tokens = 40,
            ._pad = 0,
        };
        bpf_map_update_elem(&firewall_ratelimit4_map, &src_ip, &new_entry, BPF_ANY);
        return true;
    }
    u64 elapsed = (now > entry->last_time_ns) ? (now - entry->last_time_ns) : 0;
    // 1 token per 50ms = 20 tokens/sec
    u32 add_tokens = (u32)(elapsed / 50000000ULL);
    if (add_tokens > 0) {
        entry->tokens += add_tokens;
        if (entry->tokens > 50) entry->tokens = 50;
        entry->last_time_ns = now;
    }
    if (entry->tokens > 0) {
        entry->tokens--;
        return true;
    }
    return false;
}

static __always_inline bool check_rate_limit6(const union u_inet_addr *src_ip) {
    u64 now = bpf_ktime_get_ns();
    struct ratelimit_entry *entry = bpf_map_lookup_elem(&firewall_ratelimit6_map, src_ip);
    if (!entry) {
        struct ratelimit_entry new_entry = {
            .last_time_ns = now,
            .tokens = 40,
            ._pad = 0,
        };
        bpf_map_update_elem(&firewall_ratelimit6_map, src_ip, &new_entry, BPF_ANY);
        return true;
    }
    u64 elapsed = (now > entry->last_time_ns) ? (now - entry->last_time_ns) : 0;
    u32 add_tokens = (u32)(elapsed / 50000000ULL);
    if (add_tokens > 0) {
        entry->tokens += add_tokens;
        if (entry->tokens > 50) entry->tokens = 50;
        entry->last_time_ns = now;
    }
    if (entry->tokens > 0) {
        entry->tokens--;
        return true;
    }
    return false;
}

static __always_inline bool is_ct_expired(const struct ct_entry *ent, u64 now_ns) {
    u64 timeout = CT_TIMEOUT_ESTAB_NS;
    if (ent->state == FW_STATE_SYN_SENT) {
        timeout = CT_TIMEOUT_SYN_SENT_NS;
    } else if (ent->state == FW_STATE_FIN_WAIT) {
        timeout = CT_TIMEOUT_FIN_WAIT_NS;
    } else if (ent->state == FW_STATE_UDP) {
        timeout = CT_TIMEOUT_UDP_NS;
    } else if (ent->state == FW_STATE_ICMP) {
        timeout = CT_TIMEOUT_ICMP_NS;
    }
    return (now_ns > ent->last_seen_ns && (now_ns - ent->last_seen_ns) > timeout);
}

static __always_inline bool is_wan_ping_allowed(void) {
    __u32 key = 0;
    struct firewall_global_cfg *cfg = bpf_map_lookup_elem(&firewall_config_map, &key);
    if (!cfg) return true;
    return cfg->allow_wan_ping != 0;
}

static __always_inline int fw_v4_egress(struct __sk_buff *skb) {
    struct scan_ipv4_idx idx = {};
    struct inet4_pair ip_pair = {0};

    if (scan_ipv4_full(skb, current_l3_offset, &idx) != LD_SCAN_OK) return TC_ACT_OK;
    int ret = skb_read_ipv4_info(skb, current_l3_offset, &idx, &ip_pair);
    if (ret == TC_ACT_SHOT) return TC_ACT_SHOT;
    if (ret) return TC_ACT_OK;

    // Check blacklist on dest
    struct ipv4_lpm_key block_key = {
        .prefixlen = 32,
        .addr = ip_pair.dst_addr.addr,
    };
    if (unlikely(bpf_map_lookup_elem(&firewall_block_ip4_map, &block_key)))
        return TC_ACT_SHOT;

    ret = frag4_track(&idx, ip_pair.src_addr.addr, ip_pair.dst_addr.addr, &ip_pair.src_port, &ip_pair.dst_port);
    if (ret != TC_ACT_OK) return TC_ACT_SHOT;
    if (idx.fragment_type >= FRAG_MIDDLE) return TC_ACT_OK;

    bool is_icmpx_error = idx.icmp_error_l3_offset > 0 && idx.icmp_error_inner_l4_offset > 0;
    if (is_icmpx_error) return TC_ACT_OK;

    u8 proto = idx.l4_protocol;
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_ICMP) {
        struct ct_tuple4 tuple = {
            .src_ip = ip_pair.dst_addr.addr,
            .dst_ip = ip_pair.src_addr.addr,
            .src_port = ip_pair.dst_port,
            .dst_port = ip_pair.src_port,
            .protocol = proto,
        };

        if (idx.pkt_type == PKT_TCP_SYN_V2) {
            struct ct_entry ent = {
                .last_seen_ns = bpf_ktime_get_ns(),
                .packets = 1,
                .bytes = skb->len,
                .state = FW_STATE_SYN_SENT,
            };
            bpf_map_update_elem(&firewall_state4_map, &tuple, &ent, BPF_ANY);
            tuple.src_ip = ip_pair.src_addr.addr;
            tuple.dst_ip = ip_pair.dst_addr.addr;
            tuple.src_port = ip_pair.src_port;
            tuple.dst_port = ip_pair.dst_port;
            bpf_map_update_elem(&firewall_state4_map, &tuple, &ent, BPF_ANY);
        } else if (idx.pkt_type == PKT_TCP_FIN_V2 || idx.pkt_type == PKT_TCP_RST_V2) {
            struct ct_entry *e = bpf_map_lookup_elem(&firewall_state4_map, &tuple);
            if (e) {
                e->state = FW_STATE_FIN_WAIT;
                e->last_seen_ns = bpf_ktime_get_ns();
            }
            tuple.src_ip = ip_pair.src_addr.addr;
            tuple.dst_ip = ip_pair.dst_addr.addr;
            tuple.src_port = ip_pair.src_port;
            tuple.dst_port = ip_pair.dst_port;
            e = bpf_map_lookup_elem(&firewall_state4_map, &tuple);
            if (e) {
                e->state = FW_STATE_FIN_WAIT;
                e->last_seen_ns = bpf_ktime_get_ns();
            }
        } else {
            struct ct_entry *e = bpf_map_lookup_elem(&firewall_state4_map, &tuple);
            if (e) {
                e->last_seen_ns = bpf_ktime_get_ns();
                e->packets++;
                e->bytes += skb->len;
                if (e->state == FW_STATE_SYN_SENT) e->state = FW_STATE_ESTABLISHED;
            } else {
                struct ct_entry ent = {
                    .last_seen_ns = bpf_ktime_get_ns(),
                    .packets = 1,
                    .bytes = skb->len,
                    .state = (proto == IPPROTO_UDP) ? FW_STATE_UDP :
                             (proto == IPPROTO_ICMP) ? FW_STATE_ICMP : FW_STATE_ESTABLISHED,
                };
                bpf_map_update_elem(&firewall_state4_map, &tuple, &ent, BPF_ANY);
                tuple.src_ip = ip_pair.src_addr.addr;
                tuple.dst_ip = ip_pair.dst_addr.addr;
                tuple.src_port = ip_pair.src_port;
                tuple.dst_port = ip_pair.dst_port;
                bpf_map_update_elem(&firewall_state4_map, &tuple, &ent, BPF_ANY);
            }
        }
    }
    return TC_ACT_OK;
}

static __always_inline int fw_v4_ingress(struct __sk_buff *skb) {
    struct scan_ipv4_idx idx = {};
    struct inet4_pair ip_pair = {0};

    if (scan_ipv4_full(skb, current_l3_offset, &idx) != LD_SCAN_OK) return TC_ACT_OK;
    int ret = skb_read_ipv4_info(skb, current_l3_offset, &idx, &ip_pair);
    if (ret == TC_ACT_SHOT) return TC_ACT_SHOT;
    if (ret) return TC_ACT_OK;

    // Check blacklist on src
    struct ipv4_lpm_key block_key = {
        .prefixlen = 32,
        .addr = ip_pair.src_addr.addr,
    };
    if (unlikely(bpf_map_lookup_elem(&firewall_block_ip4_map, &block_key)))
        return TC_ACT_SHOT;

    // Allow DHCPv4 client inbound (UDP 68)
    if (idx.l4_protocol == IPPROTO_UDP && bpf_ntohs(ip_pair.dst_port) == 68) {
        return TC_ACT_OK;
    }

    ret = frag4_track(&idx, ip_pair.src_addr.addr, ip_pair.dst_addr.addr, &ip_pair.src_port, &ip_pair.dst_port);
    if (ret != TC_ACT_OK) return TC_ACT_SHOT;
    if (idx.fragment_type >= FRAG_MIDDLE) return TC_ACT_OK;

    bool is_icmpx_error = idx.icmp_error_l3_offset > 0 && idx.icmp_error_inner_l4_offset > 0;
    if (is_icmpx_error) {
        // Matched related outgoing connection
        struct ct_tuple4 match_k = {
            .src_ip = ip_pair.src_addr.addr,
            .dst_ip = ip_pair.dst_addr.addr,
            .src_port = ip_pair.src_port,
            .dst_port = ip_pair.dst_port,
            .protocol = idx.icmp_error_l4_protocol,
        };
        if (bpf_map_lookup_elem(&firewall_state4_map, &match_k)) return TC_ACT_OK;
        return TC_ACT_SHOT;
    }

    if (idx.l4_protocol == IPPROTO_ICMP) {
        if (idx.pkt_type == PKT_CONNLESS_V2) {
            struct ct_tuple4 match_k = {
                .src_ip = ip_pair.src_addr.addr,
                .dst_ip = ip_pair.dst_addr.addr,
                .src_port = ip_pair.src_port,
                .dst_port = ip_pair.dst_port,
                .protocol = IPPROTO_ICMP,
            };
            struct ct_entry *ent = bpf_map_lookup_elem(&firewall_state4_map, &match_k);
            if (ent) {
                u64 now_ns = bpf_ktime_get_ns();
                if (is_ct_expired(ent, now_ns)) {
                    bpf_map_delete_elem(&firewall_state4_map, &match_k);
                } else {
                    ent->last_seen_ns = now_ns;
                    ent->packets++;
                    ent->bytes += skb->len;
                    return TC_ACT_OK;
                }
            }
            // Unsolicited WAN ping check & rate limit
            if (!is_wan_ping_allowed() || !check_rate_limit4(ip_pair.src_addr.addr)) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
        }
    }

    u8 proto = idx.l4_protocol;
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        struct ct_tuple4 match_k = {
            .src_ip = ip_pair.src_addr.addr,
            .dst_ip = ip_pair.dst_addr.addr,
            .src_port = ip_pair.src_port,
            .dst_port = ip_pair.dst_port,
            .protocol = proto,
        };
        struct ct_entry *ent = bpf_map_lookup_elem(&firewall_state4_map, &match_k);
        if (ent) {
            u64 now_ns = bpf_ktime_get_ns();
            if (is_ct_expired(ent, now_ns)) {
                bpf_map_delete_elem(&firewall_state4_map, &match_k);
                ent = NULL;
            } else {
                ent->last_seen_ns = now_ns;
                ent->packets++;
                ent->bytes += skb->len;
                if (idx.pkt_type == PKT_TCP_ACK_V2 && ent->state == FW_STATE_SYN_SENT) {
                    ent->state = FW_STATE_ESTABLISHED;
                } else if (idx.pkt_type == PKT_TCP_FIN_V2 || idx.pkt_type == PKT_TCP_RST_V2) {
                    ent->state = FW_STATE_FIN_WAIT;
                }
                return TC_ACT_OK;
            }
        }

        if (is_port_allowed(ip_pair.dst_port, proto)) {
            // Mitigate SYN flood & rapid port knocking
            if (!check_rate_limit4(ip_pair.src_addr.addr)) {
                return TC_ACT_SHOT;
            }
            if (idx.pkt_type == PKT_TCP_SYN_V2) {
                struct ct_entry in_ent = {
                    .last_seen_ns = bpf_ktime_get_ns(),
                    .packets = 1,
                    .bytes = skb->len,
                    .state = FW_STATE_SYN_SENT,
                };
                bpf_map_update_elem(&firewall_state4_map, &match_k, &in_ent, BPF_ANY);
                struct ct_tuple4 reply_k = {
                    .src_ip = ip_pair.dst_addr.addr,
                    .dst_ip = ip_pair.src_addr.addr,
                    .src_port = ip_pair.dst_port,
                    .dst_port = ip_pair.src_port,
                    .protocol = IPPROTO_TCP,
                };
                bpf_map_update_elem(&firewall_state4_map, &reply_k, &in_ent, BPF_ANY);
            }
            return TC_ACT_OK;
        }
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

static __always_inline int fw_v6_egress(struct __sk_buff *skb) {
    struct scan_ipv6_idx idx = {};
    struct inet_pair ip_pair = {0};

    int scan_ret = scan_ipv6_full(skb, current_l3_offset, &idx);
    if (scan_ret == LD_SCAN_UNSPEC) return TC_ACT_OK; // NDP / MLD pass
    if (scan_ret != LD_SCAN_OK) return TC_ACT_OK;

    int ret = skb_read_ipv6_info(skb, current_l3_offset, &idx, &ip_pair);
    if (ret == TC_ACT_SHOT) return TC_ACT_SHOT;
    if (ret) return TC_ACT_OK;

    // Check blacklist on dest
    struct ipv6_lpm_key block_key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(&block_key.addr, &ip_pair.dst_addr, sizeof(block_key.addr));
    if (unlikely(bpf_map_lookup_elem(&firewall_block_ip6_map, &block_key)))
        return TC_ACT_SHOT;

    ret = frag6_track(&idx, (struct in6_addr *)&ip_pair.src_addr, (struct in6_addr *)&ip_pair.dst_addr,
                      &ip_pair.src_port, &ip_pair.dst_port);
    if (ret != TC_ACT_OK) return TC_ACT_SHOT;
    if (idx.fragment_type >= FRAG_MIDDLE) return TC_ACT_OK;

    bool is_icmpx_error = idx.icmp_error_l3_offset > 0 && idx.icmp_error_inner_l4_offset > 0;
    if (is_icmpx_error) return TC_ACT_OK;

    u8 proto = idx.l4_protocol;
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_ICMPV6) {
        struct ct_tuple6 tuple = {
            .src_ip = ip_pair.dst_addr,
            .dst_ip = ip_pair.src_addr,
            .src_port = ip_pair.dst_port,
            .dst_port = ip_pair.src_port,
            .protocol = proto,
        };

        if (idx.pkt_type == PKT_TCP_SYN_V2) {
            struct ct_entry ent = {
                .last_seen_ns = bpf_ktime_get_ns(),
                .packets = 1,
                .bytes = skb->len,
                .state = FW_STATE_SYN_SENT,
            };
            bpf_map_update_elem(&firewall_state6_map, &tuple, &ent, BPF_ANY);
            tuple.src_ip = ip_pair.src_addr;
            tuple.dst_ip = ip_pair.dst_addr;
            tuple.src_port = ip_pair.src_port;
            tuple.dst_port = ip_pair.dst_port;
            bpf_map_update_elem(&firewall_state6_map, &tuple, &ent, BPF_ANY);
        } else if (idx.pkt_type == PKT_TCP_FIN_V2 || idx.pkt_type == PKT_TCP_RST_V2) {
            struct ct_entry *e = bpf_map_lookup_elem(&firewall_state6_map, &tuple);
            if (e) {
                e->state = FW_STATE_FIN_WAIT;
                e->last_seen_ns = bpf_ktime_get_ns();
            }
            tuple.src_ip = ip_pair.src_addr;
            tuple.dst_ip = ip_pair.dst_addr;
            tuple.src_port = ip_pair.src_port;
            tuple.dst_port = ip_pair.dst_port;
            e = bpf_map_lookup_elem(&firewall_state6_map, &tuple);
            if (e) {
                e->state = FW_STATE_FIN_WAIT;
                e->last_seen_ns = bpf_ktime_get_ns();
            }
        } else {
            struct ct_entry *e = bpf_map_lookup_elem(&firewall_state6_map, &tuple);
            if (e) {
                e->last_seen_ns = bpf_ktime_get_ns();
                e->packets++;
                e->bytes += skb->len;
                if (e->state == FW_STATE_SYN_SENT) e->state = FW_STATE_ESTABLISHED;
            } else {
                struct ct_entry ent = {
                    .last_seen_ns = bpf_ktime_get_ns(),
                    .packets = 1,
                    .bytes = skb->len,
                    .state = (proto == IPPROTO_UDP) ? FW_STATE_UDP :
                             (proto == IPPROTO_ICMPV6) ? FW_STATE_ICMP : FW_STATE_ESTABLISHED,
                };
                bpf_map_update_elem(&firewall_state6_map, &tuple, &ent, BPF_ANY);
                tuple.src_ip = ip_pair.src_addr;
                tuple.dst_ip = ip_pair.dst_addr;
                tuple.src_port = ip_pair.src_port;
                tuple.dst_port = ip_pair.dst_port;
                bpf_map_update_elem(&firewall_state6_map, &tuple, &ent, BPF_ANY);
            }
        }
    }
    return TC_ACT_OK;
}

static __always_inline int fw_v6_ingress(struct __sk_buff *skb) {
    struct scan_ipv6_idx idx = {};
    struct inet_pair ip_pair = {0};

    int scan_ret = scan_ipv6_full(skb, current_l3_offset, &idx);
    if (scan_ret == LD_SCAN_UNSPEC) return TC_ACT_OK; // Essential NDP / MLD always pass
    if (scan_ret != LD_SCAN_OK) return TC_ACT_OK;

    int ret = skb_read_ipv6_info(skb, current_l3_offset, &idx, &ip_pair);
    if (ret == TC_ACT_SHOT) return TC_ACT_SHOT;
    if (ret) return TC_ACT_OK;

    // Check blacklist on src
    struct ipv6_lpm_key block_key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(&block_key.addr, &ip_pair.src_addr, sizeof(block_key.addr));
    if (unlikely(bpf_map_lookup_elem(&firewall_block_ip6_map, &block_key)))
        return TC_ACT_SHOT;

    // Allow DHCPv6 client inbound (UDP 546)
    if (idx.l4_protocol == IPPROTO_UDP && bpf_ntohs(ip_pair.dst_port) == 546) {
        return TC_ACT_OK;
    }

    ret = frag6_track(&idx, (struct in6_addr *)&ip_pair.src_addr, (struct in6_addr *)&ip_pair.dst_addr,
                      &ip_pair.src_port, &ip_pair.dst_port);
    if (ret != TC_ACT_OK) return TC_ACT_SHOT;
    if (idx.fragment_type >= FRAG_MIDDLE) return TC_ACT_OK;

    bool is_icmpx_error = idx.icmp_error_l3_offset > 0 && idx.icmp_error_inner_l4_offset > 0;
    if (is_icmpx_error) {
        // Matched related outgoing connection
        struct ct_tuple6 match_k = {
            .src_ip = ip_pair.src_addr,
            .dst_ip = ip_pair.dst_addr,
            .src_port = ip_pair.src_port,
            .dst_port = ip_pair.dst_port,
            .protocol = idx.icmp_error_l4_protocol,
        };
        if (bpf_map_lookup_elem(&firewall_state6_map, &match_k)) return TC_ACT_OK;
        return TC_ACT_SHOT;
    }

    if (idx.l4_protocol == IPPROTO_ICMPV6) {
        if (idx.pkt_type == PKT_CONNLESS_V2) {
            struct ct_tuple6 match_k = {
                .src_ip = ip_pair.src_addr,
                .dst_ip = ip_pair.dst_addr,
                .src_port = ip_pair.src_port,
                .dst_port = ip_pair.dst_port,
                .protocol = IPPROTO_ICMPV6,
            };
            struct ct_entry *ent = bpf_map_lookup_elem(&firewall_state6_map, &match_k);
            if (ent) {
                u64 now_ns = bpf_ktime_get_ns();
                if (is_ct_expired(ent, now_ns)) {
                    bpf_map_delete_elem(&firewall_state6_map, &match_k);
                } else {
                    ent->last_seen_ns = now_ns;
                    ent->packets++;
                    ent->bytes += skb->len;
                    return TC_ACT_OK;
                }
            }
            // Unsolicited WAN ping check & rate limit
            if (!is_wan_ping_allowed() || !check_rate_limit6(&ip_pair.src_addr)) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
        }
    }

    u8 proto = idx.l4_protocol;
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        struct ct_tuple6 match_k = {
            .src_ip = ip_pair.src_addr,
            .dst_ip = ip_pair.dst_addr,
            .src_port = ip_pair.src_port,
            .dst_port = ip_pair.dst_port,
            .protocol = proto,
        };
        struct ct_entry *ent = bpf_map_lookup_elem(&firewall_state6_map, &match_k);
        if (ent) {
            u64 now_ns = bpf_ktime_get_ns();
            if (is_ct_expired(ent, now_ns)) {
                bpf_map_delete_elem(&firewall_state6_map, &match_k);
                ent = NULL;
            } else {
                ent->last_seen_ns = now_ns;
                ent->packets++;
                ent->bytes += skb->len;
                if (idx.pkt_type == PKT_TCP_ACK_V2 && ent->state == FW_STATE_SYN_SENT) {
                    ent->state = FW_STATE_ESTABLISHED;
                } else if (idx.pkt_type == PKT_TCP_FIN_V2 || idx.pkt_type == PKT_TCP_RST_V2) {
                    ent->state = FW_STATE_FIN_WAIT;
                }
                return TC_ACT_OK;
            }
        }

        if (is_port_allowed(ip_pair.dst_port, proto)) {
            // Mitigate SYN flood & rapid port knocking
            if (!check_rate_limit6(&ip_pair.src_addr)) {
                return TC_ACT_SHOT;
            }
            if (idx.pkt_type == PKT_TCP_SYN_V2) {
                struct ct_entry in_ent = {
                    .last_seen_ns = bpf_ktime_get_ns(),
                    .packets = 1,
                    .bytes = skb->len,
                    .state = FW_STATE_SYN_SENT,
                };
                bpf_map_update_elem(&firewall_state6_map, &match_k, &in_ent, BPF_ANY);
                struct ct_tuple6 reply_k = {
                    .src_ip = ip_pair.dst_addr,
                    .dst_ip = ip_pair.src_addr,
                    .src_port = ip_pair.dst_port,
                    .dst_port = ip_pair.src_port,
                    .protocol = IPPROTO_TCP,
                };
                bpf_map_update_elem(&firewall_state6_map, &reply_k, &in_ent, BPF_ANY);
            }
            return TC_ACT_OK;
        }
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

SEC("tc/egress")
int tc_firewall_wan_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< tc_firewall_wan_egress <<<"
    bool is_v4;
    if (current_pkg_type(skb, current_l3_offset, &is_v4) != TC_ACT_OK) return TC_ACT_OK;

    int ret = is_v4 ? fw_v4_egress(skb) : fw_v6_egress(skb);
    if (unlikely(ret == TC_ACT_SHOT)) return TC_ACT_SHOT;

    TC_CHAIN_WAN_EGRESS(skb);
    bpf_tail_call(skb, &tc_pipe_exits_wan_egress, TC_NEXT_SLOT);
    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int tc_firewall_wan_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< tc_firewall_wan_ingress <<<"
    bool is_v4;
    if (current_pkg_type(skb, current_l3_offset, &is_v4) != TC_ACT_OK) return TC_ACT_OK;

    int ret = is_v4 ? fw_v4_ingress(skb) : fw_v6_ingress(skb);
    if (unlikely(ret == TC_ACT_SHOT)) return TC_ACT_SHOT;

    TC_CHAIN_WAN_INGRESS(skb);
    bpf_tail_call(skb, &tc_pipe_exits_wan_ingress, TC_NEXT_SLOT);
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}
