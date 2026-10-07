#ifndef __LD_DNS_GUARD_H__
#define __LD_DNS_GUARD_H__
#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../einat_types.h"
#include "../landscape.h"
#include "../pkg_scanner.h"
#include "../base/mark.h"
#include "../route/route4_lan.h"
#include "../route/route6_lan.h"
#include "../route/route_common.h"

// Managed-DNS guard.
//
// The TC datapath forwards a direct flow to the WAN with bpf_redirect, which
// means it never reaches netfilter at all; measured on the live router, a
// client's query to 8.8.8.8 was answered by 8.8.8.8 with the nat REDIRECT rule
// installed and its counter frozen. So the enforcement point cannot be
// netfilter alone.
//
// The division of labour is deliberate and each half is required:
//
//   * TC decides - and only TC can decide - whether a packet is managed DNS,
//     because it is the last point that sees every LAN client packet. A managed
//     packet is handed to the local stack instead of being forwarded.
//   * netfilter then rules on it: the nat REDIRECT hijacks 53 to the managed
//     resolver with a correct reverse NAT, and the guard chain DROPs 853 (DoT /
//     DoQ) and any listed DoH address.
//   * the kernel's conntrack owns the reply path, so the client still sees its
//     answer come from the address it asked.
//
// Handing a packet to the stack is not itself a permission. It is a promise
// that netfilter will rule on it; with ip_forward = 0 an unruled packet is
// simply dropped, which is the fail-closed behaviour we want when the
// netfilter side is missing or broken.

// What the caller should do with the packet.
#define LD_DNS_GUARD_CONTINUE 0
// Deliver to the local stack, explicitly marked as a direct from-LAN packet.
#define LD_DNS_GUARD_HANDOFF 1
// Refuse the packet in the datapath.
#define LD_DNS_GUARD_DROP 2

// Why a packet was handled, for operations. A plain shared array with atomic
// increments rather than a per-CPU one, because the point of these counters is
// to be readable as a whole (`MapHandle::lookup` on a per-CPU map returns only
// the calling CPU's share, which reads as wildly wrong).
//
// TC is per packet and the netfilter rules are not, so these will never line up
// one for one with the iptables counters - that is expected, not a bug.
enum dns_guard_stat {
    LD_DNS_GUARD_STAT_HANDOFF_53 = 0,
    LD_DNS_GUARD_STAT_HANDOFF_DOT = 1,
    LD_DNS_GUARD_STAT_HANDOFF_DOH = 2,
    LD_DNS_GUARD_STAT_EXEMPT = 3,
    LD_DNS_GUARD_STAT_FRAGMENT_DROPPED = 4,
    LD_DNS_GUARD_STAT_FRAGMENT_PASSED = 5,
    LD_DNS_GUARD_STAT_PARSE_FAILED = 6,
    LD_DNS_GUARD_STAT_LAN_DESTINATION = 7,
    LD_DNS_GUARD_STAT_MAX = 8,
};

struct dns_guard_config {
    u8 enabled;
    /// Refuse IPv4 fragments and IPv6 packets carrying a Fragment header.
    ///
    /// A non-first fragment has no L4 header, so it cannot be classified;
    /// letting it through would let a client reach a resolver the guard just
    /// refused. Dropping costs legitimate fragmented traffic, which PMTUD makes
    /// rare, and every drop is counted.
    u8 drop_fragments;
    /// Refuse packets whose header chain cannot be parsed.
    ///
    /// Off by default, deliberately diverging from the stricter reading: on IPv6
    /// the scanner rejects ESP/AH chains, and silently dropping those looks like
    /// a broken network rather than a policy. The counter still reports them.
    u8 drop_unclassified;
    u8 _pad;
    u32 generation;
};

/// A trusted client, for one authorised service on one destination.
///
/// Exemption is by identity plus service, never by flow: the flow a packet lands
/// in is chosen by its destination, so a flow or a `local_tproxy` target is not
/// an identity. `sport` is intentionally absent - the authorisation is about
/// what the host is allowed to reach.
struct dns_guard_exempt_key {
    u8 family;
    u8 l4_protocol;
    __be16 dport;
    u32 _pad;
    union u_inet_addr src;
    union u_inet_addr dst;
};

/// Guard switch. One entry, rewritten on every configuration apply.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct dns_guard_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_guard_config_map SEC(".maps");

/// DoH endpoints to refuse, by address. DoH is ordinary HTTPS, so an address is
/// the only handle there is; an endpoint nobody listed is a documented boundary.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __type(key, struct ipv4_lpm_key);
    __type(value, u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_guard_doh4_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __type(key, struct ipv6_lpm_key);
    __type(value, u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_guard_doh6_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct dns_guard_exempt_key);
    __type(value, u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_guard_exempt_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, LD_DNS_GUARD_STAT_MAX);
    __type(key, u32);
    __type(value, u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_guard_stats_map SEC(".maps");

#define BPF_DNS_GUARD_STAT(idx)                                                                    \
    do {                                                                                           \
        u32 _k = (idx);                                                                            \
        u64 *_v = bpf_map_lookup_elem(&dns_guard_stats_map, &_k);                                  \
        if (_v) __sync_fetch_and_add(_v, 1);                                                       \
    } while (0)

static __always_inline bool dns_guard_doh_match(u8 family, const union u_inet_addr *daddr) {
    if (family == LANDSCAPE_IPV4_TYPE) {
        struct ipv4_lpm_key key = {.prefixlen = 32, .addr = daddr->ip};
        return bpf_map_lookup_elem(&dns_guard_doh4_map, &key) != NULL;
    }
    struct ipv6_lpm_key key = {0};
    key.prefixlen = 128;
    __builtin_memcpy(key.addr.in6_u.u6_addr8, daddr->bits, sizeof(daddr->bits));
    return bpf_map_lookup_elem(&dns_guard_doh6_map, &key) != NULL;
}

/// A destination that lives on the LAN is not an egress to the internet, and the
/// guard has no business there: a local server may legitimately speak DNS or DoT
/// to another local host. `ROUTE_TYPE_WAN` marks a destination that does leave.
static __always_inline bool dns_guard_dst_is_lan(u8 family, const union u_inet_addr *daddr) {
    if (family == LANDSCAPE_IPV4_TYPE) {
        struct route4_lan_key key = {.prefixlen = 32, .addr = daddr->ip};
        struct route4_lan_info *info = bpf_map_lookup_elem(&rt4_lan_map, &key);
        return info != NULL && info->route_type != ROUTE_TYPE_WAN;
    }
    struct route6_lan_key key = {0};
    key.prefixlen = 128;
    __builtin_memcpy(key.addr.all, daddr->all, sizeof(key.addr.all));
    struct route6_lan_info *info = bpf_map_lookup_elem(&rt6_lan_map, &key);
    return info != NULL && info->route_type != ROUTE_TYPE_WAN;
}

/// Decide what to do with one packet arriving from a managed LAN client.
///
/// Returns one of the `LD_DNS_GUARD_*` verdicts; the caller owns the datapath
/// action. `current_l3_offset` is the L3 header offset, not the original packet
/// offset - this runs after the caller's own scan.
static __always_inline int dns_guard_check(struct __sk_buff *skb, u32 current_l3_offset, u8 family,
                                           const union u_inet_addr *saddr,
                                           const union u_inet_addr *daddr) {
#define BPF_LOG_TOPIC "dns_guard_check"
    u32 cfg_key = 0;
    struct dns_guard_config *cfg = bpf_map_lookup_elem(&dns_guard_config_map, &cfg_key);
    // No config map, or the guard is off: not our traffic. The caller's normal
    // path is untouched, which also keeps the disabled case free.
    if (!cfg || !cfg->enabled) return LD_DNS_GUARD_CONTINUE;

    if (dns_guard_dst_is_lan(family, daddr)) {
        BPF_DNS_GUARD_STAT(LD_DNS_GUARD_STAT_LAN_DESTINATION);
        return LD_DNS_GUARD_CONTINUE;
    }

    struct packet_offset_info offset = {0};
    if (scan_packet_outer_l4(skb, current_l3_offset, &offset) != LD_SCAN_OK) {
        BPF_DNS_GUARD_STAT(LD_DNS_GUARD_STAT_PARSE_FAILED);
        return cfg->drop_unclassified ? LD_DNS_GUARD_DROP : LD_DNS_GUARD_CONTINUE;
    }

    // Only FRAG_SINGLE has a trustworthy L4 header at offset.l4_offset.
    if (offset.fragment_type != FRAG_SINGLE) {
        if (cfg->drop_fragments) {
            BPF_DNS_GUARD_STAT(LD_DNS_GUARD_STAT_FRAGMENT_DROPPED);
            return LD_DNS_GUARD_DROP;
        }
        BPF_DNS_GUARD_STAT(LD_DNS_GUARD_STAT_FRAGMENT_PASSED);
        return LD_DNS_GUARD_CONTINUE;
    }

    u8 proto = offset.l4_protocol;
    // Everything that is not TCP or UDP - ICMP, ICMPv6/NDP, GRE - is none of this
    // guard's business. NDP in particular must never be caught here.
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) return LD_DNS_GUARD_CONTINUE;

    // Destination port sits at the same offset in both TCP and UDP headers.
    __be16 dport = 0;
    if (VALIDATE_READ_DATA(skb, (void **)&dport, offset.l4_offset + 2, sizeof(dport))) {
        BPF_DNS_GUARD_STAT(LD_DNS_GUARD_STAT_PARSE_FAILED);
        return cfg->drop_unclassified ? LD_DNS_GUARD_DROP : LD_DNS_GUARD_CONTINUE;
    }

    u32 stat;
    if (dport == bpf_htons(53)) {
        stat = LD_DNS_GUARD_STAT_HANDOFF_53;
    } else if (dport == bpf_htons(853)) {
        stat = LD_DNS_GUARD_STAT_HANDOFF_DOT;
    } else if (dport == bpf_htons(443)) {
        if (!dns_guard_doh_match(family, daddr)) return LD_DNS_GUARD_CONTINUE;
        stat = LD_DNS_GUARD_STAT_HANDOFF_DOH;
    } else {
        return LD_DNS_GUARD_CONTINUE;
    }

    struct dns_guard_exempt_key exempt = {0};
    exempt.family = family;
    exempt.l4_protocol = proto;
    exempt.dport = dport;
    __builtin_memcpy(exempt.src.all, saddr->all, sizeof(exempt.src.all));
    __builtin_memcpy(exempt.dst.all, daddr->all, sizeof(exempt.dst.all));
    if (bpf_map_lookup_elem(&dns_guard_exempt_map, &exempt) != NULL) {
        BPF_DNS_GUARD_STAT(LD_DNS_GUARD_STAT_EXEMPT);
        return LD_DNS_GUARD_CONTINUE;
    }

    BPF_DNS_GUARD_STAT(stat);
    return LD_DNS_GUARD_HANDOFF;
#undef BPF_LOG_TOPIC
}

/// Mark a handoff packet so netfilter rules on it instead of TPROXY taking it.
///
/// The flow id is cleared (and the action set to direct) explicitly rather than
/// relied upon to be zero: TPROXY matches `mark 0xa/0xff`, so a packet left
/// carrying a proxy flow id would be intercepted before the nat hijack ever ran.
/// The source byte is set so the rest of the chain still sees where it came from.
static __always_inline void dns_guard_mark_handoff(struct __sk_buff *skb) {
    u32 mark = skb->mark;
    mark = replace_flow_id(mark, 0);
    mark = replace_flow_action(mark, FLOW_DIRECT);
    skb->mark = replace_flow_source(mark, FLOW_FROM_LAN);
}

#endif /* __LD_DNS_GUARD_H__ */
