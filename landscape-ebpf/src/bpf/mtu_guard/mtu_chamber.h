#ifndef __LD_MTU_CHAMBER_H__
#define __LD_MTU_CHAMBER_H__
#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../chain/tc_cb.h"
#include "../landscape.h"
#include "../neigh_ip6.h"
#include "../pkg_def.h"
#include "mtu_guard.h"

// The IPv6 Packet Too Big remedy, arranged so the kernel produces the error.
//
// The datapath forwards by redirect, so the kernel's forwarding path - the only
// place a Packet Too Big is generated - never runs, and an over-MTU IPv6 packet
// is dropped in silence. Enabling forwarding in this namespace to get the error
// back would hand the kernel a general forwarding path this design deliberately
// does not have. So the packet is handed to a namespace whose *only* job is to
// produce that error:
//
//   main datapath (admission, policy, egress selection already done)
//     |  over the MTU of the egress it selected, and only then
//     v  bpf_redirect_neigh over a dedicated veth
//   exception namespace ("chamber")
//     IPv6 forwarding ON, one dummy egress carrying that egress's MTU,
//     FORWARD DROP, and no route that reaches a real network
//     -> the kernel's forwarding MTU check runs and emits the Packet Too Big
//     v  the only thing that may come back
//   main datapath: validate, consume the admission it belongs to, deliver to
//     the client whose packet is quoted
//
// Measured on 6.12.111 before this was written (work/landscape-verify,
// probe-ptb-chamber.sh / probe-ptb-return.sh):
//
//   * `FORWARD policy DROP` does NOT suppress the error - the MTU check runs
//     before the FORWARD hook, so the policy counter stays at 0 while the PTB is
//     sent. That is what makes this shape possible at all.
//   * with forwarding off in the chamber, nothing is emitted: the error comes
//     from the forwarding path, not from the trick of moving the packet.
//   * the error is emitted with the address the client treats as its gateway
//     when the chamber's veth carries the LAN's own addresses, which is why the
//     setup copies them (with `noprefixroute`, so no connected route is created
//     on the exception link and the error still leaves through the main
//     namespace).
//   * with the veth's own address instead, the client gets no usable error.
//
// Phase 1 is deliberately narrow, and every exclusion is counted rather than
// guessed at: native forwarding only (no NPTv6-rewritten flow), no extension
// headers, no fragments, no segmentation aggregates, and only TCP, UDP and
// IPv6 echo. Anything outside that keeps the old behaviour - the packet is
// dropped as before, and the counter says why it was not given an error.

/// Everything the datapath needs to know about the chamber, written in one
/// update once the chamber is fully set up and zeroed the moment it is not.
/// A zeroed (or absent) config means "count only": no packet is diverted.
///
/// The addresses are a set rather than one address because the kernel chooses
/// which of them to speak with per RFC 6724 and per client: a client using a ULA
/// source and one using a global source get errors from different router
/// addresses, and the return path has to accept both without accepting anything
/// the chamber was not given.
#define MTU_CHAMBER_MAX_SOURCES 4

struct mtu_chamber_config {
    /// 1 = divert oversized IPv6 into the chamber.
    u32 enabled;
    /// The chamber veth, main-namespace side: the divert target.
    u32 veth_ifindex;
    /// How many of `sources` are in use.
    u32 source_count;
    /// How long an admission stays valid, in milliseconds.
    u32 ttl_ms;
    /// Per-source admissions per second before the rest are dropped. 0 refuses
    /// everything, so a half-written config fails closed rather than open.
    u32 burst;
    u32 _reserved;
    /// The chamber's address on that veth, for the neighbour rewrite.
    union u_inet6_addr nexthop;
    /// The addresses the chamber may speak with, taken from the LAN interfaces.
    /// The return path accepts an error from one of these and refuses anything
    /// else, so a packet that did not come from our chamber cannot make the
    /// datapath relay it.
    union u_inet6_addr sources[MTU_CHAMBER_MAX_SOURCES];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct mtu_chamber_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mtu_chamber_cfg_map SEC(".maps");

enum mtu_chamber_stat {
    /// An oversized packet was handed to the chamber.
    MTU_CHAMBER_STAT_DIVERTED = 0,
    /// Over the egress MTU, but the chamber is not available: counted, and left
    /// to the old behaviour. Never diverted.
    MTU_CHAMBER_STAT_SKIPPED_DISABLED = 1,
    /// Over the egress MTU but the egress rewrote the source prefix (NPTv6), so
    /// the address in the packet is not the client's and phase 1 leaves it alone.
    MTU_CHAMBER_STAT_SKIPPED_NPT = 2,
    /// Extension header (hop-by-hop / routing / destination / auth / unknown).
    MTU_CHAMBER_STAT_SKIPPED_EXTHDR = 3,
    /// Fragment header, or a non-first fragment.
    MTU_CHAMBER_STAT_SKIPPED_FRAGMENT = 4,
    /// Not TCP, UDP or IPv6 echo: no stable identity to match the reply against,
    /// and nothing a first stage can claim to handle.
    MTU_CHAMBER_STAT_SKIPPED_L4 = 5,
    /// The source used up its admissions for this second.
    MTU_CHAMBER_STAT_SKIPPED_BUDGET = 6,
    /// The admission table refused the entry (full or unwritable).
    MTU_CHAMBER_STAT_STATE_FULL = 7,
    /// The divert itself failed. Dropped and counted; never handed on.
    MTU_CHAMBER_STAT_DIVERT_FAILED = 8,
    /// A validated Packet Too Big went back to the client.
    MTU_CHAMBER_STAT_PTB_RETURNED = 9,
    /// Something arrived on the return veth that was not a valid reply to a
    /// recent admission. Dropped: the return veth carries errors and nothing.
    MTU_CHAMBER_STAT_PTB_REJECTED = 10,
    /// The reply was valid but the client's link address is not known, so it
    /// could not be delivered.
    MTU_CHAMBER_STAT_PTB_NO_MAC = 11,
    /// A valid reply arrived after its admission expired.
    MTU_CHAMBER_STAT_PTB_EXPIRED = 12,
    MTU_CHAMBER_STAT_MAX = 13,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MTU_CHAMBER_STAT_MAX);
    __type(key, u32);
    __type(value, u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mtu_chamber_stats_map SEC(".maps");

static __always_inline void mtu_chamber_count(u32 index) {
    u32 key = index;
    u64 *value = bpf_map_lookup_elem(&mtu_chamber_stats_map, &key);
    if (value) __sync_fetch_and_add(value, 1);
}

/// One admitted packet, keyed by the identity a reply can quote back.
///
/// The quoted packet in an ICMPv6 error carries the original's headers, so the
/// reply can be tied to a specific admitted packet instead of to "some packet
/// once". That is what makes "one admission, at most one error" true.
struct mtu_chamber_key {
    union u_inet6_addr saddr;
    union u_inet6_addr daddr;
    /// TCP/UDP ports, or the echo identifier and sequence.
    u32 l4_ident;
    u8 nexthdr;
    u8 _pad[3];
};

struct mtu_chamber_value {
    /// Where the admitted packet came in: the interface the reply goes back out.
    u32 lan_ifindex;
    /// The MTU promised in the error has to be this, or the reply is not ours.
    u16 egress_mtu;
    u16 _pad;
    u64 admitted_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct mtu_chamber_key);
    __type(value, struct mtu_chamber_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mtu_chamber_state_map SEC(".maps");

/// One source's admissions in the current second, so a client cannot turn the
/// error generator into a workload. Bounded by the map size, so an attacker
/// with many source addresses costs at most one entry each.
struct mtu_chamber_budget_value {
    u64 window_start_ns;
    u32 used;
    u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, union u_inet6_addr);
    __type(value, struct mtu_chamber_budget_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mtu_chamber_budget_map SEC(".maps");

static __always_inline struct mtu_chamber_config *mtu_chamber_cfg(void) {
    u32 key = 0;
    return bpf_map_lookup_elem(&mtu_chamber_cfg_map, &key);
}

#define MTU_CHAMBER_ONE_SECOND_NS 1000000000ULL

static __always_inline bool mtu_chamber_budget_allow(const struct mtu_chamber_config *cfg,
                                                     const union u_inet6_addr *src) {
    // A half-written config has burst 0, and that must refuse rather than admit:
    // the failure mode of this branch has to be "no error, packet dropped as
    // before", never "unlimited errors".
    if (cfg->burst == 0) return false;

    u64 now = bpf_ktime_get_ns();
    struct mtu_chamber_budget_value *entry = bpf_map_lookup_elem(&mtu_chamber_budget_map, src);
    if (entry == NULL) {
        struct mtu_chamber_budget_value fresh = {
            .window_start_ns = now,
            .used = 1,
        };
        bpf_map_update_elem(&mtu_chamber_budget_map, src, &fresh, BPF_NOEXIST);
        return true;
    }

    if (now - entry->window_start_ns >= MTU_CHAMBER_ONE_SECOND_NS) {
        struct mtu_chamber_budget_value reset = {
            .window_start_ns = now,
            .used = 1,
        };
        bpf_map_update_elem(&mtu_chamber_budget_map, src, &reset, BPF_ANY);
        return true;
    }

    if (entry->used >= cfg->burst) return false;

    struct mtu_chamber_budget_value next = {
        .window_start_ns = entry->window_start_ns,
        .used = entry->used + 1,
    };
    bpf_map_update_elem(&mtu_chamber_budget_map, src, &next, BPF_ANY);
    return true;
}

/// The identity of an L4 header, as the quoted packet will repeat it.
///
/// Returns false for anything without a stable 4-byte identity: for the echo
/// types that is the identifier and sequence, and for TCP/UDP the port pair.
static __always_inline bool mtu_chamber_l4_identity(struct __sk_buff *skb, u32 l4_offset,
                                                    u8 nexthdr, u32 *ident) {
    u32 offset = l4_offset;

    if (nexthdr == NEXTHDR_ICMP) {
        struct icmp6hdr *icmp6 = NULL;
        if (VALIDATE_READ_DATA(skb, &icmp6, l4_offset, sizeof(*icmp6))) return false;
        if (icmp6->icmp6_type != ICMPV6_ECHO_REQUEST && icmp6->icmp6_type != ICMPV6_ECHO_REPLY) {
            return false;
        }
        // The identifier and sequence, not the type/code/checksum.
        offset = l4_offset + 4;
    } else if (nexthdr != NEXTHDR_TCP && nexthdr != NEXTHDR_UDP) {
        return false;
    }

    u32 value = 0;
    if (bpf_skb_load_bytes(skb, offset, &value, sizeof(value))) return false;
    *ident = value;
    return true;
}

/// Narrow the header chain down to a shape phase 1 supports.
///
/// Returns the L4 protocol and its offset, or a counter index describing why the
/// packet is out of scope. `*out_offsets` is only meaningful on success.
static __always_inline int mtu_chamber_walk_ipv6(struct __sk_buff *skb, u32 l3_offset,
                                                 const struct ipv6hdr *ip6h, u8 *l4_proto,
                                                 u32 *l4_offset) {
    u8 nexthdr = ip6h->nexthdr;
    u32 offset = l3_offset + sizeof(struct ipv6hdr);

#pragma unroll
    for (int i = 0; i < LD_MAX_IPV6_EXT_NUM; i++) {
        if (nexthdr == NEXTHDR_TCP || nexthdr == NEXTHDR_UDP || nexthdr == NEXTHDR_ICMP) {
            *l4_proto = nexthdr;
            *l4_offset = offset;
            return 0;
        }
        // A fragment header carries no length field in the usual place and the
        // rest of a non-first fragment has no L4 header at all, so the identity
        // this design matches on does not exist. Out of scope, counted.
        if (nexthdr == NEXTHDR_FRAGMENT) return MTU_CHAMBER_STAT_SKIPPED_FRAGMENT;
        // Hop-by-hop, routing, destination options, authentication, ESP, and
        // anything unknown: all out of scope for a first stage.
        return MTU_CHAMBER_STAT_SKIPPED_EXTHDR;
    }

    return MTU_CHAMBER_STAT_SKIPPED_EXTHDR;
}

/// The egress decision: a packet the datapath has already admitted and routed,
/// that the selected egress cannot carry.
///
/// Returns the bpf action to take. `TC_ACT_UNSPEC` means "carry on as before".
static __always_inline int mtu_chamber_egress(struct __sk_buff *skb, u32 l3_offset,
                                              u16 egress_mtu) {
    // Forwarded LAN traffic only. A locally generated packet still has the
    // kernel's own path, including its PMTU handling, and must keep it.
    if (!skb->cb[TC_CHAIN_CB_FORWARDED_OFFSET]) return TC_ACT_UNSPEC;
    // Something went wrong already, or the source is unknown; both mean the
    // reply could not be delivered, so do not start an exchange about it.
    if (skb->ingress_ifindex == 0) return TC_ACT_UNSPEC;

    if (skb->cb[TC_CHAIN_CB_NPT_OFFSET]) {
        // The egress rewrote the source prefix, so this packet is not the
        // client's bytes any more and its quoted form would not match.
        mtu_chamber_count(MTU_CHAMBER_STAT_SKIPPED_NPT);
        return TC_ACT_UNSPEC;
    }

    struct ipv6hdr *ip6h = NULL;
    if (VALIDATE_READ_DATA(skb, &ip6h, l3_offset, sizeof(*ip6h))) return TC_ACT_UNSPEC;
    if (ip6h->version != 6) return TC_ACT_UNSPEC;

    u32 l3_len = sizeof(*ip6h) + bpf_ntohs(ip6h->payload_len);
    if (l3_len <= egress_mtu) return TC_ACT_UNSPEC;

    u8 l4_proto = 0;
    u32 l4_offset = 0;
    int refusal = mtu_chamber_walk_ipv6(skb, l3_offset, ip6h, &l4_proto, &l4_offset);
    if (refusal) {
        mtu_chamber_count(refusal);
        return TC_ACT_UNSPEC;
    }

    u32 ident = 0;
    if (!mtu_chamber_l4_identity(skb, l4_offset, l4_proto, &ident)) {
        mtu_chamber_count(MTU_CHAMBER_STAT_SKIPPED_L4);
        return TC_ACT_UNSPEC;
    }

    struct mtu_chamber_config *cfg = mtu_chamber_cfg();
    if (cfg == NULL || cfg->enabled == 0 || cfg->veth_ifindex == 0) {
        mtu_chamber_count(MTU_CHAMBER_STAT_SKIPPED_DISABLED);
        return TC_ACT_UNSPEC;
    }

    union u_inet6_addr src = {0};
    COPY_ADDR_FROM(src.bytes, ip6h->saddr.in6_u.u6_addr8);

    if (!mtu_chamber_budget_allow(cfg, &src)) {
        mtu_chamber_count(MTU_CHAMBER_STAT_SKIPPED_BUDGET);
        // The packet cannot be carried by this egress either way, so refusing it
        // explicitly is the same outcome as the silence it would otherwise get -
        // just with a reason attached.
        return TC_ACT_SHOT;
    }

    struct mtu_chamber_key key = {0};
    COPY_ADDR_FROM(key.saddr.bytes, ip6h->saddr.in6_u.u6_addr8);
    COPY_ADDR_FROM(key.daddr.bytes, ip6h->daddr.in6_u.u6_addr8);
    key.l4_ident = ident;
    key.nexthdr = l4_proto;

    struct mtu_chamber_value admission = {
        .lan_ifindex = skb->ingress_ifindex,
        .egress_mtu = egress_mtu,
        .admitted_ns = bpf_ktime_get_ns(),
    };
    if (bpf_map_update_elem(&mtu_chamber_state_map, &key, &admission, BPF_ANY)) {
        mtu_chamber_count(MTU_CHAMBER_STAT_STATE_FULL);
        return TC_ACT_SHOT;
    }

    struct bpf_redir_neigh param = {
        .nh_family = AF_INET6,
    };
    COPY_ADDR_FROM(param.ipv6_nh, cfg->nexthop.bytes);

    int ret = bpf_redirect_neigh(cfg->veth_ifindex, &param, sizeof(param), 0);
    if (ret != TC_ACT_REDIRECT) {
        mtu_chamber_count(MTU_CHAMBER_STAT_DIVERT_FAILED);
        return TC_ACT_SHOT;
    }

    mtu_chamber_count(MTU_CHAMBER_STAT_DIVERTED);
    return ret;
}

/// The return path: only a Packet Too Big that answers a recent admission gets
/// through, and it is delivered the way the datapath delivers everything else.
///
/// Everything else arriving on the return veth is counted and dropped. The
/// original packet must not be able to come back this way, and the only way to
/// know it has not is to accept exactly one shape.
static __always_inline int mtu_chamber_return(struct __sk_buff *skb, u32 l3_offset) {
    struct mtu_chamber_config *cfg = mtu_chamber_cfg();
    if (cfg == NULL || cfg->enabled == 0) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    struct ipv6hdr *ip6h = NULL;
    if (VALIDATE_READ_DATA(skb, &ip6h, l3_offset, sizeof(*ip6h))) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }
    if (ip6h->version != 6 || ip6h->nexthdr != NEXTHDR_ICMP) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    u32 icmp_offset = l3_offset + sizeof(struct ipv6hdr);
    struct icmp6hdr *icmp6 = NULL;
    if (VALIDATE_READ_DATA(skb, &icmp6, icmp_offset, sizeof(*icmp6))) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }
    if (icmp6->icmp6_type != ICMPV6_PKT_TOOBIG || icmp6->icmp6_code != 0) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    // Provenance: the chamber was given a set of addresses to speak with - the
    // LAN's own, because that is what a client expects its gateway to say - and
    // an error from any other address is not the error this datapath asked for.
    // A ULA client and a global client legitimately get different ones.
    bool source_known = false;
    u32 source_count = cfg->source_count;
    if (source_count > MTU_CHAMBER_MAX_SOURCES) source_count = MTU_CHAMBER_MAX_SOURCES;
#pragma unroll
    for (int i = 0; i < MTU_CHAMBER_MAX_SOURCES; i++) {
        if ((u32)i >= source_count) break;
        if (__builtin_memcmp(ip6h->saddr.in6_u.u6_addr8, cfg->sources[i].bytes, 16) == 0) {
            source_known = true;
            break;
        }
    }
    if (!source_known) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    // The quoted packet is what ties this to one admission. It must be present
    // in full enough to identify: an IPv6 header plus the L4 identity.
    u32 quote_offset = icmp_offset + sizeof(struct icmp6hdr);
    struct ipv6hdr *quote = NULL;
    if (VALIDATE_READ_DATA(skb, &quote, quote_offset, sizeof(*quote))) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }
    if (quote->version != 6) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    // The error is addressed to whoever sent the quoted packet; if it is not,
    // it is not this exchange and the datapath has no business relaying it.
    if (__builtin_memcmp(ip6h->daddr.in6_u.u6_addr8, quote->saddr.in6_u.u6_addr8, 16) != 0) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    u32 ident = 0;
    if (!mtu_chamber_l4_identity(skb, quote_offset + sizeof(struct ipv6hdr), quote->nexthdr,
                                 &ident)) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    struct mtu_chamber_key key = {0};
    COPY_ADDR_FROM(key.saddr.bytes, quote->saddr.in6_u.u6_addr8);
    COPY_ADDR_FROM(key.daddr.bytes, quote->daddr.in6_u.u6_addr8);
    key.l4_ident = ident;
    key.nexthdr = quote->nexthdr;

    struct mtu_chamber_value *admission = bpf_map_lookup_elem(&mtu_chamber_state_map, &key);
    if (admission == NULL) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    u64 now = bpf_ktime_get_ns();
    u64 ttl_ns = (u64)cfg->ttl_ms * 1000000ULL;
    if (cfg->ttl_ms == 0 || now - admission->admitted_ns > ttl_ns) {
        bpf_map_delete_elem(&mtu_chamber_state_map, &key);
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_EXPIRED);
        return TC_ACT_SHOT;
    }

    // The promised MTU has to be the MTU of the egress that admitted it, or the
    // client would be told to shrink to a number this path never verified.
    if (bpf_ntohl(icmp6->icmp6_dataun.un_data32[0]) != admission->egress_mtu) {
        bpf_map_delete_elem(&mtu_chamber_state_map, &key);
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    u32 lan_ifindex = admission->lan_ifindex;
    // One admission, at most one error: the entry is spent here, so a second
    // copy of the same error finds nothing to match and is dropped.
    bpf_map_delete_elem(&mtu_chamber_state_map, &key);

    // Deliver the way the datapath delivers everything else: from the link
    // addresses it learned for this client, out the interface it came in on.
    union u_inet6_addr client = {0};
    COPY_ADDR_FROM(client.bytes, quote->saddr.in6_u.u6_addr8);
    struct mac_value_v6 *mac = bpf_map_lookup_elem(&ip_mac_v6, &client);
    if (mac == NULL || mac->ifindex != lan_ifindex) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_NO_MAC);
        return TC_ACT_SHOT;
    }

    if (store_mac_v6(skb, mac->mac, mac->dev_mac)) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    int ret = bpf_redirect(lan_ifindex, 0);
    if (ret != TC_ACT_REDIRECT) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    mtu_chamber_count(MTU_CHAMBER_STAT_PTB_RETURNED);
    return ret;
}

#endif /* __LD_MTU_CHAMBER_H__ */
