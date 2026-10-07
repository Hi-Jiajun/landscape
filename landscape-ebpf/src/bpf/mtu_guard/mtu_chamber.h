#ifndef __LD_MTU_CHAMBER_H__
#define __LD_MTU_CHAMBER_H__
#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../chain/tc_cb.h"
#include "../landscape.h"
#include "../neigh_ip4.h"
#include "../neigh_ip6.h"
#include "../pkg_def.h"
#include "mtu_guard.h"

// The over-MTU remedies, arranged so the kernel produces the error.
//
// The datapath forwards by redirect, so the kernel's forwarding path - the only
// place these errors are generated - never runs, and an over-MTU packet is
// dropped in silence. Enabling forwarding in this namespace to get the error back
// would hand the kernel a general forwarding path this design deliberately does
// not have. So the packet is handed to a namespace whose *only* job is to produce
// that error:
//
//   main datapath (admission, policy, egress selection already done)
//     |  over the MTU of the egress it selected, and only then
//     v  bpf_redirect_neigh over a dedicated veth
//   exception namespace ("chamber")
//     forwarding ON, one dummy egress carrying that egress's MTU,
//     FORWARD DROP, and no route that reaches a real network
//     -> the kernel's forwarding MTU check runs and emits the error
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
// headers, no fragments, no segmentation aggregates, and only TCP, UDP and echo.
// Anything outside that keeps the old behaviour - the packet is dropped as
// before, and the counter says why it was not given an error.
//
// Both families use the one mechanism because they are the same question:
//
//   * IPv6: any packet over the egress MTU. IPv6 has no in-path fragmentation, so
//     each one is a missing Packet Too Big.
//   * IPv4: a packet over the egress MTU **with DF set**, which is a missing
//     "fragmentation needed". A DF=0 packet is a different thing entirely - the
//     correct handling is to fragment it and send it, which needs a path to the
//     real WAN and is therefore out of scope by construction rather than by
//     omission. Those keep being dropped and counted by the egress-MTU stage.

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
    /// 1 = divert over-MTU packets into the chamber.
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
    /// The IPv4 half of the same two fields.
    ///
    /// IPv4 has no set of interchangeable addresses the way RFC 6724 gives IPv6:
    /// the client has one address, so the error's source is simply the LAN
    /// interface's own, and `source_count4` is what the return gate checks
    /// against. Kept separate from the IPv6 pair rather than unified, because
    /// their meanings differ (a chosen set vs. one address) and folding them
    /// together would hide that.
    __be32 nexthop4;
    __be32 sources4[MTU_CHAMBER_MAX_SOURCES];
    u32 source_count4;
    u32 _reserved4;
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
    /// An over-MTU IPv4 packet with DF set was handed to the chamber. The IPv6
    /// and IPv4 diversions are counted apart because they are different families
    /// with different acceptance criteria, and one number covering both would
    /// hide which of them stopped working.
    MTU_CHAMBER_STAT_DIVERTED_V4 = 13,
    /// A validated ICMPv4 "fragmentation needed" went back to the client.
    MTU_CHAMBER_STAT_FRAG_NEEDED_RETURNED = 14,
    /// An ICMPv4 error arrived on the return link and was refused, for any reason:
    /// wrong source, wrong type or code, no matching admission, or an advertised
    /// MTU that is not this egress's.
    MTU_CHAMBER_STAT_FRAG_NEEDED_REJECTED = 15,
    MTU_CHAMBER_STAT_MAX = 16,
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

/// Which family an admission belongs to.
///
/// Carried in the key rather than inferred, because the address fields are wide
/// enough for both: an IPv4 address lives in the first four bytes and the rest
/// are zero, which is also how `::a.b.c.d` is written - so without this byte a
/// v4 admission and a v6 one for that address would share an entry.
#define MTU_CHAMBER_FAMILY_V4 4
#define MTU_CHAMBER_FAMILY_V6 6

/// One admitted packet, keyed by the identity a reply can quote back.
///
/// The quoted packet in an error carries the original's headers, so the reply can
/// be tied to a specific admitted packet instead of to "some packet once". That is
/// what makes "one admission, at most one error" true.
struct mtu_chamber_key {
    union u_inet6_addr saddr;
    union u_inet6_addr daddr;
    /// TCP/UDP ports, or the echo identifier and sequence.
    u32 l4_ident;
    u8 nexthdr;
    u8 family;
    u8 _pad[2];
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
///
/// The family is part of the key for the same reason it is part of the admission
/// key: the address field is wide enough for both, so a v4 source and the v6
/// address that spells the same bytes must not share a budget.
struct mtu_chamber_budget_key {
    union u_inet6_addr addr;
    u8 family;
    u8 _pad[3];
};

struct mtu_chamber_budget_value {
    u64 window_start_ns;
    u32 used;
    u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct mtu_chamber_budget_key);
    __type(value, struct mtu_chamber_budget_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mtu_chamber_budget_map SEC(".maps");

static __always_inline struct mtu_chamber_config *mtu_chamber_cfg(void) {
    u32 key = 0;
    return bpf_map_lookup_elem(&mtu_chamber_cfg_map, &key);
}

#define MTU_CHAMBER_ONE_SECOND_NS 1000000000ULL

static __always_inline bool mtu_chamber_budget_allow(const struct mtu_chamber_config *cfg,
                                                     const struct mtu_chamber_budget_key *key) {
    // A half-written config has burst 0, and that must refuse rather than admit:
    // the failure mode of this branch has to be "no error, packet dropped as
    // before", never "unlimited errors".
    if (cfg->burst == 0) return false;

    u64 now = bpf_ktime_get_ns();
    struct mtu_chamber_budget_value *entry = bpf_map_lookup_elem(&mtu_chamber_budget_map, key);
    if (entry == NULL) {
        struct mtu_chamber_budget_value fresh = {
            .window_start_ns = now,
            .used = 1,
        };
        bpf_map_update_elem(&mtu_chamber_budget_map, key, &fresh, BPF_NOEXIST);
        return true;
    }

    if (now - entry->window_start_ns >= MTU_CHAMBER_ONE_SECOND_NS) {
        struct mtu_chamber_budget_value reset = {
            .window_start_ns = now,
            .used = 1,
        };
        bpf_map_update_elem(&mtu_chamber_budget_map, key, &reset, BPF_ANY);
        return true;
    }

    if (entry->used >= cfg->burst) return false;

    struct mtu_chamber_budget_value next = {
        .window_start_ns = entry->window_start_ns,
        .used = entry->used + 1,
    };
    bpf_map_update_elem(&mtu_chamber_budget_map, key, &next, BPF_ANY);
    return true;
}

/// The identity of an L4 header, as the quoted packet will repeat it.
///
/// Returns false for anything without a stable 4-byte identity: for the echo
/// types that is the identifier and sequence, and for TCP/UDP the port pair.
static __always_inline bool mtu_chamber_l4_identity(struct __sk_buff *skb, u32 l4_offset,
                                                    u8 nexthdr, u8 family, u32 *ident) {
    u32 offset = l4_offset;

    if (nexthdr == NEXTHDR_ICMP || nexthdr == IPPROTO_ICMP) {
        u8 icmp_type = 0;
        if (bpf_skb_load_bytes(skb, l4_offset, &icmp_type, sizeof(icmp_type))) return false;
        // The two families number echo requests differently, and an IPv4 ICMP
        // packet with an IPv6 echo type would be a packet that does not exist.
        bool is_echo = family == MTU_CHAMBER_FAMILY_V4
                           ? (icmp_type == ICMP_ECHO || icmp_type == ICMP_ECHOREPLY)
                           : (icmp_type == ICMPV6_ECHO_REQUEST || icmp_type == ICMPV6_ECHO_REPLY);
        if (!is_echo) return false;
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
/// The gates both families pass before anything family-specific happens.
///
/// Astra's first admission rule, as code: an over-MTU packet is only handed on
/// after the datapath finished authorising it, and a packet that was refused
/// never reaches this point at all - the stage sits behind the firewall - so a
/// denial cannot turn into an error feedback that tells the client something
/// about this egress.
static __always_inline bool mtu_chamber_may_act(struct __sk_buff *skb) {
    // Forwarded LAN traffic only. A locally generated packet still has the
    // kernel's own path, including its PMTU handling, and must keep it.
    if (!skb->cb[TC_CHAIN_CB_FORWARDED_OFFSET]) return false;
    // Something went wrong already, or the source is unknown; both mean the
    // reply could not be delivered, so do not start an exchange about it.
    if (skb->ingress_ifindex == 0) return false;
    return true;
}

/// The shared tail: budget, admission, divert. Returns the action to take, or
/// `TC_ACT_UNSPEC` when nothing was done and the old behaviour stands.
///
/// The family only decides which neighbour the packet is handed to; the
/// bookkeeping is the same for both, which is what keeps "one admission, at most
/// one error" one rule instead of two that can drift.
static __always_inline int mtu_chamber_hand_over(struct __sk_buff *skb, u8 family, u16 egress_mtu,
                                                 const union u_inet6_addr *src,
                                                 const union u_inet6_addr *dst, u8 l4_proto,
                                                 u32 ident) {
    struct mtu_chamber_config *cfg = mtu_chamber_cfg();
    if (cfg == NULL || cfg->enabled == 0 || cfg->veth_ifindex == 0) {
        mtu_chamber_count(MTU_CHAMBER_STAT_SKIPPED_DISABLED);
        return TC_ACT_UNSPEC;
    }

    // Copied out before anything writes to a map: a map value pointer does not
    // survive a helper that may modify maps, and the budget below is one.
    u32 veth_ifindex = cfg->veth_ifindex;
    struct bpf_redir_neigh param = {
        .nh_family = family == MTU_CHAMBER_FAMILY_V4 ? AF_INET : AF_INET6,
    };
    if (family == MTU_CHAMBER_FAMILY_V4) {
        COPY_ADDR_FROM(&param.ipv4_nh, &cfg->nexthop4);
    } else {
        COPY_ADDR_FROM(param.ipv6_nh, cfg->nexthop.bytes);
    }

    struct mtu_chamber_budget_key budget = {0};
    // An IPv4 address occupies the first four bytes and the rest stay zero, which
    // is also how `::a.b.c.d` is spelled - so the family byte is what keeps the
    // two apart, not the address bytes.
    COPY_ADDR_FROM(budget.addr.bytes, src->bytes);
    budget.family = family;

    // No address to speak with for this family means no error the client would
    // accept, so do not start an exchange about it: the packet keeps the old
    // behaviour and no admission is spent waiting for a reply that cannot come.
    if (family == MTU_CHAMBER_FAMILY_V4) {
        if (cfg->source_count4 == 0) {
            mtu_chamber_count(MTU_CHAMBER_STAT_SKIPPED_DISABLED);
            return TC_ACT_UNSPEC;
        }
    } else if (cfg->source_count == 0) {
        mtu_chamber_count(MTU_CHAMBER_STAT_SKIPPED_DISABLED);
        return TC_ACT_UNSPEC;
    }

    if (!mtu_chamber_budget_allow(cfg, &budget)) {
        mtu_chamber_count(MTU_CHAMBER_STAT_SKIPPED_BUDGET);
        // The packet cannot be carried by this egress either way, so refusing it
        // explicitly is the same outcome as the silence it would otherwise get -
        // just with a reason attached.
        return TC_ACT_SHOT;
    }

    struct mtu_chamber_key key = {0};
    COPY_ADDR_FROM(key.saddr.bytes, src->bytes);
    COPY_ADDR_FROM(key.daddr.bytes, dst->bytes);
    key.l4_ident = ident;
    key.nexthdr = l4_proto;
    key.family = family;

    struct mtu_chamber_value admission = {
        .lan_ifindex = skb->ingress_ifindex,
        .egress_mtu = egress_mtu,
        .admitted_ns = bpf_ktime_get_ns(),
    };
    if (bpf_map_update_elem(&mtu_chamber_state_map, &key, &admission, BPF_ANY)) {
        mtu_chamber_count(MTU_CHAMBER_STAT_STATE_FULL);
        return TC_ACT_SHOT;
    }

    int ret = bpf_redirect_neigh(veth_ifindex, &param, sizeof(param), 0);
    if (ret != TC_ACT_REDIRECT) {
        mtu_chamber_count(MTU_CHAMBER_STAT_DIVERT_FAILED);
        return TC_ACT_SHOT;
    }

    mtu_chamber_count(family == MTU_CHAMBER_FAMILY_V4 ? MTU_CHAMBER_STAT_DIVERTED_V4
                                                      : MTU_CHAMBER_STAT_DIVERTED);
    return ret;
}

static __always_inline int mtu_chamber_egress_v6(struct __sk_buff *skb, u32 l3_offset,
                                                 u16 egress_mtu) {
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
    if (!mtu_chamber_l4_identity(skb, l4_offset, l4_proto, MTU_CHAMBER_FAMILY_V6, &ident)) {
        mtu_chamber_count(MTU_CHAMBER_STAT_SKIPPED_L4);
        return TC_ACT_UNSPEC;
    }

    // Read the addresses with the helper rather than by copying through a packet
    // pointer. The direct form gave the verifier a base register it had already
    // spilled as a scalar, and the program would not load at all - measured on
    // the target kernel, where it failed with `R2 invalid mem access 'scalar'`.
    union u_inet6_addr src = {0};
    if (bpf_skb_load_bytes(skb, l3_offset + offsetof(struct ipv6hdr, saddr), src.bytes,
                           sizeof(src.bytes))) {
        return TC_ACT_UNSPEC;
    }
    union u_inet6_addr dst = {0};
    if (bpf_skb_load_bytes(skb, l3_offset + offsetof(struct ipv6hdr, daddr), dst.bytes,
                           sizeof(dst.bytes))) {
        return TC_ACT_UNSPEC;
    }

    return mtu_chamber_hand_over(skb, MTU_CHAMBER_FAMILY_V6, egress_mtu, &src, &dst, l4_proto,
                                 ident);
}

/// The IPv4 half: only a packet with DF set, because that is the one whose
/// correct handling is an error rather than a fragmentation.
///
/// Astra's rule 6 is why DF=0 is not here: the right thing for such a packet is to
/// fragment it and send it on, which requires this namespace to have a path to the
/// real WAN - the one thing the chamber is built not to have. It keeps being
/// dropped and counted by the stage that owns that counter.
static __always_inline int mtu_chamber_egress_v4(struct __sk_buff *skb, u32 l3_offset,
                                                 u16 egress_mtu) {
    u8 first = 0;
    if (bpf_skb_load_bytes(skb, l3_offset, &first, sizeof(first))) return TC_ACT_UNSPEC;
    if ((first >> 4) != 4) return TC_ACT_UNSPEC;

    u8 ihl_version = 0;
    u8 protocol = 0;
    __be16 tot_len_be = 0;
    __be16 frag_off_be = 0;
    if (bpf_skb_load_bytes(skb, l3_offset, &ihl_version, sizeof(ihl_version)) ||
        bpf_skb_load_bytes(skb, l3_offset + offsetof(struct iphdr, protocol), &protocol,
                           sizeof(protocol)) ||
        bpf_skb_load_bytes(skb, l3_offset + offsetof(struct iphdr, tot_len), &tot_len_be,
                           sizeof(tot_len_be)) ||
        bpf_skb_load_bytes(skb, l3_offset + offsetof(struct iphdr, frag_off), &frag_off_be,
                           sizeof(frag_off_be))) {
        return TC_ACT_UNSPEC;
    }

    u32 ihl = (u32)(ihl_version & 0x0F) * 4;
    if (ihl < sizeof(struct iphdr)) return TC_ACT_UNSPEC;

    u32 l3_len = bpf_ntohs(tot_len_be);
    if (l3_len <= egress_mtu) return TC_ACT_UNSPEC;

    __be16 frag_off = bpf_ntohs(frag_off_be);
    bool dont_fragment = (frag_off & 0x4000) != 0;
    bool is_fragment = (frag_off & 0x2000) != 0 || (frag_off & 0x1FFF) != 0;
    if (!dont_fragment || is_fragment) {
        // Not this function's case: a fragment has no identity to match a reply
        // against, and a DF=0 packet is the boundary the stage already counts.
        mtu_chamber_count(MTU_CHAMBER_STAT_SKIPPED_FRAGMENT);
        return TC_ACT_UNSPEC;
    }

    u32 l4_offset = l3_offset + ihl;
    u32 ident = 0;
    if (!mtu_chamber_l4_identity(skb, l4_offset, protocol, MTU_CHAMBER_FAMILY_V4, &ident)) {
        mtu_chamber_count(MTU_CHAMBER_STAT_SKIPPED_L4);
        return TC_ACT_UNSPEC;
    }

    // The address fields are four bytes here; the rest of the union stays zero,
    // and the family byte in the keys is what separates them from an IPv6
    // address that happens to spell the same bytes.
    union u_inet6_addr src = {0};
    union u_inet6_addr dst = {0};
    if (bpf_skb_load_bytes(skb, l3_offset + offsetof(struct iphdr, saddr), src.bytes, 4) ||
        bpf_skb_load_bytes(skb, l3_offset + offsetof(struct iphdr, daddr), dst.bytes, 4)) {
        return TC_ACT_UNSPEC;
    }

    return mtu_chamber_hand_over(skb, MTU_CHAMBER_FAMILY_V4, egress_mtu, &src, &dst, protocol,
                                 ident);
}

/// The egress decision: a packet the datapath already admitted and routed, whose
/// selected egress cannot carry it.
static __always_inline int mtu_chamber_egress(struct __sk_buff *skb, u32 l3_offset,
                                              u16 egress_mtu) {
    if (!mtu_chamber_may_act(skb)) return TC_ACT_UNSPEC;

    u8 first = 0;
    if (bpf_skb_load_bytes(skb, l3_offset, &first, sizeof(first))) return TC_ACT_UNSPEC;
    if ((first >> 4) == 6) return mtu_chamber_egress_v6(skb, l3_offset, egress_mtu);
    if ((first >> 4) == 4) return mtu_chamber_egress_v4(skb, l3_offset, egress_mtu);
    return TC_ACT_UNSPEC;
}

/// The return path: only a Packet Too Big that answers a recent admission gets
/// through, and it is delivered the way the datapath delivers everything else.
///
/// Everything else arriving on the return veth is counted and dropped. The
/// original packet must not be able to come back this way, and the only way to
/// know it has not is to accept exactly one shape.
/// Deliver a validated error to the client it belongs to.
///
/// Shared by both families, and it is the part that decides whether the client
/// can act on the error at all: the source address is the one the client already
/// treats as its gateway (it is what the chamber was given to speak with), and the
/// quoted packet is the client's own bytes, so the client's stack matches it
/// against the connection that is stuck.
static __always_inline int mtu_chamber_deliver(struct __sk_buff *skb, u8 family, u32 lan_ifindex,
                                               const u8 *client_addr, u32 returned_stat,
                                               u32 rejected_stat) {
    // The learned link address when it matches, the kernel's own neighbour
    // lookup otherwise.
    //
    // The fallback is not a nicety. Measured on 2026-10-07: the ISP re-delegated
    // the LAN prefix, the client took a new address from it, and the learned-address
    // map did not have that address yet - so the error was validated, the
    // admission consumed, and then dropped, with the client seeing nothing. The
    // kernel's neighbour table already knew the client (it had been sending from
    // that address for the packets that got here), so asking the kernel is what
    // turns that window from a failure into an ordinary delivery.
    if (family == MTU_CHAMBER_FAMILY_V4) {
        struct mac_key_v4 mac_key = {0};
        __builtin_memcpy(&mac_key.addr, client_addr, sizeof(mac_key.addr));
        struct mac_value_v4 *mac = bpf_map_lookup_elem(&ip_mac_v4, &mac_key);
        if (mac != NULL && mac->ifindex == lan_ifindex) {
            if (store_mac_v4(skb, mac->mac, mac->dev_mac)) {
                mtu_chamber_count(rejected_stat);
                return TC_ACT_SHOT;
            }
            int stored = bpf_redirect(lan_ifindex, 0);
            if (stored == TC_ACT_REDIRECT) {
                mtu_chamber_count(returned_stat);
                return stored;
            }
        }

        struct bpf_redir_neigh param4 = {
            .nh_family = AF_INET,
        };
        __builtin_memcpy(&param4.ipv4_nh, client_addr, sizeof(param4.ipv4_nh));
        int ret4 = bpf_redirect_neigh(lan_ifindex, &param4, sizeof(param4), 0);
        if (ret4 != TC_ACT_REDIRECT) {
            mtu_chamber_count(rejected_stat);
            return TC_ACT_SHOT;
        }
        mtu_chamber_count(returned_stat);
        return ret4;
    }

    union u_inet6_addr client = {0};
    COPY_ADDR_FROM(client.bytes, client_addr);
    struct mac_value_v6 *mac = bpf_map_lookup_elem(&ip_mac_v6, &client);
    if (mac != NULL && mac->ifindex == lan_ifindex) {
        if (store_mac_v6(skb, mac->mac, mac->dev_mac)) {
            mtu_chamber_count(rejected_stat);
            return TC_ACT_SHOT;
        }
        int stored = bpf_redirect(lan_ifindex, 0);
        if (stored == TC_ACT_REDIRECT) {
            mtu_chamber_count(returned_stat);
            return stored;
        }
    }

    struct bpf_redir_neigh param = {
        .nh_family = AF_INET6,
    };
    COPY_ADDR_FROM(param.ipv6_nh, client_addr);
    int ret = bpf_redirect_neigh(lan_ifindex, &param, sizeof(param), 0);
    if (ret != TC_ACT_REDIRECT) {
        mtu_chamber_count(rejected_stat);
        return TC_ACT_SHOT;
    }

    mtu_chamber_count(returned_stat);
    return ret;
}

/// Match a validated reply against the admission it answers and spend it.
///
/// Returns the interface the admitted packet came in on, or 0 when there is
/// nothing to match - expired, unknown, or an MTU that is not this egress's.
/// `verify_mtu` is separated because the IPv4 error's advertised MTU is a
/// different field with different width, read by its own caller.
static __always_inline u32 mtu_chamber_consume(const struct mtu_chamber_config *cfg, u8 family,
                                               const u8 *saddr, const u8 *daddr, u8 nexthdr,
                                               u32 ident, u32 advertised_mtu, u32 rejected_stat,
                                               u32 expired_stat) {
    struct mtu_chamber_key key = {0};
    COPY_ADDR_FROM(key.saddr.bytes, saddr);
    COPY_ADDR_FROM(key.daddr.bytes, daddr);
    key.l4_ident = ident;
    key.nexthdr = nexthdr;
    key.family = family;

    struct mtu_chamber_value *admission = bpf_map_lookup_elem(&mtu_chamber_state_map, &key);
    if (admission == NULL) {
        mtu_chamber_count(rejected_stat);
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    u64 ttl_ns = (u64)cfg->ttl_ms * 1000000ULL;
    if (cfg->ttl_ms == 0 || now - admission->admitted_ns > ttl_ns) {
        bpf_map_delete_elem(&mtu_chamber_state_map, &key);
        mtu_chamber_count(expired_stat);
        return 0;
    }

    // The promised MTU has to be the MTU of the egress that admitted it, or the
    // client would be told to shrink to a number this path never verified.
    if (advertised_mtu != admission->egress_mtu) {
        bpf_map_delete_elem(&mtu_chamber_state_map, &key);
        mtu_chamber_count(rejected_stat);
        return 0;
    }

    u32 lan_ifindex = admission->lan_ifindex;
    // One admission, at most one error: the entry is spent here, so a second copy
    // of the same error finds nothing to match and is dropped.
    bpf_map_delete_elem(&mtu_chamber_state_map, &key);
    return lan_ifindex;
}

static __always_inline int mtu_chamber_return_v6(struct __sk_buff *skb, u32 l3_offset,
                                                 struct mtu_chamber_config *cfg) {
    // Everything this function needs from the packet is read here, with the
    // helper, before any map work. A packet pointer cannot be held across a
    // helper call: the verifier ends up treating the reloaded register as a
    // scalar and refuses the program, which is what happened to an earlier
    // version of this function on the target kernel. Reading up front also makes
    // the shape of "validate, then act" the shape of the code.
    u8 outer_version_byte = 0;
    u8 outer_nexthdr = 0;
    u8 icmp_type = 0;
    u8 icmp_code = 0;
    __be32 advertised_mtu = 0;
    u32 icmp_offset = l3_offset + sizeof(struct ipv6hdr);
    if (bpf_skb_load_bytes(skb, l3_offset, &outer_version_byte, sizeof(outer_version_byte)) ||
        bpf_skb_load_bytes(skb, l3_offset + offsetof(struct ipv6hdr, nexthdr), &outer_nexthdr,
                           sizeof(outer_nexthdr)) ||
        bpf_skb_load_bytes(skb, icmp_offset, &icmp_type, sizeof(icmp_type)) ||
        bpf_skb_load_bytes(skb, icmp_offset + offsetof(struct icmp6hdr, icmp6_code), &icmp_code,
                           sizeof(icmp_code)) ||
        bpf_skb_load_bytes(skb, icmp_offset + offsetof(struct icmp6hdr, icmp6_dataun),
                           &advertised_mtu, sizeof(advertised_mtu))) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }
    if ((outer_version_byte >> 4) != 6 || outer_nexthdr != NEXTHDR_ICMP ||
        icmp_type != ICMPV6_PKT_TOOBIG || icmp_code != 0) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    // Provenance: the chamber was given a set of addresses to speak with - the
    // LAN's own, because that is what a client expects its gateway to say - and
    // an error from any other address is not the error this datapath asked for.
    // A ULA client and a global client legitimately get different ones.
    u8 outer_src[16];
    if (bpf_skb_load_bytes(skb, l3_offset + offsetof(struct ipv6hdr, saddr), outer_src,
                           sizeof(outer_src))) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }
    u32 source_count = cfg->source_count;
    if (source_count > MTU_CHAMBER_MAX_SOURCES) source_count = MTU_CHAMBER_MAX_SOURCES;
    bool source_known = false;
    // Unrolled so each `sources[i]` is a constant offset into the map value, which
    // is what lets the verifier bound the read without reasoning about `i`.
#pragma unroll
    for (int i = 0; i < MTU_CHAMBER_MAX_SOURCES; i++) {
        if ((u32)i < source_count &&
            __builtin_memcmp(outer_src, cfg->sources[i].bytes, sizeof(outer_src)) == 0) {
            source_known = true;
        }
    }
    if (!source_known) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    // The quoted packet is what ties this to one admission. It must be present
    // in full enough to identify: an IPv6 header plus the L4 identity. Read with
    // the helper, for the same reason as the source addresses above.
    u32 quote_offset = icmp_offset + sizeof(struct icmp6hdr);
    u8 quote_version = 0;
    u8 quote_nexthdr = 0;
    u8 quote_saddr[16];
    u8 quote_daddr[16];
    bool quoted = true;
    quoted &= bpf_skb_load_bytes(skb, quote_offset, &quote_version, sizeof(quote_version)) == 0;
    quoted &= bpf_skb_load_bytes(skb, quote_offset + offsetof(struct ipv6hdr, nexthdr),
                                 &quote_nexthdr, sizeof(quote_nexthdr)) == 0;
    quoted &= bpf_skb_load_bytes(skb, quote_offset + offsetof(struct ipv6hdr, saddr), quote_saddr,
                                 sizeof(quote_saddr)) == 0;
    quoted &= bpf_skb_load_bytes(skb, quote_offset + offsetof(struct ipv6hdr, daddr), quote_daddr,
                                 sizeof(quote_daddr)) == 0;
    if (!quoted || (quote_version >> 4) != 6) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    // The error is addressed to whoever sent the quoted packet; if it is not, it
    // is not this exchange and the datapath has no business relaying it.
    u8 outer_dst[16];
    if (bpf_skb_load_bytes(skb, l3_offset + offsetof(struct ipv6hdr, daddr), outer_dst,
                           sizeof(outer_dst))) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }
    if (__builtin_memcmp(outer_dst, quote_saddr, sizeof(outer_dst)) != 0) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    u32 ident = 0;
    if (!mtu_chamber_l4_identity(skb, quote_offset + sizeof(struct ipv6hdr), quote_nexthdr,
                                 MTU_CHAMBER_FAMILY_V6, &ident)) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    u32 lan_ifindex = mtu_chamber_consume(
        cfg, MTU_CHAMBER_FAMILY_V6, quote_saddr, quote_daddr, quote_nexthdr, ident,
        bpf_ntohl(advertised_mtu), MTU_CHAMBER_STAT_PTB_REJECTED, MTU_CHAMBER_STAT_PTB_EXPIRED);
    if (lan_ifindex == 0) return TC_ACT_SHOT;

    return mtu_chamber_deliver(skb, MTU_CHAMBER_FAMILY_V6, lan_ifindex, quote_saddr,
                               MTU_CHAMBER_STAT_PTB_RETURNED, MTU_CHAMBER_STAT_PTB_REJECTED);
}

/// The IPv4 half of the return path: an ICMP "fragmentation needed".
///
/// The shape is the same contract as IPv6 - validated provenance, a quoted packet
/// that matches a recent admission, the advertised MTU equal to the egress's own -
/// with IPv4's own header forms. The addresses are checked against the LAN address
/// the chamber was given, so an error from any other source is not relayed.
static __always_inline int mtu_chamber_return_v4(struct __sk_buff *skb, u32 l3_offset,
                                                 struct mtu_chamber_config *cfg) {
    u8 ihl_version = 0;
    u8 protocol = 0;
    if (bpf_skb_load_bytes(skb, l3_offset, &ihl_version, sizeof(ihl_version)) ||
        bpf_skb_load_bytes(skb, l3_offset + offsetof(struct iphdr, protocol), &protocol,
                           sizeof(protocol))) {
        mtu_chamber_count(MTU_CHAMBER_STAT_FRAG_NEEDED_REJECTED);
        return TC_ACT_SHOT;
    }
    if ((ihl_version >> 4) != 4 || protocol != IPPROTO_ICMP) {
        mtu_chamber_count(MTU_CHAMBER_STAT_FRAG_NEEDED_REJECTED);
        return TC_ACT_SHOT;
    }
    u32 ihl = (u32)(ihl_version & 0x0F) * 4;
    if (ihl < sizeof(struct iphdr)) {
        mtu_chamber_count(MTU_CHAMBER_STAT_FRAG_NEEDED_REJECTED);
        return TC_ACT_SHOT;
    }

    // ICMPv4 destination-unreachable, code 4 (fragmentation needed). The MTU
    // lives in the two bytes after the unused half of the fourth word, which is
    // where a router puts the next-hop MTU for exactly this type and code.
    u32 icmp_offset = l3_offset + ihl;
    u8 icmp_type = 0;
    u8 icmp_code = 0;
    __be16 advertised_mtu_be = 0;
    if (bpf_skb_load_bytes(skb, icmp_offset, &icmp_type, sizeof(icmp_type)) ||
        bpf_skb_load_bytes(skb, icmp_offset + 1, &icmp_code, sizeof(icmp_code)) ||
        bpf_skb_load_bytes(skb, icmp_offset + 6, &advertised_mtu_be, sizeof(advertised_mtu_be))) {
        mtu_chamber_count(MTU_CHAMBER_STAT_FRAG_NEEDED_REJECTED);
        return TC_ACT_SHOT;
    }
    if (icmp_type != ICMP_DEST_UNREACH || icmp_code != 4) {
        mtu_chamber_count(MTU_CHAMBER_STAT_FRAG_NEEDED_REJECTED);
        return TC_ACT_SHOT;
    }

    u8 outer_src[4];
    u8 outer_dst[4];
    if (bpf_skb_load_bytes(skb, l3_offset + offsetof(struct iphdr, saddr), outer_src,
                           sizeof(outer_src)) ||
        bpf_skb_load_bytes(skb, l3_offset + offsetof(struct iphdr, daddr), outer_dst,
                           sizeof(outer_dst))) {
        mtu_chamber_count(MTU_CHAMBER_STAT_FRAG_NEEDED_REJECTED);
        return TC_ACT_SHOT;
    }

    u32 source_count = cfg->source_count4;
    if (source_count > MTU_CHAMBER_MAX_SOURCES) source_count = MTU_CHAMBER_MAX_SOURCES;
    bool source_known = false;
#pragma unroll
    for (int i = 0; i < MTU_CHAMBER_MAX_SOURCES; i++) {
        if ((u32)i < source_count &&
            __builtin_memcmp(outer_src, &cfg->sources4[i], sizeof(outer_src)) == 0) {
            source_known = true;
        }
    }
    if (!source_known) {
        mtu_chamber_count(MTU_CHAMBER_STAT_FRAG_NEEDED_REJECTED);
        return TC_ACT_SHOT;
    }

    // The quoted packet: an IPv4 header plus at least eight bytes of its payload,
    // which is what the L4 identity needs.
    u32 quote_offset = icmp_offset + 8;
    u8 quote_ihl_version = 0;
    u8 quote_protocol = 0;
    u8 quote_saddr[4];
    u8 quote_daddr[4];
    bool quoted = true;
    quoted &=
        bpf_skb_load_bytes(skb, quote_offset, &quote_ihl_version, sizeof(quote_ihl_version)) == 0;
    quoted &= bpf_skb_load_bytes(skb, quote_offset + offsetof(struct iphdr, protocol),
                                 &quote_protocol, sizeof(quote_protocol)) == 0;
    quoted &= bpf_skb_load_bytes(skb, quote_offset + offsetof(struct iphdr, saddr), quote_saddr,
                                 sizeof(quote_saddr)) == 0;
    quoted &= bpf_skb_load_bytes(skb, quote_offset + offsetof(struct iphdr, daddr), quote_daddr,
                                 sizeof(quote_daddr)) == 0;
    if (!quoted || (quote_ihl_version >> 4) != 4) {
        mtu_chamber_count(MTU_CHAMBER_STAT_FRAG_NEEDED_REJECTED);
        return TC_ACT_SHOT;
    }
    u32 quote_ihl = (u32)(quote_ihl_version & 0x0F) * 4;
    if (quote_ihl < sizeof(struct iphdr)) {
        mtu_chamber_count(MTU_CHAMBER_STAT_FRAG_NEEDED_REJECTED);
        return TC_ACT_SHOT;
    }

    // The error is addressed to whoever sent the quoted packet.
    if (__builtin_memcmp(outer_dst, quote_saddr, sizeof(outer_dst)) != 0) {
        mtu_chamber_count(MTU_CHAMBER_STAT_FRAG_NEEDED_REJECTED);
        return TC_ACT_SHOT;
    }

    u32 ident = 0;
    if (!mtu_chamber_l4_identity(skb, quote_offset + quote_ihl, quote_protocol,
                                 MTU_CHAMBER_FAMILY_V4, &ident)) {
        mtu_chamber_count(MTU_CHAMBER_STAT_FRAG_NEEDED_REJECTED);
        return TC_ACT_SHOT;
    }

    // The admission key carries the address in the first four bytes of a
    // sixteen-byte field, which is how the divert wrote it.
    u8 saddr[16] = {0};
    u8 daddr[16] = {0};
    __builtin_memcpy(saddr, quote_saddr, sizeof(quote_saddr));
    __builtin_memcpy(daddr, quote_daddr, sizeof(quote_daddr));

    u32 lan_ifindex =
        mtu_chamber_consume(cfg, MTU_CHAMBER_FAMILY_V4, saddr, daddr, quote_protocol, ident,
                            bpf_ntohs(advertised_mtu_be), MTU_CHAMBER_STAT_FRAG_NEEDED_REJECTED,
                            MTU_CHAMBER_STAT_FRAG_NEEDED_REJECTED);
    if (lan_ifindex == 0) return TC_ACT_SHOT;

    return mtu_chamber_deliver(skb, MTU_CHAMBER_FAMILY_V4, lan_ifindex, quote_saddr,
                               MTU_CHAMBER_STAT_FRAG_NEEDED_RETURNED,
                               MTU_CHAMBER_STAT_FRAG_NEEDED_REJECTED);
}

/// The return gate: only an error that answers a recent admission gets through.
///
/// Everything else arriving on the return veth is counted and dropped. The
/// original packet must not be able to come back this way, and the only way to
/// know it has not is to accept exactly one shape per family.
static __always_inline int mtu_chamber_return(struct __sk_buff *skb, u32 l3_offset) {
    struct mtu_chamber_config *cfg = mtu_chamber_cfg();
    if (cfg == NULL || cfg->enabled == 0) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }

    u8 first = 0;
    if (bpf_skb_load_bytes(skb, l3_offset, &first, sizeof(first))) {
        mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
        return TC_ACT_SHOT;
    }
    if ((first >> 4) == 6) return mtu_chamber_return_v6(skb, l3_offset, cfg);
    if ((first >> 4) == 4) return mtu_chamber_return_v4(skb, l3_offset, cfg);

    mtu_chamber_count(MTU_CHAMBER_STAT_PTB_REJECTED);
    return TC_ACT_SHOT;
}

#endif /* __LD_MTU_CHAMBER_H__ */
