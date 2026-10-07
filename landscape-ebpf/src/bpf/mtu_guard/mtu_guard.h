#ifndef __LD_MTU_GUARD_H__
#define __LD_MTU_GUARD_H__
#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../landscape.h"

// Packets that leave the WAN larger than the WAN can carry.
//
// Forwarding here is done by the datapath (`bpf_redirect`), so the kernel's
// forwarding path never runs - and that is where both of the remedies live:
// ICMPv6 Packet Too Big for IPv6, and fragmentation for a DF=0 IPv4 packet. A
// packet over the egress MTU is therefore dropped in silence: no error comes
// back, nothing is fragmented, and the sender keeps believing it was sent.
//
// Measured on 2026-10-07 against a 1492 egress: `ping -6 -M do -s 1444` (1488
// bytes) is answered, `-s 1450` (1498) is dropped with no PTB, and an IPv4
// `-M dont` packet of 1500 bytes is dropped with no fragmentation. TCP hides it,
// because the MSS clamp keeps TCP under the limit in both directions.
//
// This file is the *classification and counting* half: which packets the egress
// cannot carry, by family. The remedy for the IPv6 case lives in
// `mtu_chamber.h`, and runs from a stage that sits after admission, so a packet
// this counts was one the firewall had already allowed out.

enum mtu_guard_stat {
    /// IPv6 over the egress MTU. IPv6 has no in-path fragmentation, so this is
    /// always a drop and always a missing Packet Too Big.
    MTU_GUARD_STAT_OVERSIZED_V6 = 0,
    /// IPv4 over the egress MTU with DF set: a missing Fragmentation Needed.
    MTU_GUARD_STAT_OVERSIZED_V4_DF = 1,
    /// IPv4 over the egress MTU without DF: a missing fragmentation.
    MTU_GUARD_STAT_OVERSIZED_V4_FRAGMENTABLE = 2,
    /// Skipped because the skb is a segmentation aggregate. **Not** a violation:
    /// the device splits it into pieces of `gso_size`, which fits. Counting these
    /// as violations would be a false positive, and the count is kept so a reader
    /// can see how much was excluded rather than having to trust that it was.
    MTU_GUARD_STAT_GSO_SKIPPED = 3,
    MTU_GUARD_STAT_MAX = 4,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MTU_GUARD_STAT_MAX);
    __type(key, u32);
    __type(value, u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mtu_guard_stats_map SEC(".maps");

static __always_inline void mtu_guard_count(u32 index) {
    u32 key = index;
    u64 *value = bpf_map_lookup_elem(&mtu_guard_stats_map, &key);
    if (value) __sync_fetch_and_add(value, 1);
}

/// What the egress is looking at, as a pure classification: the caller decides
/// whether to count it and whether anything can be done about it.
enum mtu_guard_verdict {
    /// Fits, or a header shape this does not judge (never a reason to act).
    MTU_GUARD_VERDICT_PASS = 0,
    /// A segmentation aggregate. Its pieces fit; it is not a violation.
    MTU_GUARD_VERDICT_GSO = 1,
    MTU_GUARD_VERDICT_OVERSIZE_V6 = 2,
    MTU_GUARD_VERDICT_OVERSIZE_V4_DF = 3,
    MTU_GUARD_VERDICT_OVERSIZE_V4_FRAGMENTABLE = 4,
};

/// Classify a packet about to leave the egress whose L3 MTU is `egress_mtu`.
///
/// Deliberately says nothing about *remedies*: it answers only "would this
/// packet fit on that egress". The IPv6 remedy has to preserve the path the
/// datapath chose, so it is a separate decision with its own file.
static __always_inline enum mtu_guard_verdict
mtu_guard_classify(struct __sk_buff *skb, u32 current_l3_offset, u16 egress_mtu) {
    // A segmentation aggregate is not a violation: `gso_size` says how big the
    // pieces will be, and those fit. Checked first, because an aggregate is
    // legitimately far larger than the MTU.
    if (skb->gso_size > 0) {
        return MTU_GUARD_VERDICT_GSO;
    }

    // Version lives in the top nibble of the first L3 byte for both families.
    u8 *first_byte = NULL;
    if (VALIDATE_READ_DATA(skb, &first_byte, current_l3_offset, 1)) {
        return MTU_GUARD_VERDICT_PASS;
    }
    u8 version = (*first_byte) >> 4;

    if (version == 6) {
        struct ipv6hdr *ip6h = NULL;
        if (VALIDATE_READ_DATA(skb, &ip6h, current_l3_offset, sizeof(*ip6h))) {
            return MTU_GUARD_VERDICT_PASS;
        }
        u32 l3_len = sizeof(*ip6h) + bpf_ntohs(ip6h->payload_len);
        if (l3_len > egress_mtu) return MTU_GUARD_VERDICT_OVERSIZE_V6;
        return MTU_GUARD_VERDICT_PASS;
    }

    if (version == 4) {
        struct iphdr *iph = NULL;
        if (VALIDATE_READ_DATA(skb, &iph, current_l3_offset, sizeof(*iph))) {
            return MTU_GUARD_VERDICT_PASS;
        }
        if (bpf_ntohs(iph->tot_len) <= egress_mtu) return MTU_GUARD_VERDICT_PASS;
        bool dont_fragment = (bpf_ntohs(iph->frag_off) & 0x4000) != 0;
        return dont_fragment ? MTU_GUARD_VERDICT_OVERSIZE_V4_DF
                             : MTU_GUARD_VERDICT_OVERSIZE_V4_FRAGMENTABLE;
    }

    return MTU_GUARD_VERDICT_PASS;
}

/// The counter a verdict belongs to, or -1 for "nothing to count".
static __always_inline int mtu_guard_stat_of(enum mtu_guard_verdict verdict) {
    switch (verdict) {
    case MTU_GUARD_VERDICT_GSO:
        return MTU_GUARD_STAT_GSO_SKIPPED;
    case MTU_GUARD_VERDICT_OVERSIZE_V6:
        return MTU_GUARD_STAT_OVERSIZED_V6;
    case MTU_GUARD_VERDICT_OVERSIZE_V4_DF:
        return MTU_GUARD_STAT_OVERSIZED_V4_DF;
    case MTU_GUARD_VERDICT_OVERSIZE_V4_FRAGMENTABLE:
        return MTU_GUARD_STAT_OVERSIZED_V4_FRAGMENTABLE;
    default:
        return -1;
    }
}

#endif /* __LD_MTU_GUARD_H__ */
