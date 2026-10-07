#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "landscape.h"
#include "pkg_def.h"
#include "chain/tc_stage.h"
#include "chain/tc_wan_exit_maps.h"
#include "mtu_guard/mtu_chamber.h"
#include "mtu_guard/mtu_guard.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u16 mtu_size = 1492;
const volatile u32 current_l3_offset = 14;

// The egress MTU stage.
//
// Where this sits is the whole point: after the firewall, so a packet it acts on
// was one the operator's policy already allowed out, and before the egress
// encapsulation, so the packet is still the plain IP packet the client sent and
// the MTU being compared is the egress's own L3 MTU. A packet the firewall
// refused never reaches here, which is what keeps a denial a denial no matter
// how large it is.
//
// It counts what the egress cannot carry for both families, and it hands the
// cases the chamber can answer to it:
//
//   * IPv6 over the MTU - every one of them, since IPv6 has no in-path
//     fragmentation;
//   * IPv4 is counted and **not** answered, for a reason that had to be measured
//     rather than reasoned about: by the time this stage runs, the NAT stage has
//     already rewritten the source address, so the diverted packet carries the
//     WAN address instead of the client's. The kernel would then send the
//     fragmentation-needed error to that rewritten source - the router itself -
//     and the quoted packet inside it would not match the client's connection
//     either. Measured on 2026-10-08: the admissions show source 100.76.202.219
//     (this router's WAN address) rather than the client's 192.168.1.140, and the
//     chamber emitted the errors to a destination that went nowhere. Answering
//     IPv4 from here needs the NAT mapping reversed, which is a design decision
//     rather than a patch; until then IPv4 keeps the old behaviour and the
//     counters below keep the size of the gap visible.
//
// An IPv4 packet with DF cleared is not handed over: the right thing for it is to
// be fragmented and sent, which needs a path to the real WAN that the chamber is
// built not to have. It keeps being dropped, and `oversized_v4_fragmentable`
// keeps counting it so the boundary is visible rather than assumed.

SEC("tc/egress")
int tc_mtu_chamber_wan_egress(struct __sk_buff *skb) {
    enum mtu_guard_verdict verdict = mtu_guard_classify(skb, current_l3_offset, mtu_size);
    int stat = mtu_guard_stat_of(verdict);
    if (stat >= 0) mtu_guard_count((u32)stat);

    if (verdict == MTU_GUARD_VERDICT_OVERSIZE_V6) {
        int ret = mtu_chamber_egress(skb, current_l3_offset, mtu_size);
        if (ret != TC_ACT_UNSPEC) return ret;
    }

    TC_CHAIN_WAN_EGRESS(skb);
    bpf_tail_call(skb, &tc_pipe_exits_wan_egress, TC_NEXT_SLOT);
    return TC_ACT_UNSPEC;
}
