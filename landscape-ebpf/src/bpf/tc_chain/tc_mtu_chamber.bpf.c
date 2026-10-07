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
// IPv6 case to the chamber. IPv4 is counted only: the fragmentable case is a
// separate piece of work, and the DF case is not decided here.

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
