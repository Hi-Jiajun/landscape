#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "landscape.h"
#include "mtu_guard/mtu_chamber.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

// The return gate, attached to the chamber's veth inside the main namespace.
//
// This link carries exactly one kind of packet: the Packet Too Big the chamber
// was asked to produce. Everything else is a failure of the arrangement - the
// original packet coming back, a stray frame, an error nobody asked for - and is
// dropped here rather than handed to the stack. That is what lets the chamber be
// a namespace with forwarding on and no accept in FORWARD: nothing it emits can
// reach anything except this check.
//
// It lives beside the other TC programs rather than with the header it uses
// because the build only compiles `src/bpf/` and `src/bpf/tc_chain/`; the shared
// mechanism is in `mtu_guard/mtu_chamber.h`.

SEC("tc/ingress")
int tc_mtu_chamber_return(struct __sk_buff *skb) {
    return mtu_chamber_return(skb, current_l3_offset);
}
