#ifndef __LD_ROUTE_UNCLASSIFIED_H__
#define __LD_ROUTE_UNCLASSIFIED_H__
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "../base/mark.h"
#include "../landscape.h"

// What to do with a destination nothing classified.
//
// The routing contract for this gateway is "a destination that is explicitly
// allowed goes direct, anything explicitly proxied goes to its tier, and
// anything *unclassified* goes to a managed fallback tier or is refused - never
// silently direct". The datapath did not have that last part: an unclassified
// destination kept the packet's own flow, and with no device-to-flow assignment
// that flow is 0, which resolves to a plain forward. Measured on 2026-10-07: a
// LAN client's real IPv6 address reached three independent external reflectors,
// with the reflector's packets coming back to that address on the WAN.
//
// The distinction this relies on already exists end to end and is visible in
// the route cache: a destination a rule sent direct carries `Direct` in its
// mark (the cache holds `0x00000100`), while one nothing claimed carries
// `KeepGoing` with flow 0 (the cache holds `0x00000000`). So "explicitly direct"
// and "unclassified" are already different states; what was missing is a policy
// for the second one.

// Leave the packet on its own flow. The pre-existing behaviour, and what the
// switch being off means.
#define ROUTE_UNCLASSIFIED_PASSTHROUGH 0
// Refuse it in the datapath.
#define ROUTE_UNCLASSIFIED_DROP 1
// Send it to a managed tier.
#define ROUTE_UNCLASSIFIED_FLOW 2

struct route_unclassified_cfg {
    u8 enabled;
    u8 action;
    u16 _pad;
    /// The fallback tier, when `action` is `ROUTE_UNCLASSIFIED_FLOW`. Flow 0 is
    /// not a tier, so it is refused as a configuration rather than treated as
    /// "direct": that is the whole point of this gate.
    u32 flow_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct route_unclassified_cfg);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} route_unclassified_cfg_map SEC(".maps");

/// Whether a mark means "nothing classified this destination".
///
/// Only `KeepGoing` with flow 0 qualifies. `Direct` is an explicit decision and
/// keeps its direct path; a mark naming a real tier is already classified; and a
/// redirect that names no tier is a configuration the user-space engine
/// deliberately treats as `Direct`, so this gate does not reinterpret it.
static __always_inline bool route_mark_is_unclassified(u32 flow_mark) {
    return get_flow_action(flow_mark) == FLOW_KEEP_GOING && get_flow_id(flow_mark) == 0;
}

/// Apply the unclassified-destination policy to a verdict, in place.
///
/// Returns true when the packet must be refused. `flow_mark` is left holding the
/// fallback tier otherwise, which is what the caller then caches and routes by.
static __always_inline bool route_unclassified_apply(u32 *flow_mark) {
    if (!route_mark_is_unclassified(*flow_mark)) return false;

    u32 key = 0;
    struct route_unclassified_cfg *cfg = bpf_map_lookup_elem(&route_unclassified_cfg_map, &key);
    if (!cfg || !cfg->enabled) return false;

    if (cfg->action == ROUTE_UNCLASSIFIED_DROP) return true;
    if (cfg->action == ROUTE_UNCLASSIFIED_FLOW) {
        // A fallback naming flow 0 would resolve back to the direct path this
        // gate exists to prevent, so it is refused rather than obeyed. The
        // caller's target lookup drops a packet whose tier has no target, which
        // is the fail-closed behaviour the contract asks for.
        if (cfg->flow_id == 0) return true;
        *flow_mark = replace_flow_id(*flow_mark, (u8)cfg->flow_id);
        *flow_mark = replace_flow_action(*flow_mark, FLOW_REDIRECT);
        return false;
    }
    // An unknown action is not something to guess at.
    return false;
}

#endif /* __LD_ROUTE_UNCLASSIFIED_H__ */
