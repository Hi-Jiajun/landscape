#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "land_dns_dispatcher.h"
#include "flow_match.h"

char LICENSE[] SEC("license") = "GPL";

#undef BPF_LOG_TOPIC

// Which listener this program instance was loaded for.
//
// The plaintext DNS listener and the DoH listener are both TCP, so `ip_protocol`
// cannot tell them apart - and with one key slot for "TCP" they overwrote each
// other in the map, whichever registered last. A TCP :53 query then selected the
// DoH socket, which sits in a different reuseport group, and
// `bpf_sk_select_reuseport` refused it with EBADFD (measured on the live router).
//
// Which namespace applies is decided by the reuseport group, not by inspecting the
// packet: the two listeners are on different ports and therefore in different
// groups, and each group carries the program instance loaded for it.
const volatile u8 listener_kind = 0;

#define DNS_LISTENER_KIND_PLAINTEXT 0
#define DNS_LISTENER_KIND_DOH 1

// Three sockets per flow, so the key carries two bits of listener kind rather than
// the one bit that only had room for UDP-versus-TCP.
//
// The key has to stay inside `max_entries`: a SOCKMAP's key is an index, and the
// kernel rejects one at or beyond the size (`-E2BIG`, measured while trying to give
// DoH a namespace above the plaintext space).
#define DNS_LISTENER_KIND_PLAINTEXT_UDP 0
#define DNS_LISTENER_KIND_PLAINTEXT_TCP 1
#define DNS_LISTENER_KIND_DOH 2

SEC("sk_reuseport/migrate")
int reuseport_dns_dispatcher(struct sk_reuseport_md *reuse_md) {
#define BPF_LOG_TOPIC ">> select_dns"
    // struct bpf_sock *sk;
    // struct bpf_sock *msk = reuse_md->migrating_sk;

    struct flow_match_key match_key = {0};
    int ret = 0;
    __u32 flow_id = 0;

    ret = bpf_skb_load_bytes_relative(reuse_md, 6, &match_key.mac.mac, 6, BPF_HDR_START_MAC);
    if (!ret) {
        match_key.prefixlen = FLOW_MAC_MATCH_LEN;
        match_key.is_match_ip = FLOW_ENTRY_MODE_MAC;

        // PRINT_MAC_ADDR(match_key.mac.mac);

        u32 *flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &match_key);
        if (flow_id_ptr != NULL) {
            flow_id = *flow_id_ptr;
        }
    }

    match_key.is_match_ip = FLOW_ENTRY_MODE_IP;
    if (reuse_md->eth_protocol == ETH_IPV4) {
        match_key.prefixlen = FLOW_IP_IPV4_MATCH_LEN;
        match_key.l3_protocol = LANDSCAPE_IPV4_TYPE;
        ret = bpf_skb_load_bytes_relative(reuse_md, offsetof(struct iphdr, saddr),
                                          &match_key.src_addr, 4, BPF_HDR_START_NET);
        if (ret) {
            ld_bpf_log("reuseport_dns_dispatcher, read src IP error: %d", ret);
            return SK_DROP;
        }
        // ld_bpf_log("src ip: %pI4", &match_key.src_addr);
    } else {
        match_key.prefixlen = FLOW_IP_IPV6_MATCH_LEN;
        match_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
        ret = bpf_skb_load_bytes_relative(reuse_md, offsetof(struct ipv6hdr, saddr),
                                          &match_key.src_addr, 16, BPF_HDR_START_NET);
        if (ret) {
            ld_bpf_log("reuseport_dns_dispatcher, read src IP error: %d", ret);
            return SK_DROP;
        }

        // ld_bpf_log("src ip: %pI6", &match_key.src_addr);
    }

    u32 *flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &match_key);
    if (flow_id_ptr != NULL) {
        flow_id = *flow_id_ptr;
    }

    // key = (flow_id << 2) | listener kind. Which kind applies comes from the
    // reuseport group this program instance was loaded for, not from the packet:
    // the plaintext TCP and DoH listeners are both TCP and can only be told apart
    // by their group.
    __u32 kind = DNS_LISTENER_KIND_PLAINTEXT_UDP;
    if (listener_kind == DNS_LISTENER_KIND_DOH) {
        kind = DNS_LISTENER_KIND_DOH;
    } else if (reuse_md->ip_protocol == IPPROTO_TCP) {
        kind = DNS_LISTENER_KIND_PLAINTEXT_TCP;
    }
    __u32 flow_sock_key = (flow_id << 2) | kind;

    // ld_bpf_log("find flow_id: %d, key: %d", flow_id, flow_sock_key);
    ret = bpf_sk_select_reuseport(reuse_md, &dns_flow_socks, &flow_sock_key, 0);
    if (ret) {
        ld_bpf_log("bpf_sk_select_reuseport err: %d", ret);
        return SK_DROP;
    }

    return SK_PASS;
#undef BPF_LOG_TOPIC
}
