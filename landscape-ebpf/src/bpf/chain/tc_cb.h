#ifndef __LD_TC_CB_H_
#define __LD_TC_CB_H_

// set by pick_wan; read by tc_wan_egress_intro to enter chain
#define TC_CHAIN_CB_FORWARDED_OFFSET 0
// set by tc_wan_chain_ingress_root; read by WAN ingress exit
#define TC_CHAIN_CB_L3_OFFSET 1
// set by the NAT stage when it rewrote the source prefix (NPTv6); read by the
// egress MTU stage, which must not reason about an address the egress changed.
#define TC_CHAIN_CB_NPT_OFFSET 2

#endif /* __LD_TC_CB_H_ */
