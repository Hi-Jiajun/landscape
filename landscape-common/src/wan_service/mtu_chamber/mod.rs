//! The IPv6 Packet Too Big chamber: the settings the operator writes, the
//! wiring the datapath reads, and what the chamber did.
//!
//! The datapath forwards by `bpf_redirect`, so the kernel's forwarding path -
//! the only place a Packet Too Big is generated - never runs, and an IPv6 packet
//! over the egress MTU is dropped in silence. Enabling forwarding in the main
//! namespace to get the error back would give the kernel a general forwarding
//! path this design deliberately does not have, so the packet is handed instead
//! to a namespace whose only job is to produce that error, and the error is
//! validated on the way back. See `landscape-ebpf/src/bpf/mtu_guard/mtu_chamber.h`.
//!
//! Why this is worth the trouble, measured with a 1492 egress on 2026-10-07:
//! IPv6 TCP is hidden by the MSS clamp, but a 1498-byte ICMPv6 echo or a large
//! UDP datagram is dropped with no error at all, and the sender keeps believing
//! it was sent.

mod config;
mod dataplane;
mod wiring;

pub use config::*;
pub use dataplane::*;
pub use wiring::*;
