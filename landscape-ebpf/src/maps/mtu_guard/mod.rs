//! Counters for packets the WAN cannot carry (`mtu_guard/mtu_guard.h`).
//!
//! The datapath forwards by redirect, so the kernel's forwarding path never runs
//! and neither of its remedies does: no ICMPv6 Packet Too Big, no IPv4
//! fragmentation. A packet over the egress MTU is dropped in silence, which is what
//! these counters make visible.

mod stats;

pub use stats::*;
