pub mod config;
pub mod dataplane;

pub use config::*;

/// What the WAN egress saw of packets it could not carry.
///
/// The datapath forwards by redirect, so the kernel's forwarding path - and both of
/// its remedies, ICMPv6 Packet Too Big and IPv4 fragmentation - never runs. A
/// packet over the egress MTU is therefore dropped in silence, which is what these
/// counters make visible.
///
/// This is measurement, not a fix: emitting the error is a separate piece of work,
/// because the path that emits it has to preserve the routing, NAT and policy
/// decisions the datapath already made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MtuGuardStats {
    /// IPv6 over the egress MTU. IPv6 has no in-path fragmentation, so this is
    /// always a drop and always a missing Packet Too Big.
    pub oversized_v6: u64,
    /// IPv4 over the egress MTU with DF set: a missing Fragmentation Needed.
    pub oversized_v4_df: u64,
    /// IPv4 over the egress MTU without DF: a missing fragmentation.
    pub oversized_v4_fragmentable: u64,
    /// Skipped because the skb was a segmentation aggregate - not a violation.
    /// Published so the exclusions are visible rather than assumed.
    pub gso_skipped: u64,
}

impl MtuGuardStats {
    /// Whether any packet was actually too big for the WAN.
    pub fn has_violations(&self) -> bool {
        self.oversized_v6 + self.oversized_v4_df + self.oversized_v4_fragmentable > 0
    }
}
