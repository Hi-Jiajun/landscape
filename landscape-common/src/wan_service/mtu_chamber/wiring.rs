//! The datapath-facing shape of the chamber, and its counter names.

/// How many addresses the chamber may speak with. A home LAN usually has one
/// (a delegated prefix) or two (that plus a ULA); the kernel picks between them
/// per client, so the set has to cover both.
pub const MTU_CHAMBER_MAX_SOURCES: usize = 4;

/// The chamber's wiring, as `mtu_chamber_cfg_map` holds it.
///
/// This is a wire format: the field order and widths are the C struct's, and
/// the encoding below is what the datapath reads. It lives here rather than in
/// the eBPF crate so the service that builds it and the layer that writes it
/// agree on one definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MtuChamberWiring {
    /// The chamber veth in the main namespace: the divert target.
    pub veth_ifindex: u32,
    /// How many of `sources` are in use.
    pub source_count: u32,
    /// How long an admission stays valid, in milliseconds.
    pub ttl_ms: u32,
    /// Per-source admissions per second. 0 refuses everything.
    pub burst: u32,
    /// The chamber's address on that veth, for the neighbour rewrite.
    pub nexthop: [u8; 16],
    /// The addresses the chamber may speak with, copied from the LAN
    /// interfaces. The return gate accepts an error from one of these and
    /// refuses the rest.
    pub sources: [[u8; 16]; MTU_CHAMBER_MAX_SOURCES],
}

/// Bytes of `struct mtu_chamber_config`: `enabled`, `veth_ifindex`,
/// `source_count`, `ttl_ms`, `burst`, four bytes of padding, the nexthop, then
/// [`MTU_CHAMBER_MAX_SOURCES`] addresses.
pub const MTU_CHAMBER_CFG_SIZE: usize = 24 + 16 + 16 * MTU_CHAMBER_MAX_SOURCES;

impl MtuChamberWiring {
    /// Whether this wiring asks the datapath to divert anything.
    ///
    /// A zeroed wiring is the "count only" state, which is both the default and
    /// what a chamber that failed to come up is reset to.
    pub fn diverts(&self) -> bool {
        self.veth_ifindex != 0 && self.burst != 0 && self.ttl_ms != 0 && self.source_count != 0
    }

    /// The bytes the datapath reads: `enabled` first, then the fields.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MTU_CHAMBER_CFG_SIZE);
        // `enabled` is the C struct's first word. It is 1 whenever this struct is
        // written, because "no chamber" is represented by a zeroed struct rather
        // than by this flag; `diverts()` is the question the datapath asks.
        out.extend_from_slice(&1u32.to_ne_bytes());
        out.extend_from_slice(&self.veth_ifindex.to_ne_bytes());
        out.extend_from_slice(&self.source_count.to_ne_bytes());
        out.extend_from_slice(&self.ttl_ms.to_ne_bytes());
        out.extend_from_slice(&self.burst.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&self.nexthop);
        for source in &self.sources {
            out.extend_from_slice(source);
        }
        out
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() < MTU_CHAMBER_CFG_SIZE {
            return None;
        }
        let u32_at = |offset: usize| {
            u32::from_ne_bytes(raw[offset..offset + 4].try_into().unwrap_or_default())
        };
        let mut nexthop = [0u8; 16];
        nexthop.copy_from_slice(&raw[24..40]);
        let mut sources = [[0u8; 16]; MTU_CHAMBER_MAX_SOURCES];
        for (i, source) in sources.iter_mut().enumerate() {
            let at = 40 + i * 16;
            source.copy_from_slice(&raw[at..at + 16]);
        }
        Some(Self {
            veth_ifindex: u32_at(4),
            source_count: u32_at(8),
            ttl_ms: u32_at(12),
            burst: u32_at(16),
            nexthop,
            sources,
        })
    }
}

/// What the chamber did, by reason. Every refusal is counted rather than
/// inferred, so a packet that went without an error can always be explained.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MtuChamberStats {
    /// Over an egress MTU, and handed to the chamber.
    pub diverted: u64,
    /// Over an egress MTU with no chamber available: counted, and left to the
    /// old behaviour.
    pub skipped_disabled: u64,
    /// Out of scope because the egress rewrote the source prefix (NPTv6).
    pub skipped_npt: u64,
    /// Out of scope: an extension header this stage does not walk.
    pub skipped_exthdr: u64,
    /// Out of scope: a fragment header, whose payload has no L4 header.
    pub skipped_fragment: u64,
    /// Out of scope: not TCP, UDP or IPv6 echo.
    pub skipped_l4: u64,
    /// Refused by the per-source budget.
    pub skipped_budget: u64,
    /// The admission table would not take the entry.
    pub state_full: u64,
    /// The divert itself failed.
    pub divert_failed: u64,
    /// A validated error went back to the client.
    pub ptb_returned: u64,
    /// Something arrived on the return veth that was not a valid reply to a
    /// recent admission.
    pub ptb_rejected: u64,
    /// A valid reply whose client link address is not known.
    pub ptb_no_mac: u64,
    /// A valid reply that arrived after its admission expired.
    pub ptb_expired: u64,
}

impl MtuChamberStats {
    /// Packets the egress could not carry and no error was sent for, whatever
    /// the reason. The number that says the remedy has a gap.
    pub fn without_an_error(&self) -> u64 {
        self.skipped_disabled
            + self.skipped_npt
            + self.skipped_exthdr
            + self.skipped_fragment
            + self.skipped_l4
            + self.skipped_budget
            + self.state_full
            + self.divert_failed
    }

    /// Anything that arrived on the return veth and was refused. Not a fault on
    /// its own - the gate is meant to refuse everything that is not an answer -
    /// but a number that keeps climbing while nothing is being returned is worth
    /// looking at.
    pub fn refusals(&self) -> u64 {
        self.ptb_rejected + self.ptb_expired + self.ptb_no_mac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MtuChamberWiring {
        let mut sources = [[0u8; 16]; MTU_CHAMBER_MAX_SOURCES];
        sources[0] = [0xfd, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        sources[1] = [0x24, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        MtuChamberWiring {
            veth_ifindex: 37,
            source_count: 2,
            ttl_ms: 2000,
            burst: 8,
            nexthop: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            sources,
        }
    }

    #[test]
    fn the_encoding_is_the_c_layout() {
        // The layout is not a detail of this crate: it is what the datapath reads.
        // u32 enabled, u32 ifindex, u32 source_count, u32 ttl, u32 burst, u32
        // reserved, 16-byte nexthop, then four 16-byte sources.
        let encoded = sample().encode();
        assert_eq!(encoded.len(), MTU_CHAMBER_CFG_SIZE);
        assert_eq!(u32::from_ne_bytes(encoded[0..4].try_into().unwrap()), 1);
        assert_eq!(u32::from_ne_bytes(encoded[4..8].try_into().unwrap()), 37);
        assert_eq!(u32::from_ne_bytes(encoded[8..12].try_into().unwrap()), 2);
        assert_eq!(u32::from_ne_bytes(encoded[12..16].try_into().unwrap()), 2000);
        assert_eq!(u32::from_ne_bytes(encoded[16..20].try_into().unwrap()), 8);
        assert_eq!(encoded[24..40], sample().nexthop);
        assert_eq!(encoded[40..56], sample().sources[0]);
        assert_eq!(encoded[56..72], sample().sources[1]);
    }

    #[test]
    fn a_round_trip_preserves_every_field() {
        assert_eq!(MtuChamberWiring::decode(&sample().encode()), Some(sample()));
    }

    #[test]
    fn a_zeroed_wiring_diverts_nothing() {
        assert!(!MtuChamberWiring::default().diverts());
        // The datapath's own test of this is the same one: no veth, or no budget,
        // or no lifetime, or no address to speak with means it must not send the
        // packet anywhere.
        assert!(!MtuChamberWiring { veth_ifindex: 5, ..Default::default() }.diverts());
        assert!(
            !MtuChamberWiring {
                veth_ifindex: 5,
                burst: 8,
                ttl_ms: 2000,
                ..Default::default()
            }
            .diverts()
        );
        let full = MtuChamberWiring {
            veth_ifindex: 5,
            burst: 8,
            ttl_ms: 2000,
            source_count: 1,
            ..Default::default()
        };
        assert!(full.diverts());
    }

    #[test]
    fn a_truncated_value_is_rejected_rather_than_half_read() {
        assert_eq!(MtuChamberWiring::decode(&[0u8; MTU_CHAMBER_CFG_SIZE - 1]), None);
    }

    #[test]
    fn refusals_are_counted_apart_from_the_work() {
        let stats = MtuChamberStats {
            diverted: 10,
            ptb_returned: 9,
            skipped_npt: 2,
            ptb_rejected: 3,
            ..Default::default()
        };
        assert_eq!(stats.without_an_error(), 2);
        assert_eq!(stats.refusals(), 3);
        // A working chamber returned errors and has no unexplained drops.
        let working = MtuChamberStats { diverted: 1, ptb_returned: 1, ..Default::default() };
        assert_eq!(working.without_an_error(), 0);
    }
}
