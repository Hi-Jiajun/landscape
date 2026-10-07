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
    /// The IPv4 half. IPv4 has no address set the way IPv6 does: the client has
    /// one address, so the error's source is the LAN interface's own and the
    /// count is what the return gate checks against.
    pub nexthop4: [u8; 4],
    pub sources4: [[u8; 4]; MTU_CHAMBER_MAX_SOURCES],
    pub source_count4: u32,
}

/// Bytes of `struct mtu_chamber_config`: `enabled`, `veth_ifindex`,
/// `source_count`, `ttl_ms`, `burst`, four bytes of padding, the IPv6 nexthop and
/// address set, then the IPv4 nexthop, address set and count.
pub const MTU_CHAMBER_CFG_SIZE: usize =
    24 + 16 + 16 * MTU_CHAMBER_MAX_SOURCES + 4 + 4 * MTU_CHAMBER_MAX_SOURCES + 8;

impl MtuChamberWiring {
    /// Whether this wiring asks the datapath to divert anything.
    ///
    /// A zeroed wiring is the "count only" state, which is both the default and
    /// what a chamber that failed to come up is reset to.
    pub fn diverts(&self) -> bool {
        self.veth_ifindex != 0 && self.burst != 0 && self.ttl_ms != 0
    }

    /// Whether the chamber can answer an IPv6 error for this LAN.
    pub fn diverts_v6(&self) -> bool {
        self.diverts() && self.source_count != 0
    }

    /// Whether it can answer an IPv4 one.
    pub fn diverts_v4(&self) -> bool {
        self.diverts() && self.source_count4 != 0
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
        out.extend_from_slice(&self.nexthop4);
        for source in &self.sources4 {
            out.extend_from_slice(source);
        }
        out.extend_from_slice(&self.source_count4.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
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
        let mut nexthop4 = [0u8; 4];
        nexthop4.copy_from_slice(&raw[104..108]);
        let mut sources4 = [[0u8; 4]; MTU_CHAMBER_MAX_SOURCES];
        for (i, source) in sources4.iter_mut().enumerate() {
            let at = 108 + i * 4;
            source.copy_from_slice(&raw[at..at + 4]);
        }
        Some(Self {
            veth_ifindex: u32_at(4),
            source_count: u32_at(8),
            ttl_ms: u32_at(12),
            burst: u32_at(16),
            nexthop,
            sources,
            nexthop4,
            sources4,
            source_count4: u32_at(124),
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
    /// An over-MTU IPv4 packet with DF set was handed to the chamber.
    pub diverted_v4: u64,
    /// A validated ICMPv4 fragmentation-needed went back to the client.
    pub frag_needed_returned: u64,
    /// An ICMPv4 error arrived on the return link and was refused, for any
    /// reason. Counted apart from the IPv6 refusals so a family that stopped
    /// working cannot hide behind the other's healthy number.
    pub frag_needed_rejected: u64,
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
        self.ptb_rejected + self.ptb_expired + self.ptb_no_mac + self.frag_needed_rejected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MtuChamberWiring {
        let mut sources = [[0u8; 16]; MTU_CHAMBER_MAX_SOURCES];
        sources[0] = [0xfd, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        sources[1] = [0x24, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut sources4 = [[0u8; 4]; MTU_CHAMBER_MAX_SOURCES];
        sources4[0] = [192, 168, 1, 1];
        MtuChamberWiring {
            veth_ifindex: 37,
            source_count: 2,
            ttl_ms: 2000,
            burst: 8,
            nexthop: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            sources,
            nexthop4: [192, 168, 1, 2],
            sources4,
            source_count4: 1,
        }
    }

    #[test]
    fn the_encoding_is_the_c_layout() {
        // The layout is not a detail of this crate: it is what the datapath reads.
        // u32 enabled, u32 ifindex, u32 source_count, u32 ttl, u32 burst, u32
        // reserved, 16-byte nexthop, four 16-byte sources, the IPv4 nexthop, four
        // 4-byte sources, the IPv4 count and four bytes of padding.
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
        assert_eq!(encoded[104..108], sample().nexthop4);
        assert_eq!(encoded[108..112], sample().sources4[0]);
        assert_eq!(u32::from_ne_bytes(encoded[124..128].try_into().unwrap()), 1);
    }

    #[test]
    fn a_round_trip_preserves_every_field() {
        assert_eq!(MtuChamberWiring::decode(&sample().encode()), Some(sample()));
    }

    #[test]
    fn a_zeroed_wiring_diverts_nothing() {
        assert!(!MtuChamberWiring::default().diverts());
        // `diverts` is "the chamber is on at all": no veth, or no budget, or no
        // lifetime means it must not send a packet anywhere. Whether it can serve
        // a particular family is the separate question below, because the two
        // have different address requirements.
        assert!(!MtuChamberWiring { veth_ifindex: 5, ..Default::default() }.diverts());
        assert!(
            !MtuChamberWiring { veth_ifindex: 5, burst: 8, ..Default::default() }.diverts(),
            "no lifetime means no admission can be valid"
        );
        let full = MtuChamberWiring {
            veth_ifindex: 5,
            burst: 8,
            ttl_ms: 2000,
            ..Default::default()
        };
        assert!(full.diverts(), "the chamber is on");
        // ... but it serves no family until it has an address for it, which is
        // what stops the datapath diverting into a gate that must refuse.
        assert!(!full.diverts_v6());
        assert!(!full.diverts_v4());
    }

    /// The two families are switched on by their own address list: a LAN with no
    /// IPv6 must not have the datapath divert a v6 packet whose error the gate
    /// would then have to refuse, and the same the other way round.
    #[test]
    fn each_family_needs_an_address_of_its_own_to_be_served() {
        let v6_only = MtuChamberWiring {
            veth_ifindex: 5,
            burst: 8,
            ttl_ms: 2000,
            source_count: 2,
            ..Default::default()
        };
        assert!(v6_only.diverts_v6());
        assert!(!v6_only.diverts_v4(), "no IPv4 address means no IPv4 error can be spoken");

        let v4_only = MtuChamberWiring {
            veth_ifindex: 5,
            burst: 8,
            ttl_ms: 2000,
            source_count4: 1,
            ..Default::default()
        };
        assert!(v4_only.diverts_v4());
        assert!(!v4_only.diverts_v6());
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
