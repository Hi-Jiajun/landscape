//! `firewall_block_ip4` / `firewall_block_ip6` LPM maps (C anchor:
//! `xdp_firewall.skel.rs`).

use zerocopy::{FromBytes, Immutable, IntoBytes};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Ipv4LpmKey {
    pub prefixlen: u32,
    pub addr: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Ipv6LpmKey {
    pub prefixlen: u32,
    pub addr: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct FirewallAction {
    pub mark: u32,
}

// ── Connection-tracking, fragment and rate-limit tables ──────────────────
//
// These are declared in `firewall/firewall_share.h` with
// `LIBBPF_PIN_BY_NAME`, so they are created once and shared by every program
// that uses them. Naming their types here (rather than only in the tests) is
// what lets `init_path` create them up front and detect a layout change
// instead of letting libbpf hit a stale pin and refuse to load at all.

/// `struct ct_tuple4`: the four-tuple of one IPv4 connection.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct CtTuple4 {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub protocol: u8,
    pub _pad: [u8; 3],
}

/// `struct ct_tuple6`. The addresses are held as raw bytes so the mirror is
/// byte-for-byte the C union.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct CtTuple6 {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub protocol: u8,
    pub _pad: [u8; 3],
}

/// `struct ct_entry`: the tracked state of one connection.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct CtEntry {
    pub last_seen_ns: u64,
    pub packets: u32,
    pub bytes: u32,
    pub state: u8,
    pub flags: u8,
    pub _pad: [u8; 6],
}

/// `struct ratelimit_key4`: one IPv4 source and one traffic class.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RatelimitKey4 {
    pub addr: u32,
    pub class: u32,
}

/// `struct ratelimit_key6`: one IPv6 source and one traffic class.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RatelimitKey6 {
    pub addr: [u8; 16],
    pub class: u32,
}

/// `struct ratelimit_entry`: one token bucket.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RatelimitEntry {
    pub last_time_ns: u64,
    pub tokens: u32,
    pub _pad: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stages::firewall::xdp_firewall_skel::types as share;

    #[test]
    fn firewall_layouts_match_skel() {
        assert_size!(Ipv4LpmKey, share::ipv4_lpm_key);
        assert_field!(Ipv4LpmKey, share::ipv4_lpm_key, prefixlen);
        assert_field!(Ipv4LpmKey, share::ipv4_lpm_key, addr);

        assert_size!(Ipv6LpmKey, share::ipv6_lpm_key);
        assert_field!(Ipv6LpmKey, share::ipv6_lpm_key, prefixlen);
        assert_field!(Ipv6LpmKey, share::ipv6_lpm_key, addr);

        assert_size!(FirewallAction, share::firewall_action);
        assert_field!(FirewallAction, share::firewall_action, mark);
    }

    /// The connection-tracking, fragment and rate-limit tables must match the C
    /// declarations field for field: a size or offset drift here is what makes a
    /// pinned map from an earlier build unusable and turns into a load failure.
    #[test]
    fn connection_tracking_layouts_match_skel() {
        assert_size!(CtTuple4, share::ct_tuple4);
        assert_field!(CtTuple4, share::ct_tuple4, src_ip);
        assert_field!(CtTuple4, share::ct_tuple4, dst_ip);
        assert_field!(CtTuple4, share::ct_tuple4, src_port);
        assert_field!(CtTuple4, share::ct_tuple4, dst_port);
        assert_field!(CtTuple4, share::ct_tuple4, protocol);

        assert_size!(CtTuple6, share::ct_tuple6);
        assert_field!(CtTuple6, share::ct_tuple6, src_ip);
        assert_field!(CtTuple6, share::ct_tuple6, dst_ip);
        assert_field!(CtTuple6, share::ct_tuple6, src_port);
        assert_field!(CtTuple6, share::ct_tuple6, dst_port);
        assert_field!(CtTuple6, share::ct_tuple6, protocol);

        assert_size!(CtEntry, share::ct_entry);
        assert_field!(CtEntry, share::ct_entry, last_seen_ns);
        assert_field!(CtEntry, share::ct_entry, packets);
        assert_field!(CtEntry, share::ct_entry, bytes);
        assert_field!(CtEntry, share::ct_entry, state);
        assert_field!(CtEntry, share::ct_entry, flags);

        assert_size!(RatelimitKey4, share::ratelimit_key4);
        assert_field!(RatelimitKey4, share::ratelimit_key4, addr);
        assert_field!(RatelimitKey4, share::ratelimit_key4, class);

        assert_size!(RatelimitKey6, share::ratelimit_key6);
        assert_field!(RatelimitKey6, share::ratelimit_key6, addr);
        assert_field!(RatelimitKey6, share::ratelimit_key6, class);

        assert_size!(RatelimitEntry, share::ratelimit_entry);
        assert_field!(RatelimitEntry, share::ratelimit_entry, last_time_ns);
        assert_field!(RatelimitEntry, share::ratelimit_entry, tokens);
    }
}
