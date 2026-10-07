//! Mirror structs for `dns_guard/dns_guard.h` (C anchors: the `SEC(".maps")`
//! definitions in that header).
//!
//! Layouts are pinned by the tests at the bottom: a C-side field or size drift
//! must fail `cargo test` rather than silently corrupt the maps at runtime.

use zerocopy::{FromBytes, Immutable, IntoBytes};

/// `struct dns_guard_config`: `enabled`, `drop_fragments`, `drop_unclassified`,
/// one byte of explicit padding, then a `u32` generation.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct DnsGuardConfig {
    pub enabled: u8,
    pub plaintext_tcp: u8,
    pub drop_fragments: u8,
    pub drop_unclassified: u8,
    pub generation: u32,
}

/// `struct dns_guard_exempt_key`: one trusted client plus one authorised
/// destination service.
///
/// Both addresses are held in 16-byte unions so a single map serves both
/// families; the unused tail of an IPv4 entry is left zeroed on both the C and
/// the Rust side, which is what makes the two byte strings equal.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct DnsGuardExemptKey {
    pub family: u8,
    pub l4_protocol: u8,
    /// Network byte order, so both sides can keep it as raw bytes.
    pub dport: [u8; 2],
    pub _pad: [u8; 4],
    pub src: [u8; 16],
    pub dst: [u8; 16],
}

#[cfg(test)]
mod tests {
    use super::*;

    // The guard's maps are declared in `dns_guard/dns_guard.h`, which the LAN
    // ingress program includes, so its skeleton is the C anchor to compare with.
    pub(crate) mod tc_lan_ingress_intro {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_lan_ingress_intro.skel.rs"));
    }

    use tc_lan_ingress_intro::types as share;

    #[test]
    fn dns_guard_layouts_match_skel() {
        assert_size!(DnsGuardConfig, share::dns_guard_config);
        assert_field!(DnsGuardConfig, share::dns_guard_config, enabled);
        assert_field!(DnsGuardConfig, share::dns_guard_config, plaintext_tcp);
        assert_field!(DnsGuardConfig, share::dns_guard_config, drop_fragments);
        assert_field!(DnsGuardConfig, share::dns_guard_config, drop_unclassified);
        assert_field!(DnsGuardConfig, share::dns_guard_config, generation);

        assert_size!(DnsGuardExemptKey, share::dns_guard_exempt_key);
        assert_field!(DnsGuardExemptKey, share::dns_guard_exempt_key, family);
        assert_field!(DnsGuardExemptKey, share::dns_guard_exempt_key, l4_protocol);
        assert_field!(DnsGuardExemptKey, share::dns_guard_exempt_key, dport);
        assert_field!(DnsGuardExemptKey, share::dns_guard_exempt_key, src);
        assert_field!(DnsGuardExemptKey, share::dns_guard_exempt_key, dst);
    }
}
