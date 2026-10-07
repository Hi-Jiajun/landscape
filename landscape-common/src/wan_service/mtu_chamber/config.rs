//! What the operator configures.

use serde::{Deserialize, Serialize};

/// The chamber's settings, carried by the service that owns the WAN interface
/// it guards.
///
/// `None` in that service's config means no chamber: the egress MTU stage still
/// counts what the egress cannot carry, and nothing is diverted. That is the
/// default, and it is also what every existing installation has, because the
/// field is optional and defaults to absent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MtuChamberSettings {
    /// Which interfaces the chamber may speak as. It copies their IPv6
    /// addresses, because the error it produces has to come from the address the
    /// client already treats as its gateway: the kernel picks per RFC 6724 from
    /// the addresses on the link it sends from, so giving the chamber the same
    /// set reproduces the choice a real router would make. Measured on
    /// 2026-10-07: with the veth's own address instead, the client gets no
    /// usable error at all.
    pub lan_iface_names: Vec<String>,
    /// How long an admitted packet may wait for its error, in milliseconds.
    /// Bounded on purpose: an admission that is never answered must not linger.
    #[serde(default = "default_ttl_ms")]
    pub ttl_ms: u32,
    /// How many admissions one source gets per second. The kernel's own ICMPv6
    /// error rate limit is about one per second globally, so this bounds how many
    /// a single client can compete for.
    #[serde(default = "default_burst")]
    pub burst: u32,
}

impl Default for MtuChamberSettings {
    fn default() -> Self {
        Self {
            lan_iface_names: Vec::new(),
            ttl_ms: default_ttl_ms(),
            burst: default_burst(),
        }
    }
}

impl MtuChamberSettings {
    /// Refuse settings that could not work, rather than starting a chamber that
    /// diverts into nothing.
    pub fn validate(&self) -> Result<(), String> {
        if self.lan_iface_names.is_empty() {
            return Err("at least one LAN interface name is required: the chamber must speak \
                 with the addresses a client treats as its gateway"
                .to_string());
        }
        if self.ttl_ms == 0 || self.ttl_ms > 60_000 {
            return Err(format!("ttl_ms ({}) must be between 1 and 60000", self.ttl_ms));
        }
        if self.burst == 0 || self.burst > 1000 {
            return Err(format!("burst ({}) must be between 1 and 1000", self.burst));
        }
        Ok(())
    }
}

const fn default_ttl_ms() -> u32 {
    2000
}

const fn default_burst() -> u32 {
    8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_ask_only_for_what_cannot_be_defaulted() {
        let defaults = MtuChamberSettings::default();
        assert_eq!(defaults.ttl_ms, 2000);
        assert_eq!(defaults.burst, 8);
        // No LAN interface means no chamber, and that is the one thing the
        // operator has to say before it can work.
        assert!(defaults.validate().is_err());
    }

    #[test]
    fn settings_that_could_not_work_are_refused_rather_than_started() {
        let ok = MtuChamberSettings {
            lan_iface_names: vec!["lan".to_string()],
            ..Default::default()
        };
        assert!(ok.validate().is_ok());

        let lan = || vec!["lan".to_string()];
        for bad in [
            MtuChamberSettings {
                lan_iface_names: lan(),
                ttl_ms: 0,
                ..Default::default()
            },
            MtuChamberSettings {
                lan_iface_names: lan(),
                ttl_ms: 60_001,
                ..Default::default()
            },
            MtuChamberSettings {
                lan_iface_names: lan(),
                burst: 0,
                ..Default::default()
            },
            MtuChamberSettings {
                lan_iface_names: lan(),
                burst: 1001,
                ..Default::default()
            },
            MtuChamberSettings { ttl_ms: 2000, burst: 8, ..Default::default() },
        ] {
            assert!(bad.validate().is_err(), "{bad:?} should be refused");
        }
    }
}
