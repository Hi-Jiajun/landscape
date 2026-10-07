//! The IPv6 Packet Too Big chamber's maps (`mtu_guard/mtu_chamber.h`).
//!
//! Four maps, each with one job:
//!
//! * `mtu_chamber_cfg_map` - the chamber's shape (target veth, the address it
//!   speaks with, admission lifetime and budget). Written once the chamber is
//!   fully up, zeroed the moment it is not, so a half-configured chamber cannot
//!   divert anything;
//! * `mtu_chamber_state_map` - one entry per admitted packet, matched by the
//!   quoted packet in the error that answers it. Consumed by the reply, which is
//!   what makes "one admission, at most one error" true;
//! * `mtu_chamber_budget_map` - how many admissions each source has used this
//!   second, so the kernel's error generator cannot be turned into a workload;
//! * `mtu_chamber_stats_map` - what happened, by reason.

mod config;
mod state;

pub use config::*;
pub use state::*;
