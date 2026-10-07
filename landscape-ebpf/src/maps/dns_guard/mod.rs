//! Managed-DNS guard maps (`dns_guard/*` in `src/bpf/dns_guard/dns_guard.h`).
//!
//! These are what let the TC datapath decide, and what netfilter then rules on:
//! the config switch, the DoH address sets, the trust list, and the counters.

mod init;
mod setting;
pub(crate) mod types;

pub use init::*;
pub use setting::*;
