use serde::{Deserialize, Serialize};

use crate::config_service::iface::{ServiceKind, ZoneAwareConfig, ZoneRequirement};
use crate::database::repository::LandscapeDBStore;
use crate::service::ServiceConfigError;
use crate::service::manager::ServiceKeyProvider;
use crate::utils::time::get_f64_timestamp;
use crate::wan_service::mtu_chamber::MtuChamberSettings;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MSSClampServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    #[serde(default = "default_clamp_size")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub clamp_size: u16,
    /// The IPv6 Packet Too Big chamber for this WAN interface, or `None` for no
    /// chamber.
    ///
    /// The two mechanisms answer the same question, which is what an egress
    /// cannot carry, and the clamp is what makes the chamber unnecessary for TCP,
    /// so they share the lifecycle of the interface they belong to. The stage
    /// that counts what the egress cannot carry is attached either way; this only
    /// decides whether the IPv6 case is given an error.
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = true))]
    pub mtu_chamber: Option<MtuChamberSettings>,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl ServiceKeyProvider for MSSClampServiceConfig {
    fn service_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for MSSClampServiceConfig {
    fn get_id(&self) -> String {
        self.iface_name.clone()
    }
    fn get_update_at(&self) -> f64 {
        self.update_at
    }
    fn set_update_at(&mut self, ts: f64) {
        self.update_at = ts;
    }
}

impl ZoneAwareConfig for MSSClampServiceConfig {
    fn iface_name(&self) -> &str {
        &self.iface_name
    }
    fn zone_requirement() -> ZoneRequirement {
        ZoneRequirement::WanOrPpp
    }
    fn service_kind() -> ServiceKind {
        ServiceKind::MssClamp
    }
}

impl crate::database::validator::ValidatableConfig for MSSClampServiceConfig {
    fn validate(&self) -> Result<(), ServiceConfigError> {
        if self.clamp_size < 536 || self.clamp_size > 1500 {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!("clamp_size ({}) must be between 536 and 1500", self.clamp_size),
            });
        }
        if let Some(chamber) = &self.mtu_chamber {
            chamber.validate().map_err(|reason| ServiceConfigError::InvalidConfig {
                reason: format!("mtu_chamber: {reason}"),
            })?;
        }
        Ok(())
    }
}

const fn default_clamp_size() -> u16 {
    1492
}
