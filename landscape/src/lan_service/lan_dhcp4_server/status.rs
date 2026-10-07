use std::{collections::HashMap, net::Ipv4Addr, time::Instant};

use cidr::Ipv4Inet;
use landscape_common::{
    config_service::enrolled_device::EnrolledDevice,
    lan_service::lan_dhcpv4::config::{CustomDhcpOption, DHCPv4ServerConfig},
    net::MacAddr,
    utils::time::get_f64_timestamp,
};
use uuid::Uuid;

const OFFER_VALID_TIME: u32 = 20;
/// How long an address a client reported as conflicted stays out of circulation.
const DECLINE_HOLD_DOWN_SECS: u64 = 600;

#[derive(Debug)]
pub struct DHCPv4ServerOfferedCache {
    pub hostname: Option<String>,
    pub ip: Ipv4Addr,
    pub relative_offer_time: u64,
    pub valid_time: u32,
    pub is_static: bool,
    pub prev_ip: Option<Ipv4Addr>,
}

impl DHCPv4ServerOfferedCache {
    fn get_expire_time(&self) -> u64 {
        self.relative_offer_time + self.valid_time as u64
    }
}

#[derive(Debug, Clone, Default)]
pub struct PerMacDhcpOptions {
    pub custom_options: Vec<CustomDhcpOption>,
    pub filter_options: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAllocSource {
    Static(MacAddr),
    /// A dynamic lease, with the client it belongs to.
    ///
    /// The owner is carried because every operation here is keyed by address and
    /// has to answer "whose is this?": without it, releasing, renewing and
    /// expiring all have to guess, and each guess is a way for two clients to end
    /// up holding one address. Measured on the real LAN on 2026-10-08: a client
    /// released an address it did not hold, which freed the record of the client
    /// that did, and the address was handed to a third.
    Dynamic(MacAddr),
    /// Quarantined after a client reported the address in use by somebody else.
    Declined(Instant),
}

impl IpAllocSource {
    /// The client this record belongs to, if it belongs to one.
    fn owner(&self) -> Option<MacAddr> {
        match self {
            IpAllocSource::Static(mac) | IpAllocSource::Dynamic(mac) => Some(*mac),
            IpAllocSource::Declined(_) => None,
        }
    }

    /// Whether `mac` is the client this record belongs to.
    fn belongs_to(&self, mac: &MacAddr) -> bool {
        self.owner().is_some_and(|owner| owner == *mac)
    }
}

#[derive(Debug, Clone)]
pub struct StaticBindingEntry {
    pub ipv4: Ipv4Addr,
    pub custom_options: Vec<CustomDhcpOption>,
    pub filter_options: Vec<u8>,
    pub device_id: Option<Uuid>,
    pub hostname: Option<String>,
}

impl StaticBindingEntry {
    pub fn from_enrolled(device: &EnrolledDevice) -> Option<Self> {
        Some(Self {
            ipv4: device.ipv4?,
            custom_options: device.dhcp_custom_options.clone(),
            filter_options: device.dhcp_filter_options.clone(),
            device_id: Some(device.id),
            hostname: device.hostname.clone(),
        })
    }
}

#[derive(Debug)]
pub struct DhcpV4AssignStatus {
    pub ip_range_start: Ipv4Inet,
    pub range_capacity: u32,
    pub boot_time: f64,
    pub relative_boot_time: Instant,
    pub static_bindings: HashMap<MacAddr, StaticBindingEntry>,
    pub ip_owner: HashMap<Ipv4Addr, MacAddr>,
    pub per_mac_options: HashMap<MacAddr, PerMacDhcpOptions>,
    pub allocated_host: HashMap<Ipv4Addr, IpAllocSource>,
    pub offered_ip: HashMap<MacAddr, DHCPv4ServerOfferedCache>,
}

impl DhcpV4AssignStatus {
    pub fn from_config_and_devices(
        config: &DHCPv4ServerConfig,
        enrolled_devices: Vec<EnrolledDevice>,
    ) -> Self {
        let ip_range_start = Ipv4Inet::new(config.ip_range_start, config.network_mask)
            .unwrap_or_else(|_| {
                Ipv4Inet::new(config.ip_range_start, 24)
                    .unwrap_or_else(|_| Ipv4Inet::new_host(config.ip_range_start))
            });
        let ip_addr_end = match config.ip_range_end {
            Some(addr) if addr != Ipv4Addr::UNSPECIFIED => addr,
            _ => ip_range_start.last_address(),
        };
        let range_capacity =
            u32::from(ip_addr_end).saturating_sub(u32::from(config.ip_range_start));

        let mut status = DhcpV4AssignStatus {
            ip_range_start,
            range_capacity,
            boot_time: get_f64_timestamp(),
            relative_boot_time: Instant::now(),
            static_bindings: HashMap::new(),
            ip_owner: HashMap::new(),
            per_mac_options: HashMap::new(),
            allocated_host: HashMap::new(),
            offered_ip: HashMap::new(),
        };

        for device in enrolled_devices {
            if let Some(ipv4) = device.ipv4 {
                if let Some(old_ip) = status
                    .static_bindings
                    .insert(
                        device.mac,
                        StaticBindingEntry {
                            ipv4,
                            custom_options: device.dhcp_custom_options.clone(),
                            filter_options: device.dhcp_filter_options.clone(),
                            device_id: Some(device.id),
                            hostname: device.hostname.clone(),
                        },
                    )
                    .map(|e| e.ipv4)
                {
                    status.allocated_host.remove(&old_ip);
                    status.ip_owner.remove(&old_ip);
                }
                if let Some(old_mac) = status.ip_owner.insert(ipv4, device.mac)
                    && old_mac != device.mac
                {
                    status.static_bindings.remove(&old_mac);
                    status.offered_ip.remove(&old_mac);
                }
                status.allocated_host.insert(ipv4, IpAllocSource::Static(device.mac));
                status.offered_ip.insert(
                    device.mac,
                    DHCPv4ServerOfferedCache {
                        hostname: device.hostname.clone(),
                        ip: ipv4,
                        relative_offer_time: 0,
                        valid_time: 86400,
                        is_static: true,
                        prev_ip: None,
                    },
                );
            }

            if !device.dhcp_custom_options.is_empty() || !device.dhcp_filter_options.is_empty() {
                status.per_mac_options.insert(
                    device.mac,
                    PerMacDhcpOptions {
                        custom_options: device.dhcp_custom_options,
                        filter_options: device.dhcp_filter_options,
                    },
                );
            }
        }

        status
    }

    pub fn add_or_update_binding(&mut self, mac: MacAddr, entry: StaticBindingEntry) {
        let ip = entry.ipv4;

        let kicked = if matches!(self.allocated_host.get(&ip), Some(IpAllocSource::Dynamic(_))) {
            self.find_dynamic_owner_of_ip(ip).map(|z_mac| {
                let hostname = self.offered_ip.get(&z_mac).and_then(|c| c.hostname.clone());
                self.offered_ip.remove(&z_mac);
                (z_mac, hostname)
            })
        } else {
            None
        };

        if let Some(old_entry) = self.static_bindings.remove(&mac) {
            self.ip_owner.remove(&old_entry.ipv4);
            if let Some(IpAllocSource::Static(m)) = self.allocated_host.get(&old_entry.ipv4)
                && *m == mac
            {
                self.allocated_host.remove(&old_entry.ipv4);
            }
            self.offered_ip.remove(&mac);
            self.per_mac_options.remove(&mac);
        }

        if let Some(old_mac) = self.ip_owner.insert(ip, mac)
            && old_mac != mac
        {
            self.static_bindings.remove(&old_mac);
            self.offered_ip.remove(&old_mac);
            self.per_mac_options.remove(&old_mac);
        }

        self.static_bindings.insert(mac, entry.clone());
        self.allocated_host.insert(ip, IpAllocSource::Static(mac));
        self.offered_ip.insert(
            mac,
            DHCPv4ServerOfferedCache {
                hostname: entry.hostname.clone(),
                ip,
                relative_offer_time: self.relative_boot_time.elapsed().as_secs(),
                valid_time: 86400,
                is_static: true,
                prev_ip: None,
            },
        );
        if !entry.custom_options.is_empty() || !entry.filter_options.is_empty() {
            self.per_mac_options.insert(
                mac,
                PerMacDhcpOptions {
                    custom_options: entry.custom_options,
                    filter_options: entry.filter_options,
                },
            );
        }

        if let Some((z_mac, hostname)) = kicked {
            self.offer_ip(&z_mac, hostname);
            if let Some(cache) = self.offered_ip.get_mut(&z_mac) {
                cache.prev_ip = Some(ip);
            }
        }
    }

    pub fn remove_binding(&mut self, mac: &MacAddr) {
        let Some(entry) = self.static_bindings.remove(mac) else {
            return;
        };
        let ip = entry.ipv4;

        self.ip_owner.remove(&ip);
        self.offered_ip.remove(mac);
        self.per_mac_options.remove(mac);

        if let Some(IpAllocSource::Static(m)) = self.allocated_host.get(&ip)
            && *m == *mac
        {
            let has_dynamic = self.offered_ip.values().any(|c| c.ip == ip && !c.is_static);
            if !has_dynamic {
                self.allocated_host.remove(&ip);
            }
        }
    }

    /// The client a dynamic lease belongs to.
    ///
    /// Read from the allocation table rather than by scanning the offer caches:
    /// the table is the authority on ownership, and a cache can be stale - which
    /// is exactly the state that produced the duplicate address.
    fn find_dynamic_owner_of_ip(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        match self.allocated_host.get(&ip) {
            Some(IpAllocSource::Dynamic(mac)) => Some(*mac),
            _ => None,
        }
    }

    pub fn offer_ip(&mut self, mac_addr: &MacAddr, hostname: Option<String>) -> Option<Ipv4Addr> {
        if let Some(entry) = self.static_bindings.get(mac_addr) {
            let ip = entry.ipv4;
            let hostname = hostname.or_else(|| entry.hostname.clone());
            if let Some(old) = self.offered_ip.get(mac_addr)
                && old.ip != ip
            {
                self.allocated_host.remove(&old.ip);
            }
            self.offered_ip.insert(
                *mac_addr,
                DHCPv4ServerOfferedCache {
                    hostname,
                    ip,
                    relative_offer_time: self.relative_boot_time.elapsed().as_secs(),
                    valid_time: OFFER_VALID_TIME,
                    is_static: true,
                    prev_ip: None,
                },
            );
            self.allocated_host.insert(ip, IpAllocSource::Static(*mac_addr));
            return Some(ip);
        }

        // A cached offer is only good while the address is still this client's.
        // After the table has been rebuilt - a service restart empties it - or
        // after the address has been given to somebody else, the cache is a stale
        // claim, and serving it would offer an address that is in use. Dropping it
        // is what lets the allocation below pick a free one instead.
        if let Some(cache) = self.offered_ip.get(mac_addr) {
            let ip = cache.ip;
            if self.allocated_host.get(&ip).is_some_and(|source| source.belongs_to(mac_addr)) {
                return Some(ip);
            }
            tracing::warn!(
                "dropping a stale offer for {mac_addr:?}: {ip} is not allocated to it any more"
            );
            self.offered_ip.remove(mac_addr);
        }

        if self.range_capacity == 0 {
            return None;
        }

        let mut seed = mac_addr.u32_ckecksum();
        let mut loop_count = 0u32;
        loop {
            if (self.allocated_host.len() as u32 >= self.range_capacity
                || loop_count >= self.range_capacity)
                && self.clean_expire_ip().is_empty()
            {
                break;
            }
            loop_count += 1;
            let index = seed % self.range_capacity;
            let (client_addr, _overflow) = self.ip_range_start.overflowing_add_u32(index);
            let address = client_addr.address();
            if self.allocated_host.contains_key(&address) {
                seed += 1;
            } else {
                self.offered_ip.insert(
                    *mac_addr,
                    DHCPv4ServerOfferedCache {
                        hostname,
                        ip: address,
                        relative_offer_time: self.relative_boot_time.elapsed().as_secs(),
                        valid_time: OFFER_VALID_TIME,
                        is_static: false,
                        prev_ip: None,
                    },
                );
                self.allocated_host.insert(address, IpAllocSource::Dynamic(*mac_addr));
                return Some(address);
            }
        }
        None
    }

    pub fn ack_request(
        &mut self,
        mac_addr: &MacAddr,
        ip_addr: Ipv4Addr,
        hostname: Option<String>,
        address_lease_time: u32,
    ) -> bool {
        if self.conflicts_with_static_binding(mac_addr, ip_addr) {
            return false;
        }

        // Whose address is this? Asked before anything is confirmed, because a
        // client whose cache still names an address that now belongs to somebody
        // else would otherwise keep renewing it for ever: every ACK refreshes the
        // cache, so the entry never expires and the duplicate is permanent.
        // Measured on the real LAN: hours of client retries against the conflicting
        // address, and the conflict never cleared by itself.
        let owned_by_caller =
            self.allocated_host.get(&ip_addr).is_some_and(|source| source.belongs_to(mac_addr));
        let mut stale_offer = false;

        if let Some(offered_cache) = self.offered_ip.get_mut(mac_addr) {
            if offered_cache.ip == ip_addr {
                if owned_by_caller {
                    offered_cache.hostname = hostname;
                    if !offered_cache.is_static {
                        offered_cache.valid_time = address_lease_time;
                    }
                    offered_cache.relative_offer_time = self.relative_boot_time.elapsed().as_secs();
                    return true;
                }
                // A stale claim: refuse it, and drop the cache below so this
                // client's next request is answered with a free address.
                stale_offer = true;
            } else {
                tracing::error!(
                    "client: {mac_addr:?} request ip: {ip_addr:?}, not same as offer: {:?}",
                    offered_cache.ip
                )
            }
        } else {
            // No cache for this client. Two cases arrive here: a renewal after the
            // table was rebuilt - the client still holds the lease but the server
            // has no record of it - and a request for an address it was never
            // offered. The first is legitimate; the second is refused unless the
            // record already names this client.
            if self.allocated_host.contains_key(&ip_addr) && !owned_by_caller {
                tracing::error!(
                    "Requested IP {ip_addr:?} is already allocated to another client, request by {mac_addr:?}"
                );
                return false;
            }

            if !self.is_ip_in_range(ip_addr) {
                tracing::warn!("Requested IP out of range");
                return false;
            }

            let lease_cache = DHCPv4ServerOfferedCache {
                hostname,
                ip: ip_addr,
                is_static: false,
                valid_time: address_lease_time,
                relative_offer_time: self.relative_boot_time.elapsed().as_secs(),
                prev_ip: None,
            };

            self.offered_ip.insert(*mac_addr, lease_cache);
            self.allocated_host.insert(ip_addr, IpAllocSource::Dynamic(*mac_addr));

            tracing::info!("Assigned unoffered IP {ip_addr:?} to client {mac_addr:?}");
            return true;
        }

        if stale_offer {
            self.offered_ip.remove(mac_addr);
            tracing::warn!(
                "refusing a renewal of {ip_addr:?} by {mac_addr:?}: the address belongs to another client"
            );
        }
        false
    }

    pub fn clean_expire_ip(&mut self) -> Vec<(MacAddr, Ipv4Addr, Option<String>)> {
        let current_time = self.relative_boot_time.elapsed().as_secs();

        let mut expired: Vec<(MacAddr, Ipv4Addr, Option<String>)> = Vec::new();
        self.offered_ip.retain(|mac, value| {
            if value.is_static {
                true
            } else if current_time > value.get_expire_time() {
                expired.push((*mac, value.ip, value.hostname.clone()));
                false
            } else {
                true
            }
        });

        self.allocated_host.retain(|_key, source| match source {
            IpAllocSource::Declined(since) => since.elapsed().as_secs() < DECLINE_HOLD_DOWN_SECS,
            _ => true,
        });

        for (mac, ip, _) in &expired {
            // Only drop the record if it is still this client's. An entry can
            // expire after the address was re-assigned - a client that stopped
            // renewing leaves a record that looks free, and a rebuild-and-grant can
            // hand the address on before this sweep runs - and freeing somebody
            // else's address here is another way for two clients to end up holding
            // one address.
            if self.allocated_host.get(ip).is_some_and(|source| source.belongs_to(mac)) {
                self.allocated_host.remove(ip);
            }
        }

        if !expired.is_empty() {
            let ips: Vec<_> = expired.iter().map(|(_, ip, _)| ip).collect();
            tracing::info!("DHCPv4 server cleans up these IPs: {ips:?}");
        }
        expired
    }

    /// Release an address on a client's behalf.
    ///
    /// Only the client the address is allocated to may release it. The address
    /// comes from the packet, so without that check any client can free another's
    /// record - and then be given that address while the original holder keeps
    /// using it. Measured on 2026-10-08: that is one of the two ways this LAN ended
    /// up with two clients on `192.168.1.147`.
    ///
    /// Returns whether the release happened; the caller only announces the expiry
    /// when it did.
    pub fn release_ip(&mut self, mac: &MacAddr, ip: Ipv4Addr) -> bool {
        if !self.allocated_host.get(&ip).is_some_and(|source| source.belongs_to(mac)) {
            tracing::warn!(
                "ignoring a release of {ip:?} by {mac:?}: the address is not allocated to it"
            );
            return false;
        }

        self.offered_ip.remove(mac);
        // A static binding keeps its claim: the address is reserved for that client
        // whether or not it currently holds a lease on it.
        if matches!(self.allocated_host.get(&ip), Some(IpAllocSource::Dynamic(_))) {
            self.allocated_host.remove(&ip);
        }
        true
    }

    pub fn conflicts_with_static_binding(&self, mac_addr: &MacAddr, ip_addr: Ipv4Addr) -> bool {
        if let Some(entry) = self.static_bindings.get(mac_addr)
            && entry.ipv4 != ip_addr
        {
            tracing::warn!(
                "client {:?} requested {:?}, but static binding requires {:?}",
                mac_addr,
                ip_addr,
                entry.ipv4
            );
            return true;
        }

        if let Some(static_mac) = self.ip_owner.get(&ip_addr)
            && static_mac != mac_addr
        {
            tracing::warn!(
                "client {:?} requested static IP {:?} owned by {:?}",
                mac_addr,
                ip_addr,
                static_mac
            );
            return true;
        }

        false
    }

    /// Record a DHCPDECLINE for `ip`.
    ///
    /// A DECLINE means the client found the address already in use by somebody
    /// else, so the address is quarantined: it is not handed out again for the
    /// hold-down period. The quarantine is the point - this is precisely the address
    /// that must stop circulating - so it is unconditional.
    ///
    /// An earlier version refused to quarantine an address that still looked owned,
    /// reasoning that a client must not be able to free an address that is in use.
    /// That was wrong here, and the measurement showed it: on 2026-10-08 this LAN
    /// logged twenty declines in half an hour and every one was ignored, while the
    /// conflicted address stayed in circulation and the client that reported the
    /// conflict had no way out of it.
    ///
    /// The caches naming the address are dropped with it, so a client whose offer
    /// points at it is given a different address next time instead of being offered
    /// the one it just rejected.
    pub fn add_decline_ip(&mut self, ip: Ipv4Addr) {
        self.allocated_host.insert(ip, IpAllocSource::Declined(Instant::now()));
        // Every dynamic cache that names the address, not just the reporter's: more
        // than one client can be holding an offer for it. A static cache is kept - a
        // static binding is the operator's own statement that this client holds this
        // address, and the static path in `offer_ip` re-asserts it anyway.
        self.offered_ip.retain(|_mac, cache| cache.is_static || cache.ip != ip);
        tracing::warn!(
            "quarantining {ip} after a DHCPDECLINE for {DECLINE_HOLD_DOWN_SECS}s; clients holding it are re-allocated"
        );
    }

    pub fn is_ip_in_range(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        let start = u32::from(self.ip_range_start.address());
        let end = start.saturating_add(self.range_capacity);
        ip_u32 >= start && ip_u32 < end
    }

    #[cfg(test)]
    pub fn init_for_test(config: DHCPv4ServerConfig) -> Self {
        Self::from_config_and_devices(&config, vec![])
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::{net::Ipv4Addr, thread::sleep, time::Duration};

    use landscape_common::{
        config_service::enrolled_device::EnrolledDevice,
        lan_service::lan_dhcpv4::config::{CustomDhcpOption, DHCPv4ServerConfig},
        net::MacAddr,
    };

    use super::*;

    fn make_mac(s: &str) -> MacAddr {
        MacAddr::from_str(s).unwrap()
    }

    fn default_config() -> DHCPv4ServerConfig {
        DHCPv4ServerConfig::default()
    }

    #[test]
    fn t1_from_config_and_devices_with_two_devices() {
        let config = default_config();
        let mac1 = make_mac("00:00:00:00:00:01");
        let mac2 = make_mac("00:00:00:00:00:02");
        let ip1 = Ipv4Addr::new(192, 168, 5, 10);
        let ip2 = Ipv4Addr::new(192, 168, 5, 20);

        let d1 = EnrolledDevice {
            mac: mac1,
            name: "d1".to_string(),
            ipv4: Some(ip1),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"d1"}))
                .unwrap()
        };
        let d2 = EnrolledDevice {
            mac: mac2,
            name: "d2".to_string(),
            ipv4: Some(ip2),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:02","name":"d2"}))
                .unwrap()
        };

        let status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d1, d2]);

        assert_eq!(status.static_bindings.len(), 2);
        assert_eq!(status.ip_owner.len(), 2);
        assert_eq!(status.offered_ip.len(), 2);
        assert_eq!(status.allocated_host.len(), 2);
        assert_eq!(status.static_bindings.get(&mac1).unwrap().ipv4, ip1);
        assert_eq!(status.static_bindings.get(&mac2).unwrap().ipv4, ip2);
        assert_eq!(status.offered_ip.values().filter(|c| c.is_static).count(), 2);
    }

    #[test]
    fn t2_offer_ip_first() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let mac = make_mac("00:00:00:00:00:01");
        let result = status.offer_ip(&mac, None);
        assert!(result.is_some());
        assert_eq!(status.offered_ip.len(), 1);
        assert_eq!(status.allocated_host.len(), 1);
    }

    #[test]
    fn t3_offer_ip_cache_hit() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let mac = make_mac("00:00:00:00:00:01");
        let first = status.offer_ip(&mac, None).unwrap();
        let second = status.offer_ip(&mac, None).unwrap();
        assert_eq!(first, second);
        assert_eq!(status.offered_ip.len(), 1);
    }

    #[test]
    fn t4_offer_until_full() {
        let mut config = default_config();
        config.ip_range_start = Ipv4Addr::new(192, 168, 5, 200);
        config.ip_range_end = Some(Ipv4Addr::new(192, 168, 5, 203));
        let mut status = DhcpV4AssignStatus::init_for_test(config);

        let mut ips: HashSet<Ipv4Addr> = HashSet::new();
        for i in 0..3 {
            let mac = MacAddr::from([0, 0, 0, 0, 0, i + 1]);
            let result = status.offer_ip(&mac, None);
            assert!(result.is_some(), "failed at device {}", i);
            ips.insert(result.unwrap());
        }
        assert_eq!(ips.len(), 3, "should get 3 unique IPs");
        let mac = MacAddr::from([0, 0, 0, 0, 0, 4]);
        assert!(status.offer_ip(&mac, None).is_none(), "4th should fail");
    }

    #[test]
    fn t5_clean_expire_preserves_static() {
        let config = default_config();
        let mac_static = make_mac("00:00:00:00:00:01");
        let static_ip = Ipv4Addr::new(192, 168, 5, 10);

        let d = EnrolledDevice {
            mac: mac_static,
            name: "s".to_string(),
            ipv4: Some(static_ip),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"s"}))
                .unwrap()
        };
        let mut status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d]);

        let mac_dyn = make_mac("00:00:00:00:00:02");
        let dyn_ip = status.offer_ip(&mac_dyn, None).unwrap();
        assert_ne!(dyn_ip, static_ip);

        sleep(Duration::from_secs(25));
        status.clean_expire_ip();

        assert!(
            status.offered_ip.contains_key(&mac_static),
            "static entry should survive clean_expire_ip"
        );
        assert!(
            !status.offered_ip.contains_key(&mac_dyn),
            "expired dynamic entry should be removed"
        );
        assert_eq!(status.allocated_host.get(&static_ip), Some(&IpAllocSource::Static(mac_static)));
    }

    #[test]
    fn t6_clean_expire_triggered_by_offer_when_full() {
        let mut config = default_config();
        config.ip_range_start = Ipv4Addr::new(192, 168, 5, 200);
        config.ip_range_end = Some(Ipv4Addr::new(192, 168, 5, 203));
        let mut status = DhcpV4AssignStatus::init_for_test(config);

        for i in 0..3 {
            let mac = MacAddr::from([0, 0, 0, 0, 0, i + 1]);
            let _ = status.offer_ip(&mac, None).unwrap();
        }

        sleep(Duration::from_secs(25));

        let mac4 = MacAddr::from([0, 0, 0, 0, 0, 4]);
        let result = status.offer_ip(&mac4, None);
        assert!(result.is_some(), "should allocate after cleanup via offer_ip");
    }

    #[test]
    fn t7_add_static_binding_no_conflict() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let mac = make_mac("00:00:00:00:00:01");
        let ip = Ipv4Addr::new(192, 168, 5, 10);

        status.add_or_update_binding(
            mac,
            StaticBindingEntry {
                ipv4: ip,
                custom_options: vec![],
                filter_options: vec![],
                device_id: None,
                hostname: None,
            },
        );

        let cache = status.offered_ip.get(&mac).unwrap();
        assert!(cache.is_static);
        assert_eq!(cache.ip, ip);
        assert_eq!(cache.prev_ip, None);
        assert_eq!(status.allocated_host.get(&ip), Some(&IpAllocSource::Static(mac)));
    }

    #[test]
    fn t8_kick_dynamic_when_static_claims_ip() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let mac_z = make_mac("00:00:00:00:00:01");
        let ip_y = status.offer_ip(&mac_z, Some("dyn-client".to_string())).unwrap();

        let mac_x = make_mac("00:00:00:00:00:02");
        status.add_or_update_binding(
            mac_x,
            StaticBindingEntry {
                ipv4: ip_y,
                custom_options: vec![],
                filter_options: vec![],
                device_id: None,
                hostname: None,
            },
        );

        let x_cache = status.offered_ip.get(&mac_x).unwrap();
        assert!(x_cache.is_static);
        assert_eq!(x_cache.ip, ip_y);

        let z_cache = status.offered_ip.get(&mac_z).unwrap();
        assert!(!z_cache.is_static);
        assert_ne!(z_cache.ip, ip_y);
        assert_eq!(z_cache.prev_ip, Some(ip_y));
    }

    #[test]
    fn t8a_kicked_client_offer_ip_returns_cached() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let mac_z = make_mac("00:00:00:00:00:01");
        let ip_y = status.offer_ip(&mac_z, Some("dyn".to_string())).unwrap();

        let mac_x = make_mac("00:00:00:00:00:02");
        status.add_or_update_binding(
            mac_x,
            StaticBindingEntry {
                ipv4: ip_y,
                custom_options: vec![],
                filter_options: vec![],
                device_id: None,
                hostname: None,
            },
        );

        let new_ip = status.offer_ip(&mac_z, None);
        assert!(new_ip.is_some());
        assert_ne!(new_ip.unwrap(), ip_y);
    }

    #[test]
    fn t8b_kicked_client_ack_request_new_ip() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let mac_z = make_mac("00:00:00:00:00:01");
        let ip_y = status.offer_ip(&mac_z, Some("dyn".to_string())).unwrap();

        let mac_x = make_mac("00:00:00:00:00:02");
        status.add_or_update_binding(
            mac_x,
            StaticBindingEntry {
                ipv4: ip_y,
                custom_options: vec![],
                filter_options: vec![],
                device_id: None,
                hostname: None,
            },
        );

        let new_ip = status.offer_ip(&mac_z, None).unwrap();
        let result = status.ack_request(&mac_z, new_ip, None, 86400);
        assert!(result);
    }

    #[test]
    fn t8c_kicked_client_ack_request_old_ip_fails() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let mac_z = make_mac("00:00:00:00:00:01");
        let ip_y = status.offer_ip(&mac_z, Some("dyn".to_string())).unwrap();

        let mac_x = make_mac("00:00:00:00:00:02");
        status.add_or_update_binding(
            mac_x,
            StaticBindingEntry {
                ipv4: ip_y,
                custom_options: vec![],
                filter_options: vec![],
                device_id: None,
                hostname: None,
            },
        );

        let result = status.ack_request(&mac_z, ip_y, None, 86400);
        assert!(!result);
    }

    #[test]
    fn t9_static_mac_ack_own_ip() {
        let config = default_config();
        let mac = make_mac("00:00:00:00:00:01");
        let ip = Ipv4Addr::new(192, 168, 5, 10);
        let d = EnrolledDevice {
            mac,
            name: "s".to_string(),
            ipv4: Some(ip),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"s"}))
                .unwrap()
        };
        let mut status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d]);
        assert!(status.ack_request(&mac, ip, None, 86400));
    }

    #[test]
    fn t10_static_mac_ack_other_ip_fails() {
        let config = default_config();
        let mac = make_mac("00:00:00:00:00:01");
        let ip = Ipv4Addr::new(192, 168, 5, 10);
        let other_ip = Ipv4Addr::new(192, 168, 5, 20);
        let d = EnrolledDevice {
            mac,
            name: "s".to_string(),
            ipv4: Some(ip),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"s"}))
                .unwrap()
        };
        let mut status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d]);
        assert!(!status.ack_request(&mac, other_ip, None, 86400));
    }

    #[test]
    fn t11_remove_static_binding_releases_ip() {
        let config = default_config();
        let mac = make_mac("00:00:00:00:00:01");
        let ip = Ipv4Addr::new(192, 168, 5, 10);
        let d = EnrolledDevice {
            mac,
            name: "s".to_string(),
            ipv4: Some(ip),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"s"}))
                .unwrap()
        };
        let mut status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d]);

        assert!(status.offered_ip.contains_key(&mac));
        assert!(status.allocated_host.contains_key(&ip));

        status.remove_binding(&mac);

        assert!(!status.offered_ip.contains_key(&mac));
        assert!(!status.allocated_host.contains_key(&ip));
        assert!(status.static_bindings.is_empty());
        assert!(status.ip_owner.is_empty());
    }

    #[test]
    fn t12_remove_static_binding_keeps_ah_if_dynamic_exists() {
        let config = default_config();
        let mac_static = make_mac("00:00:00:00:00:01");
        let static_ip = Ipv4Addr::new(192, 168, 5, 10);
        let d = EnrolledDevice {
            mac: mac_static,
            name: "s".to_string(),
            ipv4: Some(static_ip),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"s"}))
                .unwrap()
        };
        let mut status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d]);

        let mac_dyn = make_mac("00:00:00:00:00:02");
        let dyn_ip = status.offer_ip(&mac_dyn, None).unwrap();
        assert_ne!(dyn_ip, static_ip);

        status.remove_binding(&mac_static);

        assert!(!status.offered_ip.contains_key(&mac_static));
        assert!(!status.allocated_host.contains_key(&static_ip));
        assert!(status.allocated_host.contains_key(&dyn_ip));
        assert!(status.offered_ip.contains_key(&mac_dyn));
    }

    #[test]
    fn t13_update_binding_same_mac_different_ip() {
        let config = default_config();
        let mac = make_mac("00:00:00:00:00:01");
        let ip_old = Ipv4Addr::new(192, 168, 5, 10);
        let ip_new = Ipv4Addr::new(192, 168, 5, 20);
        let d = EnrolledDevice {
            mac,
            name: "s".to_string(),
            ipv4: Some(ip_old),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"s"}))
                .unwrap()
        };
        let mut status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d]);

        status.add_or_update_binding(
            mac,
            StaticBindingEntry {
                ipv4: ip_new,
                custom_options: vec![],
                filter_options: vec![],
                device_id: None,
                hostname: None,
            },
        );

        assert!(!status.allocated_host.contains_key(&ip_old));
        assert_eq!(status.allocated_host.get(&ip_new), Some(&IpAllocSource::Static(mac)));
        assert_eq!(status.offered_ip.get(&mac).unwrap().ip, ip_new);
        assert!(status.offered_ip.get(&mac).unwrap().is_static);
    }

    #[test]
    fn t14_update_binding_options_change() {
        let config = default_config();
        let mac = make_mac("00:00:00:00:00:01");
        let ip = Ipv4Addr::new(192, 168, 5, 10);
        let d = EnrolledDevice {
            mac,
            name: "s".to_string(),
            ipv4: Some(ip),
            dhcp_custom_options: vec![CustomDhcpOption::TFTPServerName("old".to_string())],
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"s"}))
                .unwrap()
        };
        let mut status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d]);

        let old_opts = status.per_mac_options.get(&mac).unwrap().custom_options.clone();
        assert_eq!(old_opts.len(), 1);

        status.add_or_update_binding(
            mac,
            StaticBindingEntry {
                ipv4: ip,
                custom_options: vec![CustomDhcpOption::BootfileName("new.kpxe".to_string())],
                filter_options: vec![15],
                device_id: None,
                hostname: None,
            },
        );

        let new_opts = status.per_mac_options.get(&mac).unwrap().custom_options.clone();
        assert_eq!(new_opts.len(), 1);
        assert!(matches!(new_opts[0], CustomDhcpOption::BootfileName(_)));
        assert_eq!(status.per_mac_options.get(&mac).unwrap().filter_options, vec![15]);
    }

    #[test]
    fn t15_static_entry_survives_clean_expire() {
        let config = default_config();
        let mac = make_mac("00:00:00:00:00:01");
        let ip = Ipv4Addr::new(192, 168, 5, 10);
        let d = EnrolledDevice {
            mac,
            name: "s".to_string(),
            ipv4: Some(ip),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"s"}))
                .unwrap()
        };
        let mut status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d]);

        sleep(Duration::from_secs(1));
        assert!(status.clean_expire_ip().is_empty(), "should report no cleanup needed");

        assert!(status.offered_ip.contains_key(&mac));
        assert!(status.allocated_host.contains_key(&ip));
    }

    /// One address, one client - the rule the allocator rests on, checked at the
    /// operation that broke it.
    ///
    /// The address in a DHCPRELEASE comes from the packet, so without an ownership
    /// check any client can free the record of the client that really holds it, and
    /// the next request for that address is then granted - while the original holder
    /// is still using it. Measured on 2026-10-08: that is one of the two ways this
    /// LAN ended up with two clients on `192.168.1.147`.
    #[test]
    fn t16_only_the_holder_may_release_an_address() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let holder = make_mac("00:e2:69:a3:e3:71");
        let other = make_mac("d0:f9:28:ff:fa:eb");
        let third = make_mac("aa:bb:cc:dd:ee:ff");

        let ip = status.offer_ip(&holder, None).expect("a free address exists");
        assert!(status.ack_request(&holder, ip, None, 3600), "the offer is confirmed");

        // `other` has an address of its own, and tries to release the one `holder`
        // is using.
        let other_ip = status.offer_ip(&other, None).expect("a second free address exists");
        assert_ne!(other_ip, ip, "the two clients were given different addresses");
        assert!(
            !status.release_ip(&other, ip),
            "a client must not be able to release an address it does not hold"
        );
        assert_eq!(
            status.allocated_host.get(&ip),
            Some(&IpAllocSource::Dynamic(holder)),
            "and the holder's record must be untouched by the attempt"
        );

        // Because it is still held, nobody else may be given it...
        assert!(
            !status.ack_request(&third, ip, None, 3600),
            "{third:?} must not be granted an address that is still in use"
        );
        // ...while the holder keeps its lease.
        assert!(status.ack_request(&holder, ip, None, 3600), "the holder renews as usual");
    }

    /// A renewal is refused once the address belongs to somebody else, and the
    /// stale offer is dropped so the client is re-allocated instead of being left
    /// trying.
    ///
    /// This is the half that made the conflict permanent on the real LAN: `ack_request`
    /// answered from the client's own cache without asking who owns the address, and
    /// every ACK refreshed that cache, so neither entry ever expired and both clients
    /// kept renewing one address for hours.
    #[test]
    fn t17_a_renewal_is_refused_once_the_address_belongs_to_another_client() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let first = make_mac("00:e2:69:a3:e3:71");
        let second = make_mac("d0:f9:28:ff:fa:eb");

        let ip = status.offer_ip(&first, None).expect("a free address exists");
        assert!(status.ack_request(&first, ip, None, 3600));

        // The state a service restart produces, then a grant: the table no longer
        // knows `first`, and the address has since been given to `second`.
        status.allocated_host.insert(ip, IpAllocSource::Dynamic(second));

        assert!(
            !status.ack_request(&first, ip, None, 3600),
            "{first:?} must not keep renewing an address that belongs to {second:?}"
        );
        assert!(
            status.offered_ip.get(&first).is_none_or(|cache| cache.ip != ip),
            "the stale offer must be dropped, so the next request is answered with a free address"
        );
    }

    /// Expiring one client's lease must not free an address that now belongs to
    /// another. A client that stops renewing leaves a record that looks free, and
    /// the address can be handed on before the sweep runs.
    #[test]
    fn t18_expiring_a_lease_does_not_free_another_clients_address() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let stale = make_mac("00:e2:69:a3:e3:71");
        let current = make_mac("d0:f9:28:ff:fa:eb");

        let ip = status.offer_ip(&stale, None).expect("a free address exists");
        assert!(status.ack_request(&stale, ip, None, 3600));

        // `stale` stops renewing, and the address is granted to `current` before the
        // sweep notices.
        {
            let cache = status.offered_ip.get_mut(&stale).expect("the offer is still cached");
            cache.relative_offer_time = 0;
            cache.valid_time = 0;
        }
        status.allocated_host.insert(ip, IpAllocSource::Dynamic(current));
        sleep(Duration::from_secs(1));

        let expired = status.clean_expire_ip();
        assert_eq!(expired.len(), 1, "the abandoned lease is reported as expired");
        assert_eq!(
            status.allocated_host.get(&ip),
            Some(&IpAllocSource::Dynamic(current)),
            "the current holder's record must survive the abandoned client's expiry"
        );
    }

    /// A DHCPDECLINE quarantines the address and frees the client that reported it.
    ///
    /// Both halves matter and both were missing: an earlier version refused to
    /// quarantine an address that still looked owned (twenty declines in half an hour
    /// on the real LAN, every one ignored), and it left the reporter's offer pointing
    /// at the address it had just rejected.
    #[test]
    fn t19_a_decline_quarantines_the_address_and_reallocates_the_reporter() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let reporter = make_mac("00:e2:69:a3:e3:71");

        let ip = status.offer_ip(&reporter, None).expect("a free address exists");
        assert!(status.ack_request(&reporter, ip, None, 3600));

        status.add_decline_ip(ip);

        assert!(
            matches!(status.allocated_host.get(&ip), Some(IpAllocSource::Declined(_))),
            "the address the client found in use must be quarantined"
        );
        assert!(
            status.offered_ip.get(&reporter).is_none_or(|cache| cache.ip != ip),
            "the reporter must stop being offered the address it just rejected"
        );
        assert!(!status.ack_request(&reporter, ip, None, 3600), "and must not renew it");

        let next = status.offer_ip(&reporter, None).expect("another free address exists");
        assert_ne!(next, ip, "the reporter is given a different address");
        assert!(
            matches!(status.allocated_host.get(&ip), Some(IpAllocSource::Declined(_))),
            "and the quarantined address stays out of circulation"
        );
    }

    /// The quarantine is temporary: after the hold-down the address may be used
    /// again, so one conflict does not shrink the pool for good.
    #[test]
    fn t20_a_quarantine_lifts_after_the_hold_down() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let ip = Ipv4Addr::new(192, 168, 5, 10);
        status.allocated_host.insert(
            ip,
            IpAllocSource::Declined(
                Instant::now() - Duration::from_secs(DECLINE_HOLD_DOWN_SECS + 1),
            ),
        );

        status.clean_expire_ip();

        assert!(
            !status.allocated_host.contains_key(&ip),
            "the hold-down has passed, so the address is available again"
        );
    }
}
