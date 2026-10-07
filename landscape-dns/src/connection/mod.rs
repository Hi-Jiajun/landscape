use std::{sync::Arc, time::Duration};

use hickory_resolver::{
    Resolver,
    config::{ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig, ResolverOpts},
};

use landscape_common::dns::config::DnsUpstreamConfig;
use landscape_common::dns::upstream::DnsUpstreamMode;

use crate::connection::provider::{MarkConnectionProvider, MarkRuntimeProvider};

pub(crate) mod pool;
pub(crate) mod provider;

mod failover;

pub(crate) use failover::FailoverResolver;

pub(crate) type LandscapeMarkDNSResolver = Resolver<MarkConnectionProvider>;

/// Build the resolver for one set of addresses.
///
/// Split out of [`create_resolver`] so the backup set is built by exactly the same
/// code as the primary: the modes (plaintext / TLS / HTTPS / QUIC), the ports and
/// the connection options cannot drift apart between the two.
fn build_resolver(
    flow_id: u32,
    mark_value: u32,
    // The whole configuration rather than its parts: `bind_config`'s type is not
    // nameable from here, and taking the struct keeps the mode, port and bind
    // settings from drifting apart between the primary and the backup.
    upstream: &DnsUpstreamConfig,
    ips: &[std::net::IpAddr],
) -> Option<LandscapeMarkDNSResolver> {
    let mode = &upstream.mode;
    let port = upstream.port;
    let bind_config = upstream.bind_config.clone();
    let name_server: Vec<NameServerConfig> = match mode {
        DnsUpstreamMode::Plaintext => ips
            .iter()
            .map(|ip| {
                let port = port.unwrap_or(53);
                let mut udp = ConnectionConfig::new(ProtocolConfig::Udp);
                udp.port = port;
                let mut tcp = ConnectionConfig::new(ProtocolConfig::Tcp);
                tcp.port = port;
                NameServerConfig::new(*ip, true, vec![udp, tcp])
            })
            .collect(),
        DnsUpstreamMode::Tls { domain } => ips
            .iter()
            .map(|ip| {
                let mut conn = ConnectionConfig::new(ProtocolConfig::Tls {
                    server_name: domain.clone().into(),
                });
                conn.port = port.unwrap_or(853);
                NameServerConfig::new(*ip, true, vec![conn])
            })
            .collect(),
        DnsUpstreamMode::Https { domain, http_endpoint } => ips
            .iter()
            .map(|ip| {
                let path: Arc<str> = http_endpoint
                    .as_ref()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.clone().into())
                    .unwrap_or_else(|| Arc::from("/dns-query"));
                let mut conn = ConnectionConfig::new(ProtocolConfig::Https {
                    server_name: domain.clone().into(),
                    path,
                });
                conn.port = port.unwrap_or(443);
                NameServerConfig::new(*ip, true, vec![conn])
            })
            .collect(),
        DnsUpstreamMode::Quic { domain } => ips
            .iter()
            .map(|ip| {
                let mut conn = ConnectionConfig::new(ProtocolConfig::Quic {
                    server_name: domain.clone().into(),
                });
                conn.port = port.unwrap_or(853);
                NameServerConfig::new(*ip, true, vec![conn])
            })
            .collect(),
    };

    let resolve = ResolverConfig::from_parts(None, vec![], name_server);

    let mut options = ResolverOpts::default();
    options.cache_size = 0;
    options.num_concurrent_reqs = 4;
    options.preserve_intermediates = true;
    // options.use_hosts_file = ResolveHosts::Never;
    // Keep each attempt short (1s) so the resolver's built-in retry
    // (attempts = 3) can recover from transient first-packet loss well within
    // the 5s outer lookup timeout; with the 5s default the second attempt
    // never gets to run and the client sees a 5s ServFail on the first query.
    // Normal lookups complete in milliseconds and never hit this timeout.
    options.timeout = Duration::from_secs(1);
    options.attempts = 3;
    let resolver = match Resolver::builder_with_config(
        resolve,
        MarkRuntimeProvider::new(mark_value, bind_config),
    )
    .with_options(options)
    .build()
    {
        Ok(resolver) => resolver,
        Err(e) => {
            tracing::error!("[flow: {flow_id}]: failed to build DNS resolver: {e}");
            return None;
        }
    };

    Some(resolver)
}

pub(crate) fn create_resolver(
    flow_id: u32,
    mark_value: u32,
    upstream: DnsUpstreamConfig,
) -> Option<LandscapeMarkDNSResolver> {
    build_resolver(flow_id, mark_value, &upstream, &upstream.ips)
}

/// Build a resolver with, when the configuration names one, a backup.
///
/// The backup is built from the same mode and port as the primary: it is the same
/// kind of resolver, just a different address, which is what "domestic ISP primary
/// with a public backup" means. A backup that cannot be built is reported and
/// ignored rather than failing the rule - a misconfigured backup must not take the
/// primary's resolution down with it.
pub(crate) fn create_failover_resolver(
    flow_id: u32,
    mark_value: u32,
    upstream: DnsUpstreamConfig,
) -> Option<FailoverResolver> {
    let backup = if upstream.backup_ips.is_empty() {
        None
    } else {
        match build_resolver(flow_id, mark_value, &upstream, &upstream.backup_ips) {
            Some(resolver) => Some(resolver),
            None => {
                tracing::error!(
                    upstream_id = %upstream.id,
                    "[flow: {flow_id}]: the backup DNS upstream could not be built; the rule keeps \
                     using its primary only"
                );
                None
            }
        }
    };
    let primary = create_resolver(flow_id, mark_value, upstream)?;
    Some(FailoverResolver::new(primary, backup))
}
