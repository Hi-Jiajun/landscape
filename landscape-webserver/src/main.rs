use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;

use axum::{
    Router, handler::HandlerWithoutStateExt, http::StatusCode, response::IntoResponse, routing::get,
};

use axum_server::tls_rustls::RustlsConfig;
use colored::Colorize;

use landscape_ebpf::{chain::ip6_dao_event::Ip6DaoEventSource, runtime::EbpfRuntime};

use landscape::{
    boot::{boot_check, log::init_logger, write_config_toml, write_init_lock},
    cert::{account_service::CertAccountService, order_service::CertService},
    config_service::enrolled_device_service::EnrolledDeviceService,
    config_service::firewall_blacklist_service::FirewallBlacklistService,
    config_service::iface_service::IfaceManagerService,
    config_service::static_nat4_mapping_service::StaticNat4MappingService,
    config_service::static_nat6_mapping_service::StaticNat6MappingService,
    dns::{
        ddns_service::DdnsService, provider_profile_service::DnsProviderProfileService,
        redirect_service::DNSRedirectService, rule_service::DNSRuleService,
        upstream_service::DnsUpstreamService,
    },
    docker::LandscapeDockerService,
    flow::{dst_ip_rule_service::DstIpRuleService, rule_service::FlowRuleService},
    geo::{ip_service::GeoIpService, site_service::GeoSiteService},
    lan_service::lan_dhcp4_service::DHCPv4ServerManagerService,
    lan_service::lan_ipv6_service::LanIPv6ManagerService,
    lan_service::lan_route_service::RouteLanServiceManagerService,
    metric::MetricService,
    sys_service::route::IpRouteService,
    sys_service::{
        config_service::LandscapeConfigService, dns_service::LandscapeDnsService,
        ebpf_service::LandscapeEbpfService,
    },
    wan_service::firewall::FirewallServiceManagerService,
    wan_service::{
        ipconfig_service::IfaceIpServiceManagerService,
        ipv6pd_service::{DHCPv6ClientManagerService, generate_wan_iid},
        mss_clamp_service::MssClampServiceManagerService,
        nat_service::NatServiceManagerService,
        pppd_service::PPPDServiceConfigManagerService,
        wan_route_service::RouteWanServiceManagerService,
    },
    wifi::WifiServiceManagerService,
};
use landscape_common::lan_service::lan_route::RouteLanServiceConfig;
use landscape_common::{
    VERSION,
    args::{DbAction, LAND_ARGS, LAND_HOME_PATH, LandscapeAction, RescueAction},
    concurrency::{runtime_thread_name_fn, spawn_task, task_label, thread_name},
    config::RuntimeConfig,
    database::error::DbError,
    database::store::ConfigStore,
    event::hub::EventHub,
    wan_service::ipv6_pd::IAPrefixMap,
};
use landscape_common::{
    config::{InitConfig, StoreRuntimeConfig},
    lan_service::lan_dhcpv4::config::DHCPv4ServiceConfig,
};
use landscape_core::cert::build_tls_server_config_with_shared_resolver;
use landscape_core::{lan_device::LanDeviceDirectory, time::SyncTimeService};
use landscape_database::provider::LandscapeDBServiceProvider;
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::mpsc;
use tower_http::{compression::CompressionLayer, services::ServeDir, trace::TraceLayer};
use utoipa_scalar::{Scalar, Servable};

mod api;
mod app;
mod auth;
mod cert;
mod devices;
mod dns;
mod docker;
mod dump;
mod error;
mod firewall;
mod flow;
mod gateway;
mod gateway_runtime;
mod geo;
mod interfaces;
mod metrics;
mod nat;
mod openapi;
mod proxy;
mod redirect_https;
mod self_monitor;
mod services;
mod system;
mod websocket;

pub use app::LandscapeApp;

use crate::gateway_runtime::{GatewayService, GatewayTlsConfig};
use tracing::info;

const DNS_EVENT_CHANNEL_SIZE: usize = 128;
const DST_IP_EVENT_CHANNEL_SIZE: usize = 128;

const UPLOAD_GEO_FILE_SIZE_LIMIT: usize = 100 * 1024 * 1024;

/// 按子系统记账的全局分配器(feature `mem-track` 显式开启时精确归属;
/// 未开启时为 System 纯透传,零开销)。必须尽早声明,覆盖进程全部堆分配。
#[global_allocator]
static GLOBAL_ALLOCATOR: landscape_common::memtrack::CountingAllocator =
    landscape_common::memtrack::CountingAllocator;

fn log_startup_phase(phase: &str, phase_start: Instant, startup_start: Instant) {
    tracing::info!(
        "startup phase={} elapsed_ms={} since_run_ms={}",
        phase,
        phase_start.elapsed().as_millis(),
        startup_start.elapsed().as_millis()
    );
}

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error(transparent)]
    Boot(#[from] landscape::boot::BootError),
    #[error(transparent)]
    Database(#[from] DbError),
    #[error("{0}")]
    Cert(String),
    #[error("metric: {0}")]
    Metric(String),
    #[error("config: {0}")]
    Config(String),
}

/// `rescue` subcommand: versioned configuration snapshots and rollback.
///
/// Everything here is a file operation, so it works with the service stopped —
/// which is the state a broken configuration leaves the router in.
async fn run_rescue(
    action: &RescueAction,
    home_path: &Path,
    store: &StoreRuntimeConfig,
) -> Result<(), DbError> {
    use landscape_database::rescue::{GrantStore as Grants, SnapshotStore};

    let snapshots = SnapshotStore::for_config_dir(home_path);
    let database_path = database_file_path(&store.database_path);
    // `create` needs the URL (it connects through SQLite); `restore` needs the
    // file path (it replaces the file). Keeping both here is the only place the
    // two are easy to confuse.
    let version = env!("CARGO_PKG_VERSION");

    match action {
        RescueAction::Snapshot { label, keep } => {
            let manifest =
                snapshots.create(&store.database_path, label.clone(), false, version).await?;
            println!("snapshot {}  {} bytes", manifest.id, manifest.size);
            if let Some(label) = &manifest.label {
                println!("  label: {label}");
            }
            println!("  path : {}", database_path.display());
            let removed = snapshots.prune(*keep)?;
            if removed > 0 {
                println!("  pruned {removed} older snapshot(s), keeping {keep}");
            }
        }
        RescueAction::List => {
            let all = snapshots.list()?;
            if all.is_empty() {
                println!("no snapshots in {}", snapshots.dir().display());
                println!("take one with: landscape-webserver rescue snapshot");
                return Ok(());
            }
            println!("{:>17}  {:<6} {:>9}  label", "id", "kind", "size");
            for manifest in &all {
                println!("{}", manifest.describe());
            }
            println!("\n{} snapshot(s) in {}", all.len(), snapshots.dir().display());
        }
        RescueAction::Restore { id } => {
            let manifest = snapshots.find(id)?;
            // Take a snapshot of what is being replaced first, so this action is
            // itself undoable with the same command.
            let safety = snapshots
                .create(
                    &store.database_path,
                    Some(format!("before restoring {}", manifest.id)),
                    true,
                    version,
                )
                .await?;
            println!("pre-restore snapshot: {}", safety.id);
            snapshots.restore(&manifest.id, &database_path)?;
            println!("restored {} onto {}", manifest.id, database_path.display());
            println!("restart the service to load it: systemctl restart landscape.service");
        }
        RescueAction::Rollback => {
            let newest = snapshots.newest()?;
            let safety = snapshots
                .create(
                    &store.database_path,
                    Some(format!("before rolling back to {}", newest.id)),
                    true,
                    version,
                )
                .await?;
            println!("pre-restore snapshot: {}", safety.id);
            snapshots.restore(&newest.id, &database_path)?;
            println!("rolled back to {} ({})", newest.id, database_path.display());
            if let Some(label) = &newest.label {
                println!("  label: {label}");
            }
            println!("restart the service to load it: systemctl restart landscape.service");
        }
        RescueAction::Begin { label, timeout } => {
            let pending = snapshots
                .begin_transaction(&store.database_path, label.clone(), *timeout, version)
                .await?;
            println!("transaction open: {}", pending.describe());
            println!("  snapshot: {}", pending.snapshot_id);
            println!(
                "  it will be restored automatically in {}s unless `rescue commit` runs",
                timeout
            );
        }
        RescueAction::Commit => {
            let pending = snapshots.commit_transaction()?;
            println!("accepted the change that started from {}", pending.snapshot_id);
            if let Some(label) = &pending.label {
                println!("  label: {label}");
            }
        }
        RescueAction::Discard => {
            let pending = snapshots.rollback_transaction(&database_path)?;
            println!("discarded the change; restored {}", pending.snapshot_id);
            if let Some(label) = &pending.label {
                println!("  label: {label}");
            }
            println!("restart the service to load it: systemctl restart landscape.service");
        }
        RescueAction::Status => match snapshots.pending() {
            Some(pending) => {
                println!("a configuration change is provisional: {}", pending.describe());
                println!("  snapshot: {}", pending.snapshot_id);
                if pending.is_expired() {
                    println!("  the deadline has passed; it will be restored on the next start");
                }
            }
            None => println!("no provisional change"),
        },
        RescueAction::Authorize { mac, flow_id, minutes, reason } => {
            // Only the grant is recorded here. The flow rule is applied by the
            // service when it starts and by the sweep that removes expired grants,
            // so this works while the service is down and cannot leave a rule
            // behind that nothing tracks.
            let mut grants = Grants::load(snapshots.dir())?;
            let grant = grants.add(
                snapshots.dir(),
                mac.clone(),
                *flow_id,
                reason.clone(),
                minutes.saturating_mul(60),
            )?;
            println!("granted {} for {minutes} minute(s)", grant.describe());
            println!("  it is removed automatically when the time is up");
            println!("  the service applies it at startup and on its sweep");
        }
        RescueAction::Grants { all } => {
            let grants = Grants::load(snapshots.dir())?;
            let listed: Vec<_> = if *all { grants.all().to_vec() } else { grants.active() };
            if listed.is_empty() {
                println!("no device grants in {}", snapshots.dir().display());
                return Ok(());
            }
            for grant in &listed {
                println!("{}", grant.describe());
            }
        }
        RescueAction::Revoke { id } => {
            let mut grants = Grants::load(snapshots.dir())?;
            let revoked = grants.revoke(snapshots.dir(), id)?;
            println!("revoked {}", revoked.describe());
            println!("the service removes its flow rule on the next sweep, or at once if stopped");
        }
    }
    Ok(())
}

/// The file behind a `sqlite://…?mode=rwc` URL.
///
/// The snapshot code needs the path, and the URL is the only place the store
/// keeps it, so the same parsing has to happen here.
fn database_file_path(database_url: &str) -> PathBuf {
    let rest = database_url.strip_prefix("sqlite://").unwrap_or(database_url);
    let without_query = rest.split('?').next().unwrap_or(rest);
    PathBuf::from(without_query)
}

/// Undo a configuration change that was applied but never accepted.
///
/// Startup is the right place for the forced case: if the service did not come
/// up, or came up and then died, the operator never got to accept the change, so
/// the configuration it replaced is the last one known to work. Only a change with
/// an open transaction is affected; everything else starts normally.
async fn rollback_uncommitted_change(
    home_path: &Path,
    store: &StoreRuntimeConfig,
) -> Result<(), DbError> {
    use landscape_database::rescue::SnapshotStore;

    let snapshots = SnapshotStore::for_config_dir(home_path);
    if snapshots.pending().is_none() {
        return Ok(());
    }
    let database_path = database_file_path(&store.database_path);
    match snapshots.rollback_expired(&database_path, true) {
        Ok(Some(pending)) => {
            tracing::error!(
                snapshot = %pending.snapshot_id,
                label = pending.label.as_deref().unwrap_or("-"),
                "a configuration change was never accepted; restored the previous configuration. \
                 If that change was intended, apply it again and run `rescue commit`"
            );
            println!(
                "restored the previous configuration: the change started from snapshot {} was \
                 never committed",
                pending.snapshot_id
            );
        }
        Ok(None) => {}
        Err(e) => {
            // Keep going rather than refusing to start: the operator may need the
            // service up to fix things, and the marker is still on disk.
            tracing::error!(
                "could not roll back the uncommitted configuration change: {e}; it is still \
                 marked provisional"
            );
        }
    }
    Ok(())
}

/// Put one device into a flow, or take it out.
///
/// Used by the time-limited device grants. The flow is one the operator already
/// trusts; this only adds or removes that device's match rule, so nothing else
/// about the flow changes and removing the grant restores it exactly.
///
/// Lives here rather than on the flow service because it needs nothing private:
/// reading the rule and writing it back through the controller is the same path
/// an edit from the UI takes, so the flow matches, route targets and TProxy
/// mapping are all updated.
async fn set_device_membership(
    flow_rule_service: &FlowRuleService,
    flow_id: u32,
    mac_addr: landscape_common::net::MacAddr,
    present: bool,
) -> Result<bool, DbError> {
    use landscape_common::flow::{FlowEntryMatchMode, FlowEntryRule};
    use landscape_common::service::controller::ConfigStoreController;

    let Some(mut config) =
        flow_rule_service.list().await?.into_iter().find(|rule| rule.flow_id == flow_id)
    else {
        return Err(DbError::Internal(format!(
            "no flow with id {flow_id}; a grant must name a flow that exists"
        )));
    };

    let before = config.flow_match_rules.len();
    config.flow_match_rules.retain(|rule| {
        !matches!(&rule.mode, FlowEntryMatchMode::Mac { mac_addr: existing } if *existing == mac_addr)
    });
    let matched_before = config.flow_match_rules.len() != before;

    if present && !matched_before {
        config.flow_match_rules.push(FlowEntryRule {
            qos: None,
            mode: FlowEntryMatchMode::Mac { mac_addr },
        });
    }

    let changed = matched_before != present;
    if changed {
        flow_rule_service.checked_set(config).await?;
    }
    Ok(changed)
}

/// Bring the flow rules in line with the device grants.
///
/// Runs at startup and on a timer. Each pass:
///   * drops the grants whose time is up, and takes those devices out of their
///     flows;
///   * puts the devices of the grants still in force into their flows.
///
/// It is declarative — the grants file is the source of truth and this makes the
/// dataplane match it — so a grant removed while the service was down, or a rule
/// lost to a failed write, is corrected by the next pass rather than persisting.
/// The traffic effect is audited at the moment it changes.
async fn reconcile_device_grants(
    home_path: &Path,
    flow_rule_service: &FlowRuleService,
) -> Result<(), DbError> {
    use landscape_database::rescue::{GrantStore, SnapshotStore};

    let dir = SnapshotStore::for_config_dir(home_path);
    let grants_dir = dir.dir().to_path_buf();
    let mut store = GrantStore::load(&grants_dir)?;

    for expired in store.take_expired(&grants_dir)? {
        tracing::error!(
            grant = %expired.id,
            mac = %expired.mac,
            flow_id = expired.flow_id,
            reason = %expired.reason,
            "a temporary device authorization expired; the device is leaving the flow"
        );
        match expired.mac_addr() {
            Some(mac) => {
                if let Err(e) =
                    set_device_membership(flow_rule_service, expired.flow_id, mac, false).await
                {
                    // The grant is gone from the file, so the next pass will try
                    // again rather than leaving the device authorized.
                    tracing::error!("cannot remove the expired grant's flow rule: {e}");
                }
            }
            None => tracing::error!(mac = %expired.mac, "grant has an unreadable MAC"),
        }
    }

    for grant in store.active() {
        let Some(mac) = grant.mac_addr() else {
            tracing::error!(mac = %grant.mac, "grant has an unreadable MAC");
            continue;
        };
        match set_device_membership(flow_rule_service, grant.flow_id, mac, true).await {
            Ok(true) => tracing::warn!(
                grant = %grant.id,
                mac = %grant.mac,
                flow_id = grant.flow_id,
                remaining_secs = grant.remaining_secs(),
                reason = %grant.reason,
                "a device was authorized into a flow until the grant expires"
            ),
            Ok(false) => {}
            Err(e) => tracing::error!(grant = %grant.id, "cannot apply the grant: {e}"),
        }
    }
    Ok(())
}

async fn prepare_startup_init(
    home_path: &Path,
    config: &RuntimeConfig,
    init_config_to_import: Option<InitConfig>,
) -> Result<LandscapeDBServiceProvider, StartupError> {
    let startup_start = Instant::now();

    macro_rules! startup_phase {
        ($name:literal, $expr:expr) => {{
            let phase_start = Instant::now();
            let value = $expr;
            log_startup_phase($name, phase_start, startup_start);
            value
        }};
    }

    let init_file_config_to_persist = init_config_to_import
        .as_ref()
        .filter(|init_config| !init_config.version.is_empty())
        .map(|init_config| init_config.config.clone());

    let crypto_provider = rustls::crypto::ring::default_provider();
    crypto_provider.install_default().unwrap();

    let db_store_provider = startup_phase!(
        "db_store_provider.new",
        LandscapeDBServiceProvider::new(&config.store).await?
    );

    if let Some(init_config) = init_config_to_import {
        startup_phase!("db_store_provider.truncate_and_fit_from", {
            LandscapeDBServiceProvider::validate_init_config_can_import(init_config.clone())
                .await?;
            db_store_provider
                .truncate_and_fit_from_before_commit(init_config, || {
                    if let Some(config) = init_file_config_to_persist {
                        write_config_toml(home_path, config)
                            .map_err(|e| DbError::Internal(e.to_string()))?;
                    }
                    Ok(())
                })
                .await?
        });
        startup_phase!("write_init_lock", write_init_lock(home_path)?);
    }

    Ok(db_store_provider)
}

async fn run_system(
    home_path: PathBuf,
    config: RuntimeConfig,
    db_store_provider: LandscapeDBServiceProvider,
    time_service: SyncTimeService,
) -> Result<(), StartupError> {
    let startup_start = Instant::now();

    macro_rules! startup_phase {
        ($name:literal, $expr:expr) => {{
            let phase_start = Instant::now();
            let value = $expr;
            log_startup_phase($name, phase_start, startup_start);
            value
        }};
    }

    // init App

    // init eBPF runtime (map space + TC/XDP chain managers)
    let ebpf_rt = Arc::new(
        EbpfRuntime::init(&LAND_ARGS.ebpf_map_space, LAND_ARGS.try_native_xdp.clone())
            .expect("failed to init eBPF runtime"),
    );
    let ebpf_paths = ebpf_rt.paths().clone();

    let event_hub = EventHub::new();
    startup_phase!("observer.dev_observer", landscape::observer::dev_observer(&event_hub).await);
    let device_sender = event_hub.enrolled_device_sender();
    let ipv4_assign_sender = event_hub.ipv4_sender();
    let ipv6_assign_sender = event_hub.ipv6_sender();
    let ipv6_prefix_sender = event_hub.ipv6_prefix_sender();
    let lan_discovery_sender = event_hub.lan_discovery_sender();
    let lan_device_sender = event_hub.lan_device_sender();
    let event_handle = event_hub.spawn();

    startup_phase!(
        "xdp_redirect_able.clear",
        landscape_ebpf::maps::redirect_able::clear_xdp_redirect_able(&ebpf_paths)
    );

    let (dns_service_tx, dns_service_rx) = mpsc::channel(DNS_EVENT_CHANNEL_SIZE);
    let (dst_ip_service_tx, _) = tokio::sync::broadcast::channel(DST_IP_EVENT_CHANNEL_SIZE);

    let geo_site_service = startup_phase!(
        "geo_site_service.new",
        GeoSiteService::new(db_store_provider.clone(), dns_service_tx.clone()).await
    );

    let dns_upstream_service = startup_phase!(
        "dns_upstream_service.new",
        DnsUpstreamService::new(db_store_provider.clone(), dns_service_tx.clone()).await
    );

    let dns_rule_service = startup_phase!(
        "dns_rule_service.new",
        DNSRuleService::new(
            db_store_provider.clone(),
            dns_service_tx.clone(),
            dns_upstream_service.clone(),
        )
        .await?
    );

    let route_service =
        startup_phase!("route_service.new", IpRouteService::new(ebpf_rt.clone().route_table()));

    // Created before the flow service so the latter can publish the
    // `flow_id -> local TProxy listener` mapping the plugin has to deliver.
    let docker_service = LandscapeDockerService::new(home_path.clone(), route_service.clone());
    let proxy_service = landscape::proxy::LandscapeProxyService::new(
        home_path.clone(),
        ebpf_rt.clone().dns_guard(),
        ebpf_rt.clone().flow_rules(),
        ebpf_rt.clone().mss_clamp(),
    )
    .await;

    let flow_rule_service = startup_phase!(
        "flow_rule_service.new",
        FlowRuleService::new(
            db_store_provider.clone(),
            dns_service_tx.clone(),
            route_service.clone(),
            event_handle.subscribe_device(),
            ebpf_rt.clone().flow_rules(),
            proxy_service.tproxy_delivery(),
        )
        .await
    );

    let dns_redirect_service = startup_phase!(
        "dns_redirect_service.new",
        DNSRedirectService::new(db_store_provider.clone(), dns_service_tx.clone()).await
    );

    // Temporary device authorizations: apply what is in force and drop what has
    // expired, now and then on a timer. This runs after the flow service exists so
    // the grants take effect through the normal flow path, and again at startup so
    // a grant that expired while the service was down does not survive it.
    // A failure here is logged and the service starts anyway: the operator may
    // need it up to fix things, and the grants file still describes the intent.
    if let Err(e) = reconcile_device_grants(&home_path, &flow_rule_service).await {
        tracing::error!("cannot reconcile the device grants at startup: {e}");
    }
    {
        let home = home_path.clone();
        let service = flow_rule_service.clone();
        spawn_task("device_grants.sweep", async move {
            // A minute is far below any grant's duration and cheap: the reconcile
            // is a file read plus one comparison per grant when nothing changed.
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                ticker.tick().await;
                if let Err(e) = reconcile_device_grants(&home, &service).await {
                    tracing::error!("cannot reconcile the device grants: {e}");
                }
            }
        });
    }

    let metric_service = startup_phase!(
        "metric_service.new",
        MetricService::new(
            home_path.clone(),
            config.metric.clone(),
            Arc::new(ebpf_rt.metric_source_factory()),
        )
        .await
        .map_err(StartupError::Metric)?
    );

    let cert_account_service = startup_phase!(
        "cert_account_service.new",
        CertAccountService::new(db_store_provider.clone()).await
    );
    let cert_service = startup_phase!(
        "cert_service.new",
        CertService::new(
            db_store_provider.clone(),
            cert_account_service.clone(),
            Some(dns_redirect_service.clone()),
        )
        .await
    );
    let phase_start = Instant::now();
    if let Err(e) = cert_service.reload_api_tls_mapping().await {
        return Err(StartupError::Cert(format!("failed to load api tls certificates: {e}")));
    }
    log_startup_phase("cert_service.reload_api_tls_mapping", phase_start, startup_start);
    #[cfg(feature = "gateway")]
    let gateway_tls_config = {
        let phase_start = Instant::now();
        let gateway_tls_mapping_count = match cert_service.reload_gateway_tls_mapping().await {
            Ok(count) => count,
            Err(e) => {
                return Err(StartupError::Cert(format!(
                    "failed to load gateway tls certificates: {e}"
                )));
            }
        };
        if gateway_tls_mapping_count == 0 {
            tracing::warn!(
                "No valid for_gateway certificate found; gateway HTTPS listener will start but reject TLS handshakes until a certificate is loaded"
            );
        }
        let mut gateway_server_config =
            build_tls_server_config_with_shared_resolver(cert_service.gateway_tls_resolver());
        gateway_server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        log_startup_phase("cert_service.reload_gateway_tls_mapping", phase_start, startup_start);
        Some(GatewayTlsConfig::new(std::sync::Arc::new(gateway_server_config)))
    };
    #[cfg(not(feature = "gateway"))]
    let gateway_tls_config: Option<GatewayTlsConfig> = None;

    // Gateway
    let gateway_store = db_store_provider.gateway_http_upstream_store();
    let gateway_service = startup_phase!(
        "gateway_service.init_service",
        GatewayService::init_service(gateway_store, config.gateway.clone(), gateway_tls_config)
            .await
    );

    let enrolled_devices = db_store_provider.enrolled_device_store().list().await.map_err(|e| {
        StartupError::Database(DbError::Internal(format!("failed to list enrolled devices: {e}")))
    })?;
    let lan_device_directory = startup_phase!("lan_device.new", {
        LanDeviceDirectory::new(
            enrolled_devices.clone(),
            lan_device_sender,
            event_handle.subscribe_device(),
            event_handle.subscribe_ipv4_assign(),
            event_handle.subscribe_ipv6_assign(),
            event_handle.subscribe_lan_discovery(),
        )
    });
    // Shared LAN hostname config: hot-reloaded by the config service and read
    // by the DNS local resolver and the DHCPv4 server (options 15/119).
    let lan_domain_state = Arc::new(ArcSwap::from_pointee(config.lan_hostname.clone()));
    let dns_service = startup_phase!(
        "dns_service.new",
        LandscapeDnsService::new(
            dns_service_rx,
            dns_rule_service.clone(),
            dns_redirect_service.clone(),
            geo_site_service.clone(),
            dns_upstream_service.clone(),
            route_service.clone(),
            config.dns.clone(),
            cert_service.clone(),
            metric_service.get_dns_metric_channel(),
            lan_device_directory.clone(),
            lan_domain_state.clone(),
            Arc::new(ebpf_rt.dns_result_sink()),
            Arc::new(ebpf_rt.flow_socket_registrar()),
        )
        .await
    );
    let dns_provider_profile_service =
        DnsProviderProfileService::new(db_store_provider.clone()).await;
    let prefix_map = IAPrefixMap::new();

    let dao_event_source = match Ip6DaoEventSource::spawn(ebpf_paths.clone()) {
        Ok(source) => {
            tracing::info!("ip6_dao_event ringbuf consumer started");
            Some(Arc::new(source))
        }
        Err(e) => {
            tracing::warn!("ip6_dao_event ringbuf consumer failed to start: {e}");
            None
        }
    };
    let lan_ipv6_service = LanIPv6ManagerService::new(
        db_store_provider.clone(),
        event_handle.subscribe_iface(),
        event_handle.subscribe_device(),
        event_handle.subscribe_ipv6_prefix(),
        route_service.clone(),
        prefix_map.clone(),
        ipv6_assign_sender.clone(),
        ebpf_rt.clone().mac_binding(),
        dao_event_source,
        ebpf_rt.clone().ipv6_dao_filter(),
    )
    .await;
    let ddns_service = DdnsService::new(
        db_store_provider.clone(),
        route_service.clone(),
        prefix_map.clone(),
        lan_device_directory.clone(),
        event_handle.subscribe_lan_device(),
        event_handle.subscribe_ipv6_prefix(),
    )
    .await;

    let geo_ip_service =
        GeoIpService::new(db_store_provider.clone(), dst_ip_service_tx.clone()).await;
    let dst_ip_rule_service = DstIpRuleService::new(
        db_store_provider.clone(),
        geo_ip_service.clone(),
        dst_ip_service_tx.subscribe(),
        ebpf_rt.clone().flow_rules(),
    )
    .await;
    let firewall_blacklist_service = FirewallBlacklistService::new(
        db_store_provider.clone(),
        geo_ip_service.clone(),
        dst_ip_service_tx.subscribe(),
        ebpf_rt.clone().firewall(),
    )
    .await;

    let config_service =
        LandscapeConfigService::new(config.clone(), db_store_provider.clone()).await;

    let ebpf_service = LandscapeEbpfService::new(ebpf_rt.start_neigh_update());

    let static_nat4_mapping_service = StaticNat4MappingService::new(
        db_store_provider.clone(),
        event_handle.subscribe_device(),
        ebpf_rt.clone().nat(),
    )
    .await;

    let shared_wan_iid = Arc::new(generate_wan_iid());
    let static_nat6_mapping_service = StaticNat6MappingService::new(
        db_store_provider.clone(),
        lan_device_directory.clone(),
        shared_wan_iid.clone(),
        ebpf_rt.clone().nat(),
    )
    .await;

    let enrolled_device_service =
        EnrolledDeviceService::new(db_store_provider.clone(), device_sender).await;

    let route_lan_service = RouteLanServiceManagerService::new(
        db_store_provider.clone(),
        route_service.clone(),
        event_handle.subscribe_iface(),
        ebpf_rt.clone().lan_route(),
    )
    .await?;
    let route_wan_service = RouteWanServiceManagerService::new(
        db_store_provider.clone(),
        event_handle.subscribe_iface(),
        ebpf_rt.clone().wan_route(),
    )
    .await?;

    let mss_clamp_service = MssClampServiceManagerService::new(
        db_store_provider.clone(),
        event_handle.subscribe_iface(),
        ebpf_rt.clone().mss_clamp(),
    )
    .await?;

    let firewall_service = FirewallServiceManagerService::new(
        db_store_provider.clone(),
        event_handle.subscribe_iface(),
        ebpf_rt.clone().firewall(),
    )
    .await?;

    let nat_service = NatServiceManagerService::new(
        db_store_provider.clone(),
        event_handle.subscribe_iface(),
        route_service.clone(),
        ebpf_rt.clone().nat(),
    )
    .await;

    let wifi_service = WifiServiceManagerService::new(db_store_provider.clone()).await?;

    let iface_config_service = IfaceManagerService::new(db_store_provider.clone()).await;

    let dhcp_v4_server_service = DHCPv4ServerManagerService::new(
        route_service.clone(),
        db_store_provider.clone(),
        cert_service.api_tls_resolver(),
        config.dns.clone(),
        lan_domain_state,
        event_handle.subscribe_iface(),
        ipv4_assign_sender,
        lan_discovery_sender,
        event_handle.subscribe_device(),
        ebpf_rt.clone().mac_binding(),
    )
    .await;

    let wan_ip_service = IfaceIpServiceManagerService::new(
        route_service.clone(),
        ebpf_rt.clone().wan_addr_binding(),
        ebpf_rt.clone().pppoe_dataplane(),
        db_store_provider.clone(),
        event_handle.subscribe_iface(),
    )
    .await;

    let pppd_service = PPPDServiceConfigManagerService::new(
        db_store_provider.clone(),
        route_service.clone(),
        ebpf_rt.clone().wan_addr_binding(),
    )
    .await;

    let ipv6_pd_service = DHCPv6ClientManagerService::new(
        db_store_provider.clone(),
        event_handle.subscribe_iface(),
        route_service.clone(),
        ebpf_rt.clone().wan_addr_binding(),
        prefix_map.clone(),
        ipv6_prefix_sender.clone(),
        shared_wan_iid,
    )
    .await?;

    startup_phase!(
        "docker_service.start_to_listen_event",
        docker_service.start_to_listen_event().await
    );

    startup_phase!("metric_service.start_service", metric_service.start_service().await);
    // RAM 环形缓冲仅服务实时查询;分钟级持久化由 metric_service(MemRecording)独立负责。
    let memory_history = landscape_common::memtrack::start_sampler();
    let auth_share = Arc::new(ArcSwap::from_pointee(config.auth.clone()));
    let landscape_app_status = LandscapeApp {
        home_path: home_path.clone(),
        auth: auth_share.clone(),
        ebpf_paths,
        time_service,
        dns_service,
        ddns_service,
        lan_device_directory,
        dns_provider_profile_service,
        dns_rule_service,
        flow_rule_service,
        geo_site_service,
        firewall_blacklist_service,
        dst_ip_rule_service,
        geo_ip_service,
        config_service,
        metric_service,
        memory_history,
        route_service,
        dhcp_v4_server_service,
        wan_ip_service,

        route_lan_service,
        route_wan_service,

        docker_service,

        pppd_service,

        // IPV6
        ipv6_pd_service,
        lan_ipv6_service,
        static_nat4_mapping_service,
        static_nat6_mapping_service,
        dns_redirect_service,
        dns_upstream_service,
        iface_config_service,
        mss_clamp_service,
        firewall_service,
        wifi_service,
        nat_service,
        // ebpf
        ebpf_service,
        enrolled_device_service,
        // cert
        cert_account_service,
        cert_service: cert_service.clone(),
        // gateway
        gateway_service: gateway_service.clone(),
        proxy_service,
    };

    gateway::sync_gateway_dynamic_dns_redirects(&landscape_app_status).await;

    // 初始化结束
    let tls_config = build_tls_server_config_with_shared_resolver(cert_service.api_tls_resolver());
    landscape_common::utils::sysctl::init_sysctl_setting();

    let addr = SocketAddr::from((config.web.address, config.web.https_port));
    // spawn a second server to redirect http requests to this server
    spawn_task(
        task_label::task::WEB_REDIRECT_HTTPS,
        redirect_https::redirect_http_to_https(config.web.clone()),
    );
    let web_root = config.web.web_root.clone();
    let service = (move || handle_404(web_root)).into_service();

    let serve_dir = ServeDir::new(&config.web.web_root).not_found_service(service);

    auth::output_sys_token(&config.auth).await;
    // Build OpenApiRouter for each domain, then split into plain Router + discard local spec
    let (interfaces_router, _) = openapi::build_interfaces_openapi_router().split_for_parts();
    let (system_router, _) = openapi::build_system_openapi_router().split_for_parts();
    let (services_router, _) = openapi::build_services_openapi_router().split_for_parts();
    let (dns_router, _) = openapi::build_dns_openapi_router().split_for_parts();
    let (firewall_router, _) = openapi::build_firewall_openapi_router().split_for_parts();
    let (flow_router, _) = openapi::build_flow_openapi_router().split_for_parts();
    let (nat_router, _) = openapi::build_nat_openapi_router().split_for_parts();
    let (geo_router, _) = openapi::build_geo_openapi_router().split_for_parts();
    let (devices_router, _) = openapi::build_devices_openapi_router().split_for_parts();
    let (cert_router, _) = openapi::build_cert_openapi_router().split_for_parts();
    let (docker_router, _) = openapi::build_docker_openapi_router().split_for_parts();
    let (metrics_router, _) = openapi::build_metrics_openapi_router().split_for_parts();
    let (self_monitor_router, _) = openapi::build_self_monitor_openapi_router().split_for_parts();
    let (gateway_router, _) = openapi::build_gateway_openapi_router().split_for_parts();
    let (proxy_router, _) = openapi::build_proxy_openapi_router().split_for_parts();
    let openapi = openapi::build_full_openapi_spec();

    // /system combines two routers with different state types:
    // - system_router (LandscapeApp state): /config/...
    // - sysinfo (shared status snapshot state): /info/...
    let system_combined = system_router
        .with_state(landscape_app_status.clone())
        .merge(system::info::get_sys_info_route(ebpf_rt.paths().clone()));

    // /api/v1 — all authenticated HTTP routes (Bearer token)
    let v1_route = Router::new()
        .nest("/interfaces", interfaces_router)
        .nest("/services", services_router)
        .nest("/dns", dns_router)
        .nest("/firewall", firewall_router)
        .nest("/flow", flow_router)
        .nest("/nat", nat_router)
        .nest("/geo", geo_router)
        .nest("/devices", devices_router)
        .nest("/cert", cert_router)
        .nest("/docker", docker_router)
        .nest("/metrics", metrics_router)
        .nest("/self-monitor", self_monitor_router)
        .nest("/gateway", gateway_router)
        .nest("/proxy", proxy_router)
        .with_state(landscape_app_status.clone())
        .nest("/system", system_combined)
        .route_layer(axum::middleware::from_fn_with_state(auth_share.clone(), auth::auth_handler));

    // /api/ws — WebSocket routes (query string token auth)
    let ws_route = Router::new()
        .nest("/docker", websocket::docker_task::get_docker_images_socks_paths().await)
        .nest("/pty", websocket::web_pty::get_web_pty_socks_paths().await)
        .with_state(landscape_app_status.clone())
        .merge(dump::get_tump_router())
        .route_layer(axum::middleware::from_fn_with_state(
            auth_share.clone(),
            auth::auth_handler_from_query,
        ));

    let api_route = Router::new()
        .nest("/v1", v1_route)
        .nest("/ws", ws_route)
        .nest("/auth", auth::get_auth_route(auth_share))
        .merge(Scalar::with_url("/docs", openapi).custom_html(
            r#"<!doctype html>
<html>
<head>
    <title>Landscape API Docs</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <link rel="stylesheet" href="/scalar/style.css"/>
    <style>
        .home-btn {
            position: fixed;
            top: 12px;
            right: 24px;
            z-index: 9999;
            padding: 6px 16px;
            background: #3451b2;
            color: #fff;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            text-decoration: none;
            line-height: 1.5;
        }
        .home-btn:hover {
            background: #2c3e8f;
        }
    </style>
</head>
<body>
<a class="home-btn" href="/">Home</a>
<script
        id="api-reference"
        type="application/json">
    $spec
</script>
<script src="/scalar/standalone.js"></script>
</body>
</html>"#,
        ));
    let app = Router::new()
        .nest("/api", api_route)
        // .nest("/sock", sockets_route)
        .route("/foo", get(|| async { "Hi from /foo" }))
        .fallback_service(serve_dir)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http());

    let server_handle = axum_server::Handle::new();
    let server = axum_server::bind_rustls(addr, RustlsConfig::from_config(tls_config.into()))
        .handle(server_handle.clone())
        .serve(app.into_make_service_with_connect_info::<SocketAddr>());

    tokio::select! {
        result = server => {
            if let Err(e) = result {
                tracing::error!("Server error: {e:?}");
            }
        }
        _ = shutdown_signal() => {
            tracing::info!("Initiating graceful shutdown...");
        }
    }

    server_handle.graceful_shutdown(Some(Duration::from_secs(10)));

    let shutdown_timeout = Duration::from_secs(30);
    tracing::info!("Stopping all services ({}s timeout)...", shutdown_timeout.as_secs());
    match tokio::time::timeout(shutdown_timeout, landscape_app_status.shutdown()).await {
        Ok(()) => tracing::info!("All services stopped successfully."),
        Err(_) => tracing::warn!("Shutdown timed out, some hooks may remain."),
    }

    tracing::info!("Landscape Router shutdown complete.");
    Ok(())
}

fn main() -> Result<(), StartupError> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .thread_name_fn(runtime_thread_name_fn(thread_name::prefix::CORE_RUNTIME))
        .build()
        .expect("failed to create main runtime");

    runtime.block_on(async_main())
}

async fn async_main() -> Result<(), StartupError> {
    let home_path = LAND_HOME_PATH.clone();

    let lock_exists = home_path.join(landscape_common::INIT_LOCK_FILE_NAME).exists();
    let init_exists = home_path.join(landscape_common::INIT_FILE_NAME).exists();
    let db_exists = home_path.join(landscape_common::LANDSCAPE_DB_SQLITE_NAME).exists();

    let args = (*LAND_ARGS).clone();

    // The `config` subcommand only generates a landscape_init.toml. It does not
    // touch the database, eBPF or the running system, so handle it before any
    // logging / time-sync side effects.
    if let Some(LandscapeAction::Config(config_args)) = &args.action {
        landscape_common::config::cli::run_config_cli(config_args)
            .map_err(|e| StartupError::Config(e.to_string()))?;
        return Ok(());
    }

    let init_config_to_import = if args.action.is_none() { boot_check(&home_path)? } else { None };
    let config = RuntimeConfig::new_with_file_config(
        args.clone(),
        init_config_to_import
            .as_ref()
            .filter(|_| init_exists)
            .map(|init_config| init_config.config.clone()),
    );

    if let Err(e) = init_logger(config.log.clone()) {
        panic!("init log error: {e:?}");
    }

    // The rescue subcommand works on the configuration files directly so it is
    // usable when a configuration change is what broke the network. It runs
    // before the time service and before anything binds a port, so it does not
    // need DNS, the proxy or the web UI to be working.
    if let Some(LandscapeAction::Rescue(action)) = &args.action {
        run_rescue(action, &home_path, &config.store)
            .await
            .map_err(|e| StartupError::Config(e.to_string()))?;
        return Ok(());
    }

    // A configuration change that was never accepted must not survive a restart:
    // an uncommitted change that took the service down is exactly the case the
    // transaction exists for. Done before anything reads the configuration.
    rollback_uncommitted_change(&home_path, &config.store).await?;

    let time_service = SyncTimeService::start(config.time.clone());

    let mut init_config_to_import = init_config_to_import;
    if config.auto {
        if lock_exists || init_exists || db_exists {
            let mut reasons = vec![];
            if lock_exists {
                reasons
                    .push(format!("lock file ({}) exists", landscape_common::INIT_LOCK_FILE_NAME));
            }
            if init_exists {
                reasons.push(format!("init toml ({}) exists", landscape_common::INIT_FILE_NAME));
            }
            if db_exists {
                reasons.push(format!(
                    "database ({}) exists",
                    landscape_common::LANDSCAPE_DB_SQLITE_NAME
                ));
            }
            tracing::info!("Auto init skipped: {}.", reasons.join(", "));
        } else {
            do_auto_init(&home_path, &config).await?;
            init_config_to_import = None;
        }
    }

    banner(&config);

    if let Some(action) = &args.action {
        match action {
            LandscapeAction::Db { action, rollback, times } => match action {
                Some(DbAction::Rollback) => {
                    landscape_database::provider::rollback_interactive(&config.store)
                        .await
                        .map_err(StartupError::from)
                }
                None if *rollback || times.is_some() => {
                    tracing::warn!(
                        "Using deprecated step-based database action. Prefer `landscape db rollback`."
                    );
                    landscape_database::provider::db_action(
                        &config.store,
                        rollback,
                        &times.unwrap_or(1),
                    )
                    .await
                    .map_err(StartupError::from)
                }
                None => {
                    eprintln!(
                        "No database action selected. Use `landscape db rollback` for interactive rollback."
                    );
                    Ok(())
                }
            },
            // Handled (and returned early) before this point.
            LandscapeAction::Config(_) => Ok(()),
            LandscapeAction::Rescue(_) => Ok(()),
        }
    } else {
        let db_store_provider =
            prepare_startup_init(&home_path, &config, init_config_to_import).await?;
        run_system(home_path, config, db_store_provider, time_service).await
    }
}

async fn do_auto_init(home_path: &PathBuf, config: &RuntimeConfig) -> Result<(), StartupError> {
    let mut interface_map = HashMap::new();
    let devs = landscape::get_all_devices().await;
    tracing::info!("Discovered {} total interfaces.", devs.len());
    for dev in devs {
        interface_map.insert(dev.name.clone(), dev);
    }

    let default_configs = landscape::gen_default_config(&interface_map);
    if default_configs.is_empty() {
        tracing::warn!("Auto init: no physical interfaces found.");
        return Ok(());
    }

    let db_store_provider = LandscapeDBServiceProvider::new(&config.store).await?;
    let store = db_store_provider.iface_store();
    for cfg in default_configs {
        store.upsert(cfg).await.unwrap();
    }

    // 创建 lock 文件 避免重复进行初始化
    write_init_lock(home_path)?;

    // 初始化 br_lan 的服务
    let dhcp_store = db_store_provider.dhcp_v4_server_store();
    dhcp_store.upsert(DHCPv4ServiceConfig::default()).await.unwrap();

    let route_lan_store = db_store_provider.route_lan_service_store();
    route_lan_store
        .upsert(RouteLanServiceConfig {
            iface_name: landscape_common::LANDSCAPE_DEFAULT_LAN_NAME.to_string(),
            enable: true,
            update_at: landscape_common::utils::time::get_f64_timestamp(),
            static_routes: None,
        })
        .await
        .unwrap();

    tracing::info!(
        "Auto init: bridge, IP, DHCP and Route services configuration saved to database."
    );
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    // Ctrl+C (SIGINT)
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
        tracing::info!("Received SIGINT (Ctrl+C)");
    };

    // systemctl stop (SIGTERM)
    let terminate = async {
        signal(SignalKind::terminate()).expect("failed to install SIGTERM handler").recv().await;
        tracing::info!("Received SIGTERM (systemctl stop)");
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received, starting graceful cleanup...");
}

/// NOT Found
async fn handle_404(web_root: PathBuf) -> impl IntoResponse {
    let path = web_root.join("index.html");
    if path.exists()
        && let Ok(content) = std::fs::read_to_string(path)
    {
        return (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "text/html")], content)
            .into_response();
    }
    (StatusCode::NOT_FOUND, "Not found").into_response()
}

fn banner(config: &RuntimeConfig) {
    let banner = format!(
        r#"
██╗      █████╗ ███╗   ██╗██████╗ ███████╗ ██████╗ █████╗ ██████╗ ███████╗
██║     ██╔══██╗████╗  ██║██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝
██║     ███████║██╔██╗ ██║██║  ██║███████╗██║     ███████║██████╔╝█████╗
██║     ██╔══██║██║╚██╗██║██║  ██║╚════██║██║     ██╔══██║██╔═══╝ ██╔══╝
███████╗██║  ██║██║ ╚████║██████╔╝███████║╚██████╗██║  ██║██║     ███████╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚══════╝

██████╗  ██████╗ ██╗   ██╗████████╗███████╗██████╗
██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝██║   ██║██║   ██║   ██║   █████╗  ██████╔╝
██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  ██╔══██╗
██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗██║  ██║
╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝ (v{version})

Landscape Router is licensed under the GPL-3.0 License

Github: https://github.com/ThisSeanZhang/landscape
Doc   : https://landscape.whileaway.dev
"#,
        version = VERSION
    );
    let config_str = config.to_string_summary();
    info!("{}{}", banner, config_str);
    if !config.log.log_output_in_terminal {
        // 当日志不在 terminal 直接展示时, 仅输出一些信息
        let banner = banner.bright_blue().bold();
        let config_str = config_str.green();
        println!("{}", banner);
        println!("{}", config_str);
    }
}
