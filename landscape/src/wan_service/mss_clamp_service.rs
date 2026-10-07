use std::sync::Arc;

use landscape_common::database::error::DbError;
use landscape_common::database::store::ConfigStore;
use landscape_common::ebpf::DataplaneGuard;
use landscape_common::event::hub::IfaceEventReader;
use landscape_common::{
    concurrency::{spawn_task, task_label},
    event::hub::iface::IfaceObserverAction,
    service::{
        ServiceHandle, ServiceStatus,
        controller::{ConfigStoreController, ConfigStoreServiceController},
        manager::{ServiceManager, ServiceStarterTrait},
    },
    wan_service::mss_clamp::MSSClampServiceConfig,
    wan_service::mss_clamp::dataplane::MssClampDataplane,
    wan_service::mtu_chamber::{MtuChamberDataplane, MtuChamberSettings},
};
use landscape_database::{
    mss_clamp::repository::MssClampServiceRepository, provider::LandscapeDBServiceProvider,
};

use crate::get_iface_by_name;
use crate::wan_service::mtu_chamber_env::{MtuChamberEnv, bring_up as bring_up_mtu_chamber};

/// The chamber's half of a run: the capability, and what this interface asked
/// for. Kept together so the run function stays about the interface instead of
/// about the feature's plumbing.
#[derive(Clone)]
pub struct ChamberSetup {
    dataplane: Arc<dyn MtuChamberDataplane>,
    settings: Option<MtuChamberSettings>,
}

#[derive(Clone)]
pub struct MssClampService {
    dataplane: Arc<dyn MssClampDataplane>,
    /// The chamber rides this service's lifecycle: it belongs to the same
    /// interface, and the clamp is what makes it unnecessary for TCP.
    chamber: Arc<dyn MtuChamberDataplane>,
}

#[async_trait::async_trait]
impl ServiceStarterTrait for MssClampService {
    type Config = MSSClampServiceConfig;

    async fn start(&self, config: MSSClampServiceConfig) -> ServiceHandle {
        let service_status = ServiceHandle::new();

        if config.enable {
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                // 契约:返回前进入 Staring,任务内直接 Staring → Running/Stop
                service_status.just_change_status(ServiceStatus::Staring);
                let iface_name = config.iface_name.clone();
                let dataplane = self.dataplane.clone();
                let chamber_dataplane = self.chamber.clone();
                let chamber_settings = config.mtu_chamber.clone();
                let spawn_status = service_status.clone();
                let task_status = service_status.clone();
                spawn_status.spawn_task_with_resource(
                    task_label::task::MSS_CLAMP_RUN,
                    iface_name.clone(),
                    async move {
                        run_mss_clamp(
                            iface_name,
                            iface.index as i32,
                            config.clamp_size,
                            iface.mac.is_some(),
                            task_status,
                            dataplane,
                            ChamberSetup {
                                dataplane: chamber_dataplane,
                                settings: chamber_settings,
                            },
                        )
                        .await
                    },
                );
            } else {
                tracing::error!("Interface {} not found", config.iface_name);
                service_status.just_change_status(ServiceStatus::Staring);
                service_status.just_change_status(ServiceStatus::Failed);
            }
        } else {
            service_status.just_change_status(ServiceStatus::Disabled);
        }

        service_status
    }
}

pub async fn run_mss_clamp(
    iface_name: String,
    ifindex: i32,
    mtu_size: u16,
    has_mac: bool,
    service_status: ServiceHandle,
    dataplane: Arc<dyn MssClampDataplane>,
    chamber: ChamberSetup,
) {
    let ChamberSetup {
        dataplane: chamber_dataplane,
        settings: chamber_settings,
    } = chamber;
    let mss_clamp = match dataplane.attach(ifindex as u32, mtu_size, has_mac) {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start mss clamp for {iface_name}: {err}");
            service_status.just_change_status(ServiceStatus::Stop);
            return;
        }
    };
    let mut guards: Vec<Box<dyn DataplaneGuard>> = vec![mss_clamp];

    // The egress MTU stage. Attached with this service rather than with the
    // chamber, so the counters that say what the egress cannot carry exist
    // whether or not anything is done about it: an oversize count of zero is only
    // meaningful if the thing that counts it is running.
    match crate::wan_service::mtu_chamber_env::read_iface_mtu(&iface_name).await {
        Some(egress_mtu) => {
            match chamber_dataplane.attach_stage(ifindex as u32, egress_mtu, has_mac) {
                Ok(guard) => guards.push(guard),
                Err(err) => tracing::error!(
                    "failed to attach the egress MTU stage for {iface_name} (mtu {egress_mtu}): \
                     {err}; the oversize counters are blind and no packet is diverted"
                ),
            }
        }
        None => tracing::error!(
            "cannot read the MTU of {iface_name}: the egress MTU stage is not attached, so the \
             oversize counters are blind"
        ),
    };

    // The chamber, if one is configured for this interface. Brought up before the
    // datapath is told about it, and the divert is written last - by the gate - so
    // there is no window where a packet is sent somewhere nothing validates.
    let mut chamber_env: Option<MtuChamberEnv> = None;
    if let Some(settings) = chamber_settings {
        match bring_up_mtu_chamber(&iface_name, ifindex as u32, &settings).await {
            Ok(env) => {
                let wiring = env.wiring(settings.ttl_ms, settings.burst);
                match chamber_dataplane.attach_return_gate(env.veth_main_ifindex, wiring) {
                    Ok(gate) => {
                        tracing::info!(
                            "IPv6 Packet Too Big chamber is up for {iface_name}: {}",
                            env.describe()
                        );
                        guards.push(gate);
                        chamber_env = Some(env);
                    }
                    Err(err) => {
                        // The namespace exists but nothing validates what comes
                        // back from it, so it must not stay. Dropping it removes
                        // it, and the divert was never enabled.
                        tracing::error!(
                            "not enabling the IPv6 Packet Too Big chamber for {iface_name}: the \
                             return gate could not be attached: {err}"
                        );
                        drop(env);
                    }
                }
            }
            Err(err) => tracing::error!(
                "not enabling the IPv6 Packet Too Big chamber for {iface_name}: {err}"
            ),
        }
    }

    service_status.just_change_status(ServiceStatus::Running);
    tracing::info!("Waiting for external stop signal");
    service_status.stop_token().cancelled().await;
    tracing::info!("Received external stop signal");

    // Gates first: each disables the divert it wrote, then detaches. The
    // namespace they pointed at goes last.
    drop(guards);
    drop(chamber_env);

    service_status.just_change_status(ServiceStatus::Stop);
}

#[derive(Clone)]
pub struct MssClampServiceManagerService {
    store: MssClampServiceRepository,
    service: ServiceManager<MssClampService>,
}

#[async_trait::async_trait]
impl ConfigStoreController for MssClampServiceManagerService {
    type Id = String;
    type Config = MSSClampServiceConfig;
    type Store = MssClampServiceRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }
}

impl ConfigStoreServiceController for MssClampServiceManagerService {
    type H = MssClampService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }
}

impl MssClampServiceManagerService {
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: IfaceEventReader,
        dataplane: Arc<dyn MssClampDataplane>,
        chamber: Arc<dyn MtuChamberDataplane>,
    ) -> Result<Self, DbError> {
        let store = store_service.mss_clamp_service_store();
        let service =
            ServiceManager::init(store.list().await?, MssClampService { dataplane, chamber }).await;

        let service_clone = service.clone();
        spawn_task(task_label::task::MSS_CLAMP_OBSERVER, async move {
            while let Some(msg) = dev_observer.recv_skipping_lag().await {
                match msg {
                    IfaceObserverAction::Up(iface_name) => {
                        tracing::info!("restart {iface_name} Firewall service");
                        let service_config = if let Some(service_config) =
                            store.find_by_id(iface_name.clone()).await.unwrap()
                        {
                            service_config
                        } else {
                            continue;
                        };

                        let _ = service_clone.update_service(service_config).await;
                    }
                    IfaceObserverAction::Down(_) => {}
                }
            }
        });

        let store = store_service.mss_clamp_service_store();
        Ok(Self { service, store })
    }
}
