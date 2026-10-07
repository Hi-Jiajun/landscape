use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use landscape_common::proxy::{ProxyPluginConfig, ProxyRuntimeInfo, ProxySubscription};
use landscape_common::service::ServiceStatus;
use serde_json::json;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

pub mod dns_guard;
pub mod leak_guard;
pub mod tproxy;

pub use landscape_common::proxy::{TproxyDeliveryStatus, TproxyTargetStatus};
pub use tproxy::TproxyDelivery;

/// Upper bound for one subscription payload, enforced while the body is being
/// read (not after it has been fully buffered).
const MAX_SUBSCRIPTION_BYTES: usize = 32 * 1024 * 1024;

/// How long a single `/version` readiness probe may take.
const READINESS_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// `<file>.tmp` next to `path` (same filesystem, so the rename is atomic).
fn tmp_sibling(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Write `bytes` to `path` via a sibling temp file + rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = tmp_sibling(path);
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Is `pid` a live (non-zombie) process?
///
/// `kill(pid, 0)` alone reports success for zombies, which made `stop()` sit
/// out its whole 2s grace period and fire a needless SIGKILL. The state byte of
/// `/proc/<pid>/stat` ("pid (comm) STATE ...") disambiguates.
fn process_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            // `comm` may contain spaces and parentheses, so parse what follows
            // the last ')'.
            let state =
                stat.rsplit_once(')').and_then(|(_, rest)| rest.trim_start().chars().next());
            state != Some('Z')
        }
        // /proc unavailable (non-Linux or a permission quirk): keep the old
        // kill(0) based answer.
        Err(_) => true,
    }
}

/// Read a response body while enforcing a hard byte limit.
///
/// The limit is applied per chunk, so a chunked response without
/// `Content-Length` (or a lying one) can never be buffered past `limit`.
async fn read_body_capped(
    mut resp: reqwest::Response,
    limit: usize,
    what: &str,
) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length()
        && len > limit as u64
    {
        return Err(format!("{what} is {len} bytes, exceeding the {limit} byte limit"));
    }

    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) =
        resp.chunk().await.map_err(|e| format!("failed while reading {what}: {e}"))?
    {
        if body.len() + chunk.len() > limit {
            return Err(format!(
                "{what} exceeded the {limit} byte limit and was aborted mid-stream"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn url_path_encode(input: &str) -> String {
    let mut encoded = String::new();
    for byte in input.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

#[derive(Clone)]
pub struct LandscapeProxyService {
    home_path: PathBuf,
    config: Arc<RwLock<ProxyPluginConfig>>,
    child_pid: Arc<RwLock<Option<u32>>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    engine_version: Arc<RwLock<Option<String>>>,
    shutting_down: Arc<RwLock<bool>>,
    /// Serializes start/stop/restart so the watchdog, the API and config saves
    /// can never race two engine launches (which used to allow double spawns
    /// and cross-killing of freshly started instances).
    op_lock: Arc<Mutex<()>>,
    /// Owns the kernel TPROXY fabric that delivers `LocalTproxy` flows to this
    /// plugin's transparent listeners.
    tproxy: Arc<TproxyDelivery>,
    /// Blocks the DNS paths that bypass the managed resolver.
    dns_guard: Arc<dns_guard::DnsLeakGuard>,
    http_client: reqwest::Client,
}

impl LandscapeProxyService {
    /// Build the service.
    ///
    /// `dns_guard_dataplane` is the datapath half of the DNS leak guard. It is
    /// passed in rather than reached for globally because the guard cannot work
    /// through netfilter alone: a direct flow is forwarded in TC before netfilter
    /// runs, so the decision has to be programmed into the datapath maps.
    pub async fn new(
        home_path: PathBuf,
        dns_guard_dataplane: Arc<dyn landscape_common::proxy::dataplane::DnsGuardDataplane>,
    ) -> Self {
        let proxy_dir = home_path.join("proxy");
        let _ = fs::create_dir_all(&proxy_dir);
        let _ = fs::create_dir_all(proxy_dir.join("providers"));
        let _ = fs::create_dir_all(home_path.join("logs"));

        let config_path = proxy_dir.join("config.json");
        let initial_config = if config_path.exists() {
            match fs::read_to_string(&config_path) {
                Ok(content) => {
                    serde_json::from_str::<ProxyPluginConfig>(&content).unwrap_or_default()
                }
                Err(_) => ProxyPluginConfig::default(),
            }
        } else {
            let default_cfg = ProxyPluginConfig::default();
            if let Ok(content) = serde_json::to_string_pretty(&default_cfg) {
                let _ = fs::write(&config_path, content);
            }
            default_cfg
        };

        let service = Self {
            home_path,
            config: Arc::new(RwLock::new(initial_config.clone())),
            child_pid: Arc::new(RwLock::new(None)),
            start_time: Arc::new(RwLock::new(None)),
            engine_version: Arc::new(RwLock::new(None)),
            shutting_down: Arc::new(RwLock::new(false)),
            op_lock: Arc::new(Mutex::new(())),
            tproxy: Arc::new(TproxyDelivery::new(
                initial_config.manage_tproxy_delivery,
                initial_config.tproxy_missing_listener,
            )),
            dns_guard: dns_guard::DnsLeakGuard::new(dns_guard_dataplane),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        };

        // If explicitly enabled in stored config, attempt cold start
        if initial_config.enable {
            let svc_clone = service.clone();
            tokio::spawn(async move {
                if let Err(e) = svc_clone.start().await {
                    warn!("Proxy service auto-start failed: {e}");
                }
            });
        }

        // Watchdog: keep the engine alive while the service is enabled. It runs
        // in its own task so subscription downloads (which can block on the
        // network for a long time) never delay health supervision.
        let svc_watchdog = service.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
            let mut tproxy_tick = 0u32;
            loop {
                ticker.tick().await;
                let (enabled, is_stopping) = {
                    let cfg = svc_watchdog.config.read().await;
                    let stopping = *svc_watchdog.shutting_down.read().await;
                    (cfg.enable, stopping)
                };
                if enabled && !is_stopping && !svc_watchdog.is_running().await {
                    warn!("Proxy engine is not running while enabled, watchdog auto-recovering...");
                    if let Err(e) = svc_watchdog.start().await {
                        warn!("Watchdog failed to recover proxy engine: {e}");
                    }
                }

                // Periodically re-derive the kernel TProxy fabric. Reconcile is
                // a no-op while nothing changed, but it repairs drift (a
                // leftover writer, a flushed chain, a rebooted rules loader)
                // without needing another config change.
                tproxy_tick += 1;
                if tproxy_tick >= 60 {
                    tproxy_tick = 0;
                    if enabled && !is_stopping {
                        svc_watchdog.tproxy.activate().await;
                    }
                }
            }
        });

        // Subscription scheduler: every tick (300s) refresh whatever is due.
        let svc_scheduler = service.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(300));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let (enabled, subs) = {
                    let cfg = svc_scheduler.config.read().await;
                    (cfg.enable, cfg.subscriptions.clone())
                };
                if !enabled || subs.is_empty() {
                    continue;
                }
                let now = chrono::Utc::now().timestamp() as f64;
                for sub in subs {
                    if !sub.enabled || sub.url.is_empty() {
                        continue;
                    }
                    let interval_secs = (sub.update_interval_hours as f64) * 3600.0;
                    let should_update = match sub.last_updated_at {
                        None => true,
                        Some(last) => (now - last) >= interval_secs,
                    };
                    if should_update {
                        info!(
                            "Proxy subscription scheduler: auto-refreshing '{}' (ID: {})...",
                            sub.name, sub.id
                        );
                        if let Err(e) = svc_scheduler.refresh_subscription(sub.id).await {
                            warn!(
                                "Proxy subscription scheduler: failed to refresh '{}': {e}",
                                sub.name
                            );
                        }
                    }
                }
            }
        });

        service
    }

    fn config_path(&self) -> PathBuf {
        self.home_path.join("proxy").join("config.json")
    }

    fn proxy_dir(&self) -> PathBuf {
        self.home_path.join("proxy")
    }

    fn generated_config_path(&self) -> PathBuf {
        self.proxy_dir().join("generated_config.json")
    }

    /// PID of the engine process we own, used for precise orphan cleanup.
    fn engine_pid_file(&self) -> PathBuf {
        self.proxy_dir().join("engine.pid")
    }

    fn engine_log_file(&self) -> PathBuf {
        self.home_path.join("logs").join("proxy.log")
    }

    pub async fn get_config(&self) -> ProxyPluginConfig {
        self.config.read().await.clone()
    }

    /// Kernel-side state of the local TProxy delivery fabric, for status/UI and
    /// drift detection.
    pub async fn tproxy_status(&self) -> TproxyDeliveryStatus {
        self.tproxy.status().await
    }

    /// Kernel state of the DNS leak guard.
    pub async fn dns_guard_status(&self) -> landscape_common::proxy::DnsGuardStatus {
        self.dns_guard.status().await
    }

    /// Apply the DNS leak guard from the current configuration.
    ///
    /// Called whenever the configuration is saved and at startup, so the kernel
    /// follows the configuration rather than being toggled by hand.
    pub async fn apply_dns_guard(&self) {
        let config = self.config.read().await.dns_guard.clone();
        self.dns_guard.set_config(&config);
        self.dns_guard.apply().await;
    }

    /// Borrow the delivery fabric so the flow service can publish the
    /// `flow_id -> listener port` mapping it owns.
    pub fn tproxy_delivery(&self) -> Arc<TproxyDelivery> {
        self.tproxy.clone()
    }

    /// Replace the whole configuration (last writer wins, e.g. `PUT /proxy/config`).
    ///
    /// The file is written to a sibling temporary file and renamed into place so
    /// a crash can never leave a truncated `config.json` behind.
    pub async fn replace_config(&self, new_config: ProxyPluginConfig) -> Result<(), String> {
        let managed_before = self.config.read().await.manage_tproxy_delivery;
        let content = serde_json::to_string_pretty(&new_config)
            .map_err(|e| format!("Failed to serialize config: {e}"))?;
        write_atomic(&self.config_path(), content.as_bytes())
            .map_err(|e| format!("Failed to write config file: {e}"))?;
        self.tproxy
            .set_policy(new_config.manage_tproxy_delivery, new_config.tproxy_missing_listener);
        let management_turned_off = managed_before && !new_config.manage_tproxy_delivery;
        *self.config.write().await = new_config;
        if management_turned_off {
            // The operator switched our management off: the rules we own have to
            // go, otherwise turning the feature off leaves redirects behind.
            self.tproxy.teardown().await;
        }
        // The DNS guard follows the configuration the same way: applied when
        // saved, removed when turned off.
        self.apply_dns_guard().await;
        Ok(())
    }

    /// Apply a targeted mutation under the configuration write lock, so that a
    /// concurrent enable/disable or subscription edit is never clobbered by a
    /// stale read-modify-write snapshot.
    pub async fn update_config<F>(&self, mutate: F) -> Result<(), String>
    where
        F: FnOnce(&mut ProxyPluginConfig),
    {
        let mut guard = self.config.write().await;
        let managed_before = guard.manage_tproxy_delivery;
        let mut next = guard.clone();
        mutate(&mut next);
        let content = serde_json::to_string_pretty(&next)
            .map_err(|e| format!("Failed to serialize config: {e}"))?;
        write_atomic(&self.config_path(), content.as_bytes())
            .map_err(|e| format!("Failed to write config file: {e}"))?;
        self.tproxy.set_policy(next.manage_tproxy_delivery, next.tproxy_missing_listener);
        let management_turned_off = managed_before && !next.manage_tproxy_delivery;
        *guard = next;
        drop(guard);
        if management_turned_off {
            self.tproxy.teardown().await;
        }
        self.apply_dns_guard().await;
        Ok(())
    }

    pub async fn save_config(&self, new_config: ProxyPluginConfig) -> Result<(), String> {
        let was_enabled = self.config.read().await.enable;
        self.replace_config(new_config.clone()).await?;

        if new_config.enable {
            // Restart or start with new config
            self.restart().await?;
        } else if was_enabled {
            // Transitioned to disabled: cleanly stop and free all resources
            self.stop().await?;
        }
        if !new_config.enable {
            // The listeners are gone, so the redirect rules must go too:
            // leaving them behind would black-hole every flow that targets them.
            self.tproxy.teardown().await;
        }

        Ok(())
    }

    pub async fn toggle(&self, enable: bool) -> Result<ServiceStatus, String> {
        let was_enabled = self.config.read().await.enable;
        self.update_config(|cfg| cfg.enable = enable).await?;

        if enable {
            self.restart().await?;
        } else if was_enabled {
            self.stop().await?;
        }
        if !enable {
            self.tproxy.teardown().await;
        }
        Ok(self.status().await.status)
    }

    pub async fn find_engine_binary(&self) -> Result<PathBuf, String> {
        let cfg = self.config.read().await;
        if let Some(ref p) = cfg.engine_path {
            let path = PathBuf::from(p);
            if path.exists() {
                return Ok(path);
            }
        }

        // Standard locations
        let candidates =
            ["/usr/local/bin/mihomo", "/usr/bin/mihomo", "/usr/local/bin/meow", "/usr/bin/meow"];
        for candidate in candidates {
            let path = PathBuf::from(candidate);
            if path.exists() {
                return Ok(path);
            }
        }

        Err("Proxy engine binary (mihomo / meow) not found on system".to_string())
    }

    pub async fn is_running(&self) -> bool {
        let pid_opt = *self.child_pid.read().await;
        if let Some(pid) = pid_opt { process_alive(pid as i32) } else { false }
    }

    pub async fn status(&self) -> ProxyRuntimeInfo {
        let running = self.is_running().await;
        let pid = if running { *self.child_pid.read().await } else { None };
        let uptime = if running {
            self.start_time.read().await.map(|t| t.elapsed().as_secs()).unwrap_or(0)
        } else {
            0
        };

        let mut mem_bytes = 0u64;
        let cpu_pct = 0.0f32;
        if let Some(p) = pid
            && let Ok(statm) = fs::read_to_string(format!("/proc/{p}/statm"))
        {
            let parts: Vec<&str> = statm.split_whitespace().collect();
            if parts.len() >= 2
                && let Ok(pages) = parts[1].parse::<u64>()
            {
                mem_bytes = pages * 4096;
            }
        }

        let cfg = self.config.read().await;
        let total_nodes: usize = cfg.subscriptions.iter().map(|s| s.node_count).sum();

        ProxyRuntimeInfo {
            status: if running {
                ServiceStatus::Running
            } else if !cfg.enable {
                ServiceStatus::Disabled
            } else {
                ServiceStatus::Stop
            },
            pid,
            memory_bytes: mem_bytes,
            cpu_percent: cpu_pct,
            uptime_seconds: uptime,
            engine_version: self.engine_version.read().await.clone(),
            tproxy_port: cfg.tproxy_port,
            mixed_port: cfg.mixed_port,
            api_port: cfg.api_port,
            total_nodes,
            subscriptions_count: cfg.subscriptions.len(),
        }
    }

    /// Start the engine. Serialized with `stop`/`restart` so concurrent callers
    /// (watchdog, API, config save) can never launch two engines at once.
    pub async fn start(&self) -> Result<(), String> {
        let _op = self.op_lock.lock().await;
        self.start_locked().await
    }

    async fn start_locked(&self) -> Result<(), String> {
        if !self.config.read().await.enable {
            return Err("proxy engine is disabled; enable the service first".to_string());
        }
        if self.is_running().await {
            return Ok(());
        }

        let binary = self.find_engine_binary().await?;

        // Query version. Bounded, because a hung `-v` used to stall startup.
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::process::Command::new(&binary).arg("-v").output(),
        )
        .await
        {
            Ok(Ok(out)) => {
                let ver = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !ver.is_empty() {
                    *self.engine_version.write().await = Some(ver);
                }
            }
            Ok(Err(e)) => warn!("Failed to query proxy engine version: {e}"),
            Err(_) => warn!("Timed out after 5s while querying the proxy engine version"),
        }

        // Generate JSON configuration
        let cfg = self.config.read().await.clone();
        let generated_json = self.render_engine_config(&cfg)?;
        let json_str = serde_json::to_string_pretty(&generated_json)
            .map_err(|e| format!("Failed to serialize generated engine config: {e}"))?;
        write_atomic(&self.generated_config_path(), json_str.as_bytes())
            .map_err(|e| format!("Failed to write generated engine config: {e}"))?;

        let log_file = self.engine_log_file();
        let stdout_file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .map_err(|e| format!("Failed to open log file: {e}"))?;
        let stderr_file =
            stdout_file.try_clone().map_err(|e| format!("Failed to clone log file: {e}"))?;

        // Reclaim an engine orphaned by a previous run. Ownership is verified
        // against /proc (binary + our proxy dir) instead of a regex `pkill -f`
        // that could match unrelated processes or a just-started replacement.
        self.cleanup_orphan_engine(&binary).await;

        info!(
            "Starting proxy engine: {} -d {} -f {}",
            binary.display(),
            self.proxy_dir().display(),
            self.generated_config_path().display()
        );

        let mut child = tokio::process::Command::new(&binary)
            .arg("-d")
            .arg(self.proxy_dir())
            .arg("-f")
            .arg(self.generated_config_path())
            .stdout(stdout_file)
            .stderr(stderr_file)
            .spawn()
            .map_err(|e| format!("Failed to spawn proxy process: {e}"))?;

        let child_id =
            child.id().ok_or_else(|| "Failed to obtain child process PID".to_string())?;
        *self.child_pid.write().await = Some(child_id);
        *self.start_time.write().await = Some(Instant::now());
        if let Err(e) = fs::write(self.engine_pid_file(), format!("{child_id}\n")) {
            warn!("Failed to record proxy engine pid file: {e}");
        }

        // Spawn monitor for child process exit. The PID comparison keeps a
        // delayed monitor from clearing the PID of an engine started later.
        let child_pid_clone = self.child_pid.clone();
        let start_time_clone = self.start_time.clone();
        tokio::spawn(async move {
            let status = child.wait().await;
            info!("Proxy engine process exited with status: {status:?}");
            let mut cur = child_pid_clone.write().await;
            if *cur == Some(child_id) {
                *cur = None;
                *start_time_clone.write().await = None;
            }
        });

        // Readiness probe: per-request timeout plus a bounded overall deadline,
        // and the API secret is applied so an authenticated controller is not
        // misreported as "not ready".
        let api_url = format!("http://127.0.0.1:{}/version", cfg.api_port);
        let api_secret = cfg.api_secret.clone();
        let healthy = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            for _ in 0..15 {
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                let mut req = self.http_client.get(&api_url);
                if !api_secret.trim().is_empty() {
                    req = req.header("Authorization", format!("Bearer {api_secret}"));
                }
                if let Ok(Ok(resp)) =
                    tokio::time::timeout(READINESS_PROBE_TIMEOUT, req.send()).await
                    && resp.status().is_success()
                {
                    return true;
                }
            }
            false
        })
        .await
        .unwrap_or(false);

        if !healthy {
            warn!(
                "Proxy engine controller API did not respond within timeout, process may still be initializing"
            );
        } else {
            info!("Proxy engine successfully started and external controller is online");
        }

        // The listeners are up (or about to be): make sure the kernel redirects
        // every flow that targets one of them. Idempotent, so a plain restart
        // does not rewrite the ruleset.
        self.tproxy.activate().await;

        // The DNS guard is independent of the engine, so it is applied here too:
        // a restart must not leave the encrypted-DNS path open because the guard
        // was only ever applied when the configuration was saved.
        self.apply_dns_guard().await;

        Ok(())
    }

    /// Terminate an engine left over from a previous run, if (and only if) the
    /// PID recorded in our own pid file still refers to an engine started with
    /// our proxy directory.
    async fn cleanup_orphan_engine(&self, binary: &Path) {
        let pid_file = self.engine_pid_file();
        let Ok(raw) = fs::read_to_string(&pid_file) else {
            return;
        };
        let Ok(pid) = raw.trim().parse::<i32>() else {
            let _ = fs::remove_file(&pid_file);
            return;
        };
        if pid <= 0 {
            let _ = fs::remove_file(&pid_file);
            return;
        }
        if let Some(current) = *self.child_pid.read().await
            && current as i32 == pid
        {
            return;
        }

        let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else {
            // Process is gone (or /proc is unavailable): nothing to reclaim.
            let _ = fs::remove_file(&pid_file);
            return;
        };
        let cmd = String::from_utf8_lossy(&cmdline).replace('\0', " ");
        let binary_name = binary.file_name().and_then(|n| n.to_str()).unwrap_or("mihomo");
        let belongs_to_us = (cmd.contains(binary_name)
            || cmd.contains(&binary.display().to_string()))
            && cmd.contains(&self.proxy_dir().display().to_string());
        if !belongs_to_us {
            warn!(
                "Ignoring stale proxy pid file: pid {pid} is not an engine for this proxy directory"
            );
            let _ = fs::remove_file(&pid_file);
            return;
        }

        warn!("Reclaiming orphaned proxy engine from a previous run (PID: {pid})...");
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        for _ in 0..10 {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            if !process_alive(pid) {
                break;
            }
        }
        if process_alive(pid) {
            warn!("Orphaned proxy engine did not exit gracefully, sending SIGKILL...");
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        let _ = fs::remove_file(&pid_file);
    }

    pub async fn stop(&self) -> Result<(), String> {
        let _op = self.op_lock.lock().await;
        self.stop_locked().await
    }

    async fn stop_locked(&self) -> Result<(), String> {
        *self.shutting_down.write().await = true;
        let pid_opt = *self.child_pid.read().await;
        if let Some(pid) = pid_opt {
            info!("Stopping proxy engine (PID: {pid})...");
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }

            // Wait up to 2 seconds for process to exit
            for _ in 0..20 {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                if !process_alive(pid as i32) {
                    let mut cur = self.child_pid.write().await;
                    if *cur == Some(pid) {
                        *cur = None;
                        *self.start_time.write().await = None;
                    }
                    let _ = fs::remove_file(self.engine_pid_file());
                    *self.shutting_down.write().await = false;
                    info!("Proxy engine cleanly stopped");
                    return Ok(());
                }
            }

            // Force kill if not exited
            warn!("Proxy engine did not exit gracefully, sending SIGKILL...");
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
            let mut cur = self.child_pid.write().await;
            if *cur == Some(pid) {
                *cur = None;
                *self.start_time.write().await = None;
            }
            let _ = fs::remove_file(self.engine_pid_file());
        }
        *self.shutting_down.write().await = false;

        Ok(())
    }

    /// Restart under a single lifecycle lock so a concurrent watchdog/API call
    /// cannot interleave its own stop/start between ours.
    pub async fn restart(&self) -> Result<(), String> {
        let _op = self.op_lock.lock().await;
        self.stop_locked().await?;
        self.start_locked().await
    }

    fn render_engine_config(&self, cfg: &ProxyPluginConfig) -> Result<serde_json::Value, String> {
        let mut providers = serde_json::Map::new();
        let mut provider_names = Vec::new();

        for sub in &cfg.subscriptions {
            if !sub.enabled {
                continue;
            }
            let key = format!("sub_{}", sub.id.simple());
            provider_names.push(key.clone());

            let provider_entry = json!({
                "type": "http",
                "url": sub.url,
                "path": format!("providers/{}.yaml", sub.id),
                // saturating: a hostile/typo'd interval must not wrap around in
                // release builds (or panic in debug builds).
                "interval": sub.update_interval_hours.saturating_mul(3600),
                "health-check": {
                    "enable": true,
                    "interval": 300,
                    "url": "http://www.gstatic.com/generate_204"
                }
            });
            providers.insert(key, provider_entry);
        }

        let mut groups = Vec::new();
        for grp in &cfg.groups {
            let mut proxies = grp.proxies.clone();
            if proxies.is_empty() {
                proxies.push("DIRECT".to_string());
            }

            let mut grp_obj = serde_json::Map::new();
            grp_obj.insert("name".to_string(), json!(grp.name));
            grp_obj.insert("type".to_string(), json!(grp.group_type));
            grp_obj.insert("proxies".to_string(), json!(proxies));
            if !provider_names.is_empty() {
                grp_obj.insert("use".to_string(), json!(provider_names));
            }
            if let Some(ref url) = grp.url {
                grp_obj.insert("url".to_string(), json!(url));
            }
            if let Some(interval) = grp.interval {
                grp_obj.insert("interval".to_string(), json!(interval));
            }
            groups.push(serde_json::Value::Object(grp_obj));
        }

        let mut listeners_arr = Vec::new();
        let mut active_listeners = if cfg.listeners.is_empty() {
            landscape_common::proxy::default_listeners()
        } else {
            cfg.listeners.clone()
        };
        // Auto-augment any missing default listeners (such as DNS tunnels or new flow ports)
        let default_lis = landscape_common::proxy::default_listeners();
        for def in default_lis {
            if !active_listeners.iter().any(|l| l.port == def.port || l.name == def.name) {
                active_listeners.push(def);
            }
        }

        let default_match_group = cfg
            .groups
            .iter()
            .find(|g| g.name == "🚀 节点选择")
            .map(|g| g.name.clone())
            .or_else(|| cfg.groups.first().map(|g| g.name.clone()))
            .unwrap_or_else(|| "DIRECT".to_string());

        for lis in active_listeners {
            let mut lis_obj = serde_json::Map::new();
            lis_obj.insert("name".to_string(), json!(lis.name));
            lis_obj.insert("type".to_string(), json!(lis.listener_type));
            lis_obj.insert("port".to_string(), json!(lis.port));
            if let Some(ref p) = lis.proxy {
                let valid_proxy =
                    if p == "DIRECT" || p == "REJECT" || cfg.groups.iter().any(|g| &g.name == p) {
                        p.clone()
                    } else {
                        default_match_group.clone()
                    };
                lis_obj.insert("proxy".to_string(), json!(valid_proxy));
            }
            if let Some(ref t) = lis.target {
                lis_obj.insert("target".to_string(), json!(t));
            }
            if let Some(ref net) = lis.network {
                lis_obj.insert("network".to_string(), json!(net));
            } else if lis.listener_type == "tunnel" {
                lis_obj.insert("network".to_string(), json!(vec!["tcp", "udp"]));
            }
            listeners_arr.push(serde_json::Value::Object(lis_obj));
        }

        let mut root_obj = serde_json::Map::new();
        root_obj.insert("tproxy-port".to_string(), json!(cfg.tproxy_port));
        root_obj.insert("mixed-port".to_string(), json!(cfg.mixed_port));
        let controller_host =
            if cfg.api_secret.trim().is_empty() { "127.0.0.1" } else { "0.0.0.0" };
        root_obj.insert(
            "external-controller".to_string(),
            json!(format!("{controller_host}:{}", cfg.api_port)),
        );
        root_obj.insert("secret".to_string(), json!(cfg.api_secret));
        root_obj.insert("mode".to_string(), json!(cfg.mode));
        root_obj.insert("log-level".to_string(), json!(cfg.log_level));
        root_obj.insert("allow-lan".to_string(), json!(true));
        root_obj.insert("bind-address".to_string(), json!("*"));
        root_obj.insert("unified-delay".to_string(), json!(true));
        root_obj.insert("tcp-concurrent".to_string(), json!(true));
        root_obj.insert("ipv6".to_string(), json!(false));
        root_obj.insert("find-process-mode".to_string(), json!("off"));
        root_obj.insert(
            "profile".to_string(),
            json!({
                "store-selected": true,
                "store-fake-ip": false
            }),
        );
        root_obj.insert(
            "dns".to_string(),
            json!({
                "enable": true,
                "ipv6": false,
                "enhanced-mode": "normal",
                "nameserver": [
                    "223.5.5.5",
                    "119.29.29.29"
                ]
            }),
        );
        if let Some(ref ui_path) = cfg.external_ui {
            let p = std::path::Path::new(ui_path);
            if p.is_relative() {
                root_obj.insert("external-ui".to_string(), json!(ui_path));
            } else if p.exists() {
                let proxy_dir = self.home_path.join("proxy");
                let symlink_path = proxy_dir.join("ui");
                if symlink_path.is_symlink() || symlink_path.exists() {
                    let _ = std::fs::remove_file(&symlink_path);
                }
                #[cfg(unix)]
                let _ = std::os::unix::fs::symlink(ui_path, &symlink_path);
                root_obj.insert("external-ui".to_string(), json!("ui"));
            }
        }
        root_obj.insert("listeners".to_string(), json!(listeners_arr));
        root_obj.insert("proxies".to_string(), json!(cfg.custom_nodes));
        root_obj.insert("proxy-providers".to_string(), json!(providers));
        root_obj.insert("proxy-groups".to_string(), json!(groups));
        root_obj.insert("rules".to_string(), json!([format!("MATCH,{}", default_match_group)]));

        Ok(serde_json::Value::Object(root_obj))
    }

    pub async fn add_subscription(
        &self,
        name: String,
        url: String,
    ) -> Result<ProxySubscription, String> {
        let sub = ProxySubscription {
            id: Uuid::new_v4(),
            name,
            url,
            enabled: true,
            update_interval_hours: 24,
            last_updated_at: None,
            node_count: 0,
        };

        let sub_id = sub.id;
        let enabled = self.config.read().await.enable;
        self.update_config(|cfg| cfg.subscriptions.push(sub.clone())).await?;

        // A brand new provider only becomes visible to the engine after a
        // reload/restart, so apply the configuration we just stored.
        if enabled {
            self.restart().await?;
        }

        // Attempt initial download in background
        let this = self.clone();
        tokio::spawn(async move {
            let _ = this.refresh_subscription(sub_id).await;
        });

        Ok(sub)
    }

    pub async fn delete_subscription(&self, id: Uuid) -> Result<(), String> {
        let enabled = self.config.read().await.enable;
        let path = self.proxy_dir().join("providers").join(format!("{id}.yaml"));
        let _ = fs::remove_file(path);
        self.update_config(|cfg| cfg.subscriptions.retain(|s| s.id != id)).await?;
        if enabled {
            self.restart().await?;
        }
        Ok(())
    }

    pub async fn refresh_subscription(&self, id: Uuid) -> Result<usize, String> {
        let (url, name) = {
            let cfg = self.config.read().await;
            let sub =
                cfg.subscriptions.iter().find(|s| s.id == id).ok_or("Subscription not found")?;
            (sub.url.clone(), sub.name.clone())
        };

        info!("Fetching subscription '{}' from {}", name, url);
        let resp = match self
            .http_client
            .get(&url)
            .header("User-Agent", "ClashMeta/v1.19.0 (Landscape Router)")
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r,
            direct_err => {
                // If direct download failed and proxy core is running, attempt download through local proxy
                let is_running = self.is_running().await;
                let cfg = self.config.read().await.clone();
                let mut fallback_resp = None;
                if is_running {
                    let proxy_addr = format!("http://127.0.0.1:{}", cfg.mixed_port);
                    if let Ok(proxy) = reqwest::Proxy::all(&proxy_addr)
                        && let Ok(proxy_client) = reqwest::Client::builder()
                            .proxy(proxy)
                            .timeout(std::time::Duration::from_secs(15))
                            .build()
                    {
                        warn!(
                            "Direct subscription download failed, attempting via local proxy: {proxy_addr}"
                        );
                        if let Ok(p_resp) = proxy_client
                            .get(&url)
                            .header("User-Agent", "ClashMeta/v1.19.0 (Landscape Router)")
                            .send()
                            .await
                            && p_resp.status().is_success()
                        {
                            fallback_resp = Some(p_resp);
                        }
                    }
                }
                match fallback_resp {
                    Some(r) => r,
                    None => match direct_err {
                        Ok(r) => {
                            return Err(format!(
                                "Subscription download returned HTTP {}",
                                r.status()
                            ));
                        }
                        Err(e) => return Err(format!("Failed to download subscription: {e}")),
                    },
                }
            }
        };

        // Hard limit enforced *while* reading, so a chunked/oversized response
        // cannot exhaust the gateway's memory before the length is checked.
        let raw = read_body_capped(resp, MAX_SUBSCRIPTION_BYTES, "subscription payload").await?;
        if raw.is_empty() {
            return Err("Subscription download returned an empty body".to_string());
        }
        let body = String::from_utf8_lossy(&raw).into_owned();
        let sub_file = self.proxy_dir().join("providers").join(format!("{id}.yaml"));
        write_atomic(&sub_file, &raw)
            .map_err(|e| format!("Failed to save subscription file: {e}"))?;

        // Estimate node count
        let count = body
            .lines()
            .filter(|l| {
                let trimmed = l.trim_start();
                trimmed.starts_with("- name:") || trimmed.starts_with("name:")
            })
            .count();

        // Update stored metadata only (never restarts the engine, and never
        // clobbers a concurrent enable/disable or subscription edit).
        let now = chrono::Utc::now().timestamp() as f64;
        self.update_config(|cfg| {
            if let Some(sub) = cfg.subscriptions.iter_mut().find(|s| s.id == id) {
                sub.node_count = count;
                sub.last_updated_at = Some(now);
            }
        })
        .await?;

        // If controller is running, trigger provider reload and report a
        // non-2xx answer instead of silently claiming success.
        let cfg = self.config.read().await;
        if self.is_running().await {
            let provider_name = format!("sub_{}", id.simple());
            let reload_url =
                format!("http://127.0.0.1:{}/providers/proxies/{}", cfg.api_port, provider_name);
            let mut req = self.http_client.put(&reload_url);
            if !cfg.api_secret.is_empty() {
                req = req.header("Authorization", format!("Bearer {}", cfg.api_secret));
            }
            match req.send().await {
                Ok(resp) if resp.status().is_success() => {}
                Ok(resp) => warn!(
                    "Proxy provider '{provider_name}' reload returned HTTP {}; the engine may still serve the previous node list",
                    resp.status()
                ),
                Err(e) => warn!("Failed to reload proxy provider '{provider_name}': {e}"),
            }
        }

        info!("Subscription '{}' refreshed successfully, detected {} nodes", name, count);
        Ok(count)
    }

    pub async fn get_proxies_from_controller(&self) -> Result<serde_json::Value, String> {
        let cfg = self.config.read().await;
        let url = format!("http://127.0.0.1:{}/proxies", cfg.api_port);
        let mut req = self.http_client.get(&url);
        if !cfg.api_secret.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", cfg.api_secret));
        }
        let resp = req.send().await.map_err(|e| format!("Failed to query proxies: {e}"))?;

        let body_text =
            resp.text().await.map_err(|e| format!("Failed to read proxies body: {e}"))?;
        serde_json::from_str::<serde_json::Value>(&body_text)
            .map_err(|e| format!("Failed to parse response: {e}"))
    }

    pub async fn test_node_delay(&self, name: &str, test_url: Option<&str>) -> Result<u64, String> {
        let cfg = self.config.read().await;
        let encoded_name = url_path_encode(name);
        let target_url = test_url.unwrap_or("http://www.gstatic.com/generate_204");
        let encoded_target_url =
            url::form_urlencoded::byte_serialize(target_url.as_bytes()).collect::<String>();
        let url = format!(
            "http://127.0.0.1:{}/proxies/{}/delay?timeout=5000&url={}",
            cfg.api_port, encoded_name, encoded_target_url
        );

        let mut req = self.http_client.get(&url);
        if !cfg.api_secret.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", cfg.api_secret));
        }
        let resp = req.send().await.map_err(|e| format!("Delay test request failed: {e}"))?;

        let body_text = resp.text().await.map_err(|e| format!("Invalid delay response: {e}"))?;
        let data: serde_json::Value =
            serde_json::from_str(&body_text).map_err(|e| format!("Failed to parse JSON: {e}"))?;

        if let Some(delay) = data.get("delay").and_then(|v| v.as_u64()) {
            Ok(delay)
        } else if let Some(msg) = data.get("message").and_then(|v| v.as_str()) {
            Err(msg.to_string())
        } else {
            Err("Unknown response from proxy core".to_string())
        }
    }

    pub async fn select_group_node(&self, group: &str, node: &str) -> Result<(), String> {
        let cfg = self.config.read().await;
        let encoded_group = url_path_encode(group);
        let url = format!("http://127.0.0.1:{}/proxies/{}", cfg.api_port, encoded_group);
        let body = json!({ "name": node });
        let body_str = serde_json::to_string(&body).map_err(|e| e.to_string())?;

        let mut req =
            self.http_client.put(&url).header("Content-Type", "application/json").body(body_str);
        if !cfg.api_secret.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", cfg.api_secret));
        }
        let resp = req.send().await.map_err(|e| format!("Select node request failed: {e}"))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("Select node returned HTTP {}", resp.status()))
        }
    }
}
