use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use landscape_common::proxy::{
    ProxyPluginConfig, ProxyRuntimeInfo, ProxySubscription,
};
use landscape_common::service::ServiceStatus;
use serde_json::json;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

fn url_encode(input: &str) -> String {
    url::form_urlencoded::byte_serialize(input.as_bytes()).collect()
}

#[derive(Clone)]
pub struct LandscapeProxyService {
    home_path: PathBuf,
    config: Arc<RwLock<ProxyPluginConfig>>,
    child_pid: Arc<RwLock<Option<u32>>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    engine_version: Arc<RwLock<Option<String>>>,
    http_client: reqwest::Client,
}

impl LandscapeProxyService {
    pub async fn new(home_path: PathBuf) -> Self {
        let proxy_dir = home_path.join("proxy");
        let _ = fs::create_dir_all(&proxy_dir);
        let _ = fs::create_dir_all(proxy_dir.join("providers"));
        let _ = fs::create_dir_all(home_path.join("logs"));

        let config_path = proxy_dir.join("config.json");
        let initial_config = if config_path.exists() {
            match fs::read_to_string(&config_path) {
                Ok(content) => serde_json::from_str::<ProxyPluginConfig>(&content).unwrap_or_default(),
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

    pub async fn get_config(&self) -> ProxyPluginConfig {
        self.config.read().await.clone()
    }

    pub async fn save_config(&self, new_config: ProxyPluginConfig) -> Result<(), String> {
        let content = serde_json::to_string_pretty(&new_config)
            .map_err(|e| format!("Failed to serialize config: {e}"))?;
        fs::write(self.config_path(), content)
            .map_err(|e| format!("Failed to write config file: {e}"))?;

        let was_enabled = self.config.read().await.enable;
        *self.config.write().await = new_config.clone();

        if new_config.enable {
            // Restart or start with new config
            self.restart().await?;
        } else if was_enabled {
            // Transitioned to disabled: cleanly stop and free all resources
            self.stop().await?;
        }

        Ok(())
    }

    pub async fn toggle(&self, enable: bool) -> Result<ServiceStatus, String> {
        let mut cfg = self.config.read().await.clone();
        cfg.enable = enable;
        self.save_config(cfg).await?;
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
        let candidates = [
            "/usr/local/bin/mihomo",
            "/usr/bin/mihomo",
            "/usr/local/bin/meow",
            "/usr/bin/meow",
        ];
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
        if let Some(pid) = pid_opt {
            unsafe { libc::kill(pid as i32, 0) == 0 }
        } else {
            false
        }
    }

    pub async fn status(&self) -> ProxyRuntimeInfo {
        let running = self.is_running().await;
        let pid = if running { *self.child_pid.read().await } else { None };
        let uptime = if running {
            self.start_time
                .read()
                .await
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0)
        } else {
            0
        };

        let mut mem_bytes = 0u64;
        let cpu_pct = 0.0f32;
        if let Some(p) = pid {
            if let Ok(statm) = fs::read_to_string(format!("/proc/{p}/statm")) {
                let parts: Vec<&str> = statm.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(pages) = parts[1].parse::<u64>() {
                        mem_bytes = pages * 4096;
                    }
                }
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

    pub async fn start(&self) -> Result<(), String> {
        if self.is_running().await {
            return Ok(());
        }

        let binary = self.find_engine_binary().await?;

        // Query version
        if let Ok(out) = tokio::process::Command::new(&binary).arg("-v").output().await {
            let ver = String::from_utf8_lossy(&out.stdout).trim().to_string();
            *self.engine_version.write().await = Some(ver);
        }

        // Generate JSON configuration
        let cfg = self.config.read().await.clone();
        let generated_json = self.render_engine_config(&cfg)?;
        fs::write(self.generated_config_path(), serde_json::to_string_pretty(&generated_json).unwrap())
            .map_err(|e| format!("Failed to write generated engine config: {e}"))?;

        let log_file = self.home_path.join("logs").join("proxy.log");
        let stdout_file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .map_err(|e| format!("Failed to open log file: {e}"))?;
        let stderr_file = stdout_file.try_clone().map_err(|e| format!("Failed to clone log file: {e}"))?;

        info!("Starting proxy engine: {} -d {} -f {}", binary.display(), self.proxy_dir().display(), self.generated_config_path().display());

        let mut child = tokio::process::Command::new(&binary)
            .arg("-d")
            .arg(self.proxy_dir())
            .arg("-f")
            .arg(self.generated_config_path())
            .stdout(stdout_file)
            .stderr(stderr_file)
            .spawn()
            .map_err(|e| format!("Failed to spawn proxy process: {e}"))?;

        let child_id = child.id().ok_or_else(|| "Failed to obtain child process PID".to_string())?;
        *self.child_pid.write().await = Some(child_id);
        *self.start_time.write().await = Some(Instant::now());

        // Spawn watchdog for this child process
        let child_pid_clone = self.child_pid.clone();
        let start_time_clone = self.start_time.clone();
        tokio::spawn(async move {
            let status = child.wait().await;
            info!("Proxy engine process exited with status: {status:?}");
            *child_pid_clone.write().await = None;
            *start_time_clone.write().await = None;
        });

        // Wait up to 3 seconds for external controller to respond
        let api_url = format!("http://127.0.0.1:{}/version", cfg.api_port);
        let mut healthy = false;
        for _ in 0..15 {
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            if let Ok(resp) = self.http_client.get(&api_url).send().await {
                if resp.status().is_success() {
                    healthy = true;
                    break;
                }
            }
        }

        if !healthy {
            warn!("Proxy engine controller API did not respond within timeout, process may still be initializing");
        } else {
            info!("Proxy engine successfully started and external controller is online");
        }

        Ok(())
    }

    pub async fn stop(&self) -> Result<(), String> {
        let pid_opt = *self.child_pid.read().await;
        if let Some(pid) = pid_opt {
            info!("Stopping proxy engine (PID: {pid})...");
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }

            // Wait up to 2 seconds for process to exit
            for _ in 0..20 {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                let alive = unsafe { libc::kill(pid as i32, 0) == 0 };
                if !alive {
                    *self.child_pid.write().await = None;
                    *self.start_time.write().await = None;
                    info!("Proxy engine cleanly stopped");
                    return Ok(());
                }
            }

            // Force kill if not exited
            warn!("Proxy engine did not exit gracefully, sending SIGKILL...");
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
            *self.child_pid.write().await = None;
            *self.start_time.write().await = None;
        }

        Ok(())
    }

    pub async fn restart(&self) -> Result<(), String> {
        self.stop().await?;
        self.start().await?;
        Ok(())
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
                "interval": sub.update_interval_hours * 3600,
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
        let active_listeners = if cfg.listeners.is_empty() {
            landscape_common::proxy::default_listeners()
        } else {
            cfg.listeners.clone()
        };
        for lis in active_listeners {
            let mut lis_obj = serde_json::Map::new();
            lis_obj.insert("name".to_string(), json!(lis.name));
            lis_obj.insert("type".to_string(), json!(lis.listener_type));
            lis_obj.insert("port".to_string(), json!(lis.port));
            if let Some(ref p) = lis.proxy {
                lis_obj.insert("proxy".to_string(), json!(p));
            }
            listeners_arr.push(serde_json::Value::Object(lis_obj));
        }

        let root = json!({
            "tproxy-port": cfg.tproxy_port,
            "mixed-port": cfg.mixed_port,
            "external-controller": format!("127.0.0.1:{}", cfg.api_port),
            "secret": cfg.api_secret,
            "mode": cfg.mode,
            "log-level": cfg.log_level,
            "allow-lan": true,
            "bind-address": "*",
            "unified-delay": true,
            "tcp-concurrent": true,
            "ipv6": false,
            "find-process-mode": "off",
            "profile": {
                "store-selected": true,
                "store-fake-ip": false
            },
            "dns": {
                "enable": true,
                "ipv6": false,
                "enhanced-mode": "normal",
                "nameserver": [
                    "223.5.5.5",
                    "119.29.29.29"
                ]
            },
            "listeners": listeners_arr,
            "proxies": cfg.custom_nodes,
            "proxy-providers": providers,
            "proxy-groups": groups,
            "rules": [
                "MATCH,🚀 节点选择"
            ]
        });

        Ok(root)
    }

    pub async fn add_subscription(&self, name: String, url: String) -> Result<ProxySubscription, String> {
        let sub = ProxySubscription {
            id: Uuid::new_v4(),
            name,
            url,
            enabled: true,
            update_interval_hours: 24,
            last_updated_at: None,
            node_count: 0,
        };

        let mut cfg = self.config.read().await.clone();
        cfg.subscriptions.push(sub.clone());
        self.save_config(cfg).await?;

        // Attempt initial download in background
        let this = self.clone();
        let sub_id = sub.id;
        tokio::spawn(async move {
            let _ = this.refresh_subscription(sub_id).await;
        });

        Ok(sub)
    }

    pub async fn delete_subscription(&self, id: Uuid) -> Result<(), String> {
        let mut cfg = self.config.read().await.clone();
        cfg.subscriptions.retain(|s| s.id != id);
        let path = self.proxy_dir().join("providers").join(format!("{id}.yaml"));
        let _ = fs::remove_file(path);
        self.save_config(cfg).await?;
        Ok(())
    }

    pub async fn refresh_subscription(&self, id: Uuid) -> Result<usize, String> {
        let (url, name) = {
            let cfg = self.config.read().await;
            let sub = cfg.subscriptions.iter().find(|s| s.id == id).ok_or("Subscription not found")?;
            (sub.url.clone(), sub.name.clone())
        };

        info!("Fetching subscription '{}' from {}", name, url);
        let resp = self.http_client
            .get(&url)
            .header("User-Agent", "ClashMeta/v1.19.0 (Landscape Router)")
            .send()
            .await
            .map_err(|e| format!("Failed to download subscription: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("Subscription download returned HTTP {}", resp.status()));
        }

        let body = resp.text().await.map_err(|e| format!("Failed to read body: {e}"))?;
        let sub_file = self.proxy_dir().join("providers").join(format!("{id}.yaml"));
        fs::write(&sub_file, &body).map_err(|e| format!("Failed to save subscription file: {e}"))?;

        // Estimate node count
        let count = body.lines().filter(|l| {
            let trimmed = l.trim_start();
            trimmed.starts_with("- name:") || trimmed.starts_with("name:")
        }).count();

        // Update stored metadata
        let now = chrono::Utc::now().timestamp() as f64;
        {
            let mut cfg = self.config.read().await.clone();
            if let Some(sub) = cfg.subscriptions.iter_mut().find(|s| s.id == id) {
                sub.node_count = count;
                sub.last_updated_at = Some(now);
            }
            let _ = self.save_config(cfg).await;
        }

        // If controller is running, trigger provider reload
        let cfg = self.config.read().await;
        if self.is_running().await {
            let provider_name = format!("sub_{}", id.simple());
            let reload_url = format!("http://127.0.0.1:{}/providers/proxies/{}", cfg.api_port, provider_name);
            let _ = self.http_client
                .put(&reload_url)
                .header("Authorization", format!("Bearer {}", cfg.api_secret))
                .send()
                .await;
        }

        info!("Subscription '{}' refreshed successfully, detected {} nodes", name, count);
        Ok(count)
    }

    pub async fn get_proxies_from_controller(&self) -> Result<serde_json::Value, String> {
        let cfg = self.config.read().await;
        let url = format!("http://127.0.0.1:{}/proxies", cfg.api_port);
        let resp = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", cfg.api_secret))
            .send()
            .await
            .map_err(|e| format!("Failed to query proxies: {e}"))?;

        let body_text = resp.text().await.map_err(|e| format!("Failed to read proxies body: {e}"))?;
        serde_json::from_str::<serde_json::Value>(&body_text)
            .map_err(|e| format!("Failed to parse response: {e}"))
    }

    pub async fn test_node_delay(&self, name: &str, test_url: Option<&str>) -> Result<u64, String> {
        let cfg = self.config.read().await;
        let encoded_name = url_encode(name);
        let target_url = test_url.unwrap_or("http://www.gstatic.com/generate_204");
        let url = format!(
            "http://127.0.0.1:{}/proxies/{}/delay?timeout=5000&url={}",
            cfg.api_port, encoded_name, url_encode(target_url)
        );

        let resp = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", cfg.api_secret))
            .send()
            .await
            .map_err(|e| format!("Delay test request failed: {e}"))?;

        let body_text = resp.text().await.map_err(|e| format!("Invalid delay response: {e}"))?;
        let data: serde_json::Value = serde_json::from_str(&body_text)
            .map_err(|e| format!("Failed to parse JSON: {e}"))?;

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
        let encoded_group = url_encode(group);
        let url = format!("http://127.0.0.1:{}/proxies/{}", cfg.api_port, encoded_group);
        let body = json!({ "name": node });
        let body_str = serde_json::to_string(&body).map_err(|e| e.to_string())?;

        let resp = self.http_client
            .put(&url)
            .header("Authorization", format!("Bearer {}", cfg.api_secret))
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await
            .map_err(|e| format!("Select node request failed: {e}"))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("Select node returned HTTP {}", resp.status()))
        }
    }
}
