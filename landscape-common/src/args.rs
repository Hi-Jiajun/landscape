use std::{net::IpAddr, path::PathBuf};

use clap::{Parser, Subcommand};
use once_cell::sync::Lazy;

use crate::LANDSCAPE_CONFIG_DIR_NAME;

pub static LAND_HOSTNAME: Lazy<String> = Lazy::new(|| {
    let hostname = hostname::get().expect("无法获取主机名");
    hostname.to_string_lossy().to_string()
});

pub static LAND_ARGS: Lazy<WebCommArgs> = Lazy::new(|| {
    dotenvy::dotenv().ok();
    if std::env::var_os("LANDSCAPE_IGNORE_CLI_ARGS").is_some() {
        // Test/embedded use: ignore the real argv (test harness filters etc.)
        // and parse from nothing, so env vars and defaults still apply.
        WebCommArgs::try_parse_from(std::iter::empty::<String>()).unwrap_or_default()
    } else {
        WebCommArgs::parse()
    }
});

pub static LAND_HOME_PATH: Lazy<PathBuf> = Lazy::new(|| {
    if let Some(path) = &LAND_ARGS.config_dir {
        path.clone()
    } else {
        let Some(path) = homedir::my_home().unwrap() else {
            panic!("can not get home path");
        };
        path.join(LANDSCAPE_CONFIG_DIR_NAME)
    }
});

#[derive(Parser, Debug, Clone, Default)]
#[command(version, about, long_about = None)]
pub struct WebCommArgs {
    /// Static HTML location [default: /root/.landscape-router/static]
    #[arg(short, long, env = "LANDSCAPE_WEB_ROOT")]
    pub web: Option<PathBuf>,

    /// Listen HTTP port [default: 6300]
    #[arg(short, long, env = "LANDSCAPE_WEB_HTTP_PORT")]
    pub port: Option<u16>,

    /// Listen HTTPS port [default: 6443]
    #[arg(short = 's', long = "https", env = "LANDSCAPE_WEB_HTTPS_PORT")]
    pub https_port: Option<u16>,

    /// Listen address [default: 0.0.0.0]
    #[arg(short, long, env = "LANDSCAPE_WEB_ADDR")]
    pub address: Option<IpAddr>,

    /// Controls whether the WAN IP can be used to access the management interface [default: false]
    #[arg(short, long)]
    pub export_manager: bool,

    /// All Config DIR, Not file Path [default: /root/.landscape-router]
    #[clap(short, long, env = "LANDSCAPE_CONF_PATH")]
    pub config_dir: Option<PathBuf>,

    /// Log File location [default: /root/.landscape-router/logs]
    #[clap(long = "log_path", env = "LANDSCAPE_LOG_PATH")]
    pub log_path: Option<PathBuf>,

    /// Database URL, SQLite Connect Like Default
    /// sqlite://<path>
    /// [default: sqlite:///root/.landscape-router/landscape_db.sqlite]
    #[clap(long = "db_url", env = "DATABASE_URL")]
    pub database_path: Option<String>,

    /// ebpf map space
    /// [default: default]
    #[clap(long, env = "LANDSCAPE_EBPF_MAP_SPACE", default_value = "default")]
    pub ebpf_map_space: String,

    /// Manager user [default: root]
    #[clap(long = "user", env = "LANDSCAPE_ADMIN_USER")]
    pub admin_user: Option<String>,

    /// Manager pass [default: root]
    #[clap(long = "pass", env = "LANDSCAPE_ADMIN_PASS")]
    pub admin_pass: Option<String>,

    /// Debug mode [default: false]
    #[arg(long, env = "LANDSCAPE_DEBUG")]
    pub debug: Option<bool>,

    /// Try native XDP attach. By default, only TC (SKB) mode is used.
    /// If specified without values, attempts native XDP on all interfaces.
    /// Specify comma-separated ifindex list to try native XDP only on those interfaces (e.g., 3,5).
    #[arg(long = "try-xdp", visible_alias = "txdp", value_delimiter = ',', num_args = 0..)]
    pub try_native_xdp: Option<Vec<i32>>,

    /// Log output location [default: false]
    #[arg(short = 'o', long, env = "LANDSCAPE_LOG_TERMINAL")]
    pub log_output_in_terminal: Option<bool>,

    /// Max log files number
    /// [default: 7]
    #[arg(long, env = "LANDSCAPE_LOG_FILE_LIMIT")]
    pub max_log_files: Option<usize>,

    /// Log keyword filter: comma-separated list of keywords
    /// When specified, only ERROR/WARN logs and logs containing any keyword are shown
    /// [example: --log-filter dhcp,dns,firewall]
    #[arg(long, value_delimiter = ',', env = "LANDSCAPE_LOG_FILTER")]
    pub log_filter: Vec<String>,

    /// Auto init Default Net [default: false]
    #[arg(long, env = "LANDSCAPE_AUTO")]
    pub auto: bool,

    #[command(subcommand)]
    pub action: Option<LandscapeAction>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum LandscapeAction {
    /// Database-related operations
    Db {
        #[command(subcommand)]
        action: Option<DbAction>,

        #[arg(short, long, hide = true)]
        rollback: bool,

        #[clap(short = 't', long, hide = true)]
        times: Option<u32>,
    },

    /// Generate a landscape_init.toml from high-level deployment options
    Config(Box<crate::config::cli::ConfigCliArgs>),

    /// Versioned configuration snapshots and rollback to one
    ///
    /// Works without the service running, so it is usable when a configuration
    /// change has made the network unusable.
    #[command(subcommand)]
    Rescue(RescueAction),
}

#[derive(Subcommand, Debug, Clone)]
pub enum RescueAction {
    /// Copy the current configuration into a new snapshot
    Snapshot {
        /// Free-form label, e.g. `before-tproxy-change`
        #[arg(short, long)]
        label: Option<String>,
        /// How many snapshots to keep, oldest removed first
        #[arg(long, default_value_t = 20)]
        keep: usize,
    },
    /// List the snapshots that can be restored
    List,
    /// Replace the live configuration with a snapshot's
    ///
    /// Stop the service first: the database file is replaced, which is only safe
    /// with nothing holding it open.
    Restore {
        /// Snapshot id, as shown by `rescue list`
        id: String,
    },
    /// Restore the most recent snapshot
    Rollback,

    /// Mark a configuration change as provisional
    ///
    /// Snapshots the current configuration and records a deadline. Unless
    /// `rescue commit` runs before it, the snapshot is restored — including on the
    /// next start, so a change that took the service down is undone rather than
    /// left in place.
    Begin {
        /// Free-form label, e.g. `tproxy-port-change`
        #[arg(short, long)]
        label: Option<String>,
        /// Seconds to accept the change before rolling it back
        #[arg(long, default_value_t = 120)]
        timeout: u64,
    },
    /// Accept the provisional change
    Commit,
    /// Give up the provisional change and restore the snapshot it started from
    Discard,
    /// Show whether a change is currently provisional
    Status,

    /// Let one device through for a bounded time
    ///
    /// The last resort of the rescue channel: instead of turning the strict scope
    /// off for everybody, one device is placed in the given flow until the time is
    /// up. The grant is removed automatically, and the reason is recorded.
    Authorize {
        /// Device MAC address, e.g. `aa:bb:cc:dd:ee:ff`
        #[arg(long)]
        mac: String,
        /// Flow to place the device in while the grant lasts
        #[arg(long)]
        flow_id: u32,
        /// Minutes until the grant expires
        #[arg(long, default_value_t = 30)]
        minutes: u64,
        /// Why the device is being let through (kept in the audit trail)
        #[arg(short, long, default_value = "operator rescue")]
        reason: String,
    },
    /// List the device grants that are still in force
    Grants {
        /// Include grants that have already expired
        #[arg(long)]
        all: bool,
    },
    /// Remove a device grant before its time is up
    Revoke {
        /// Grant id, as shown by `rescue grants`
        id: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum DbAction {
    /// Interactively roll back the database to a registered release boundary
    #[command(visible_alias = "rb")]
    Rollback,
}

#[derive(Debug, Clone)]
pub struct WebConfig {
    pub web_root: PathBuf,

    pub port: u16,

    pub address: IpAddr,
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub log_path: PathBuf,
    pub debug: bool,
    pub log_output_in_terminal: bool,
    pub max_log_files: usize,
}
