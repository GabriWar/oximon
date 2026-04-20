use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use oximon::config::Config;
use oximon::db::Db;
use oximon::intensive;
use oximon::ipc::{self, Cmd as IpcCmd, CommandEnvelope, Reply, Target};
use oximon::model::{Device, EventKind, Port};
use oximon::notify;
use oximon::oui::OuiDb;
use oximon::paths;
use oximon::scan::ArpScanner;
use oximon::tray::{OximonTray, TrayAction};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Semaphore, broadcast, mpsc};

#[derive(Parser, Debug)]
#[command(name = "oximond", about = "oximon daemon + control")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Command>,

    // run args (used when no subcommand given)
    #[arg(short, long, default_value_t = 60)]
    interval: u64,
    #[arg(long)]
    iface: Option<String>,
    #[arg(long)]
    subnet: Option<String>,
    #[arg(long)]
    no_notify: bool,
    #[arg(long)]
    once: bool,
    #[arg(long, default_value_t = 16)]
    intensive_workers: usize,
    #[arg(long, default_value_t = 1500)]
    arp_window_ms: u64,
    #[arg(long, default_value_t = 3)]
    arp_passes: u32,
    #[arg(long)]
    map_path: Option<std::path::PathBuf>,
    #[arg(long)]
    no_tray: bool,
    /// http bind host (127.0.0.1 local-only, 0.0.0.0 open)
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// http bind port
    #[arg(long, default_value_t = 3737)]
    port: u16,
    /// disable http server
    #[arg(long)]
    no_http: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// run the daemon (also default if no subcommand)
    Run,
    /// trigger intensive scan on a device or all connected
    Intensive {
        /// target mac
        #[arg(long)]
        mac: Option<String>,
        /// target ip
        #[arg(long)]
        ip: Option<String>,
        /// scan every connected device
        #[arg(long)]
        all: bool,
        /// scan all 65535 ports (slow). only valid w/ --mac or --ip
        #[arg(long)]
        full_ports: bool,
    },
    /// mute notifications
    Mute,
    /// unmute notifications
    Unmute,
    /// toggle notification mute
    ToggleMute,
    /// query daemon status
    Status,
    /// force a rescan now
    Rescan,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.cmd.as_ref() {
        None | Some(Command::Run) => run_daemon(cli).await,
        Some(Command::Intensive { mac, ip, all, full_ports }) => {
            if *all && *full_ports {
                anyhow::bail!("--full-ports cannot combine with --all (must be targeted)");
            }
            let target = if *all {
                Target::All
            } else if let Some(m) = mac {
                Target::Mac { mac: m.to_lowercase() }
            } else if let Some(i) = ip {
                Target::Ip { ip: i.clone() }
            } else {
                anyhow::bail!("specify --mac, --ip, or --all");
            };
            client_cmd(IpcCmd::Intensive { target, full_ports: *full_ports }).await
        }
        Some(Command::Mute) => client_cmd(IpcCmd::Mute).await,
        Some(Command::Unmute) => client_cmd(IpcCmd::Unmute).await,
        Some(Command::ToggleMute) => client_cmd(IpcCmd::ToggleMute).await,
        Some(Command::Status) => client_cmd(IpcCmd::Status).await,
        Some(Command::Rescan) => client_cmd(IpcCmd::Rescan).await,
    }
}

async fn client_cmd(cmd: IpcCmd) -> Result<()> {
    let reply = ipc::send_cmd(&cmd).await?;
    if let Some(m) = reply.msg {
        println!("{m}");
    }
    if let Some(d) = reply.data {
        println!("{}", serde_json::to_string_pretty(&d)?);
    }
    if !reply.ok {
        std::process::exit(1);
    }
    Ok(())
}

async fn run_daemon(args: Cli) -> Result<()> {
    let cfg = Config {
        scan_interval_secs: args.interval,
        intensive_refresh_hours: 24,
        iface: args.iface.clone(),
        subnet: args.subnet.clone(),
        notify: !args.no_notify,
        ..Config::default()
    };

    let db_path = paths::state_db()?;
    tracing::info!(path = %db_path.display(), "opening db");
    let db = Arc::new(Mutex::new(Db::open(&db_path)?));

    let oui_path = paths::oui_csv()?;
    let oui_max_age = Duration::from_secs(cfg.oui_max_age_days * 86400);
    let oui = tokio::task::spawn_blocking(move || OuiDb::load_or_fetch(&oui_path, oui_max_age))
        .await?
        .unwrap_or_else(|e| {
            tracing::warn!(?e, "oui db unavailable, vendors blank");
            OuiDb::empty()
        });
    let oui = Arc::new(oui);

    let scanner = Arc::new(
        ArpScanner::autodetect(cfg.iface.as_deref(), cfg.subnet.as_deref())
            .context("arp scanner init (need CAP_NET_RAW)")?,
    );
    let iface_name = scanner.iface_name().to_string();
    tracing::info!(
        iface = %iface_name,
        hosts = scanner.subnet_size(),
        "scanner ready"
    );

    let notify_on = Arc::new(AtomicBool::new(cfg.notify));
    let arp_scanning = Arc::new(AtomicBool::new(false));
    let intensive_inflight = Arc::new(AtomicUsize::new(0));
    let map_path = args
        .map_path
        .clone()
        .unwrap_or_else(|| paths::data_dir().ok().unwrap_or_default().join("map.html"));
    tracing::info!(path = %map_path.display(), "map output");

    // live broadcast for WS clients
    let (live_tx, _) = broadcast::channel::<String>(64);

    // map regen + WS broadcast debounce channel
    let (map_tx, mut map_rx) = mpsc::channel::<()>(32);
    {
        let db = db.clone();
        let path = map_path.clone();
        let iface = iface_name.clone();
        let live_tx = live_tx.clone();
        let arp_flag = arp_scanning.clone();
        let inflight = intensive_inflight.clone();
        tokio::spawn(async move {
            while map_rx.recv().await.is_some() {
                while map_rx.try_recv().is_ok() {}
                let db_c = db.clone();
                let path = path.clone();
                let iface = iface.clone();
                let live_tx = live_tx.clone();
                let progress = oximon::html::Progress {
                    arp_scanning: arp_flag.load(Ordering::Relaxed),
                    intensive_inflight: inflight.load(Ordering::Relaxed),
                };
                let _ = tokio::task::spawn_blocking(move || {
                    write_map_now(&db_c, &path, &iface, progress);
                    let snap = {
                        let db = db_c.lock().unwrap();
                        oximon::html::build_snapshot(&db, &iface, progress)
                    };
                    let _ = live_tx.send(snap);
                })
                .await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });
    }

    // intensive worker pool
    let (intensive_tx, mut intensive_rx) = mpsc::channel::<(String, String, bool)>(1024);
    let intensive_sem = Arc::new(Semaphore::new(args.intensive_workers.max(1)));
    {
        let db = db.clone();
        let notify_flag = notify_on.clone();
        let sem = intensive_sem.clone();
        let map_tx = map_tx.clone();
        let inflight = intensive_inflight.clone();
        tokio::spawn(async move {
            while let Some((mac, ip, full_ports)) = intensive_rx.recv().await {
                let permit = match sem.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let db_c = db.clone();
                let notify_flag = notify_flag.clone();
                let map_tx = map_tx.clone();
                let inflight = inflight.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let mac_c = mac.clone();
                    let ip_c = ip.clone();
                    let opts = intensive::Options { full_ports };
                    let res =
                        tokio::task::spawn_blocking(move || intensive::run_with(&mac_c, &ip_c, opts))
                            .await;
                    match res {
                        Ok(Ok(r)) => {
                            let now = Utc::now();
                            let os = r.os_guess.clone();
                            {
                                let mut db = db_c.lock().unwrap();
                                if let Err(e) = db.replace_ports(&mac, &r.ports) {
                                    tracing::warn!(?e, "replace_ports fail");
                                }
                                if let Err(e) = db.set_intensive_done(&mac, now, os.as_deref()) {
                                    tracing::warn!(?e, "set_intensive_done fail");
                                }
                                if let Err(e) =
                                    db.insert_event(&mac, EventKind::IntensiveDone, now, None)
                                {
                                    tracing::warn!(?e, "insert_event fail");
                                }
                            }
                            if notify_flag.load(Ordering::Relaxed) {
                                let dev = {
                                    let db = db_c.lock().unwrap();
                                    db.get_device(&mac).ok().flatten()
                                };
                                if let Some(d) = dev {
                                    notify::emit_detached(EventKind::IntensiveDone, d);
                                }
                            }
                            tracing::info!(mac=%mac, ports=r.ports.len(), os=?os, "intensive done");
                        }
                        Ok(Err(e)) => tracing::warn!(?e, mac=%mac, "intensive failed"),
                        Err(e) => tracing::warn!(?e, mac=%mac, "intensive join err"),
                    }
                    inflight.fetch_sub(1, Ordering::Relaxed);
                    let _ = map_tx.try_send(());
                });
            }
        });
    }

    // ipc server
    let (ipc_tx, mut ipc_rx) = mpsc::channel::<CommandEnvelope>(64);
    let sock_path = ipc::socket_path();
    {
        let sock_path = sock_path.clone();
        tokio::spawn(async move {
            if let Err(e) = ipc::serve(&sock_path, ipc_tx).await {
                tracing::error!(?e, "ipc serve err");
            }
        });
    }

    // tray
    let (tray_tx, mut tray_rx) = mpsc::unbounded_channel::<TrayAction>();
    let tray_handle = if args.no_tray {
        None
    } else {
        match spawn_tray(tray_tx.clone(), iface_name.clone(), notify_on.clone()).await {
            Ok(h) => Some(h),
            Err(e) => {
                tracing::warn!(?e, "tray unavailable, continuing without");
                None
            }
        }
    };

    // rescan trigger
    let (rescan_tx, mut rescan_rx) = mpsc::channel::<()>(8);

    // http server
    if !args.no_http {
        let bind_host: std::net::IpAddr = args.host.parse().unwrap_or_else(|_| {
            tracing::warn!(host = %args.host, "invalid --host, falling back to 127.0.0.1");
            "127.0.0.1".parse().unwrap()
        });
        let addr = std::net::SocketAddr::new(bind_host, args.port);
        let app_state = oximon::http::AppState {
            db: db.clone(),
            intensive_tx: intensive_tx.clone(),
            rescan_tx: rescan_tx.clone(),
            notify_on: notify_on.clone(),
            iface: iface_name.clone(),
            live_tx: live_tx.clone(),
            arp_scanning: arp_scanning.clone(),
            intensive_inflight: intensive_inflight.clone(),
            map_tx: map_tx.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = oximon::http::serve(addr, app_state).await {
                tracing::error!(?e, "http serve err");
            }
        });
    }

    let interval = cfg.scan_interval();
    let mut interval_tick = tokio::time::interval(interval);
    interval_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let quit = Arc::new(AtomicBool::new(false));

    loop {
        tokio::select! {
            biased;

            _ = interval_tick.tick() => {
                if quit.load(Ordering::Relaxed) { break; }
                run_scan_tick(
                    scanner.clone(), db.clone(), oui.clone(), notify_on.clone(),
                    &map_path, &iface_name, args.arp_passes, args.arp_window_ms,
                    arp_scanning.clone(), map_tx.clone(),
                ).await;
                let _ = map_tx.try_send(());
                update_tray(&tray_handle, &db, &iface_name, notify_on.load(Ordering::Relaxed));
                if args.once { break; }
            }

            _ = rescan_rx.recv() => {
                run_scan_tick(
                    scanner.clone(), db.clone(), oui.clone(), notify_on.clone(),
                    &map_path, &iface_name, args.arp_passes, args.arp_window_ms,
                    arp_scanning.clone(), map_tx.clone(),
                ).await;
                let _ = map_tx.try_send(());
                update_tray(&tray_handle, &db, &iface_name, notify_on.load(Ordering::Relaxed));
            }

            Some(env) = ipc_rx.recv() => {
                let reply = handle_ipc(
                    env.cmd, &db, &intensive_tx, &notify_on, &rescan_tx, &iface_name,
                    &intensive_inflight, &map_tx,
                ).await;
                let _ = env.reply.send(reply);
                update_tray(&tray_handle, &db, &iface_name, notify_on.load(Ordering::Relaxed));
            }

            Some(act) = tray_rx.recv() => {
                match act {
                    TrayAction::ToggleMute => {
                        let prev = notify_on.fetch_xor(true, Ordering::Relaxed);
                        tracing::info!(muted = prev, "tray: toggle mute");
                    }
                    TrayAction::ScanAll => {
                        let all_connected: Vec<(String, String)> = {
                            let db = db.lock().unwrap();
                            db.all_devices().unwrap_or_default()
                                .into_iter()
                                .filter(|d| d.connected)
                                .map(|d| (d.mac, d.ip))
                                .collect()
                        };
                        tracing::info!(n = all_connected.len(), "tray: scan all");
                        for (mac, ip) in all_connected {
                            intensive_inflight.fetch_add(1, Ordering::Relaxed);
                            if intensive_tx.try_send((mac, ip, false)).is_err() {
                                intensive_inflight.fetch_sub(1, Ordering::Relaxed);
                            }
                        }
                        let _ = map_tx.try_send(());
                    }
                    TrayAction::Quit => {
                        tracing::info!("tray: quit");
                        quit.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                update_tray(&tray_handle, &db, &iface_name, notify_on.load(Ordering::Relaxed));
            }
        }
    }

    tracing::info!("draining intensive workers");
    let total = args.intensive_workers.max(1);
    let deadline = std::time::Instant::now() + Duration::from_secs(600);
    loop {
        if intensive_sem.available_permits() >= total {
            break;
        }
        if std::time::Instant::now() >= deadline {
            tracing::warn!("drain deadline hit");
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let _ = std::fs::remove_file(&sock_path);
    Ok(())
}

fn write_map_now(
    db: &Arc<Mutex<Db>>,
    path: &std::path::Path,
    iface: &str,
    progress: oximon::html::Progress,
) {
    let devices = {
        let db = db.lock().unwrap();
        db.all_devices().unwrap_or_default()
    };
    let events = {
        let db = db.lock().unwrap();
        db.recent_events(200).unwrap_or_default()
    };
    let mut ports_by_mac: HashMap<String, Vec<Port>> = HashMap::new();
    {
        let db = db.lock().unwrap();
        for d in &devices {
            if let Ok(p) = db.ports_for(&d.mac) {
                ports_by_mac.insert(d.mac.clone(), p);
            }
        }
    }
    if let Err(e) = oximon::html::write_map(path, &devices, &events, &ports_by_mac, iface, progress) {
        tracing::warn!(?e, "map write fail");
    } else {
        tracing::debug!(path = %path.display(), "map written");
    }
}

async fn spawn_tray(
    tx: mpsc::UnboundedSender<TrayAction>,
    iface: String,
    notify_on: Arc<AtomicBool>,
) -> Result<ksni::Handle<OximonTray>> {
    use ksni::TrayMethods;
    let tray = OximonTray {
        notifications: notify_on.load(Ordering::Relaxed),
        total: 0,
        online: 0,
        iface,
        tx,
    };
    let handle = tray.spawn().await.context("tray spawn")?;
    Ok(handle)
}

fn update_tray(
    handle: &Option<ksni::Handle<OximonTray>>,
    db: &Arc<Mutex<Db>>,
    iface: &str,
    notifications: bool,
) {
    let Some(h) = handle else { return };
    let (total, online) = {
        let db = db.lock().unwrap();
        let all = db.all_devices().unwrap_or_default();
        (all.len(), all.iter().filter(|d| d.connected).count())
    };
    let iface = iface.to_string();
    let h = h.clone();
    tokio::spawn(async move {
        h.update(move |t: &mut OximonTray| {
            t.total = total;
            t.online = online;
            t.notifications = notifications;
            t.iface = iface;
        })
        .await;
    });
}

#[allow(clippy::too_many_arguments)]
async fn handle_ipc(
    cmd: IpcCmd,
    db: &Arc<Mutex<Db>>,
    intensive_tx: &mpsc::Sender<(String, String, bool)>,
    notify_on: &Arc<AtomicBool>,
    rescan_tx: &mpsc::Sender<()>,
    iface: &str,
    intensive_inflight: &Arc<AtomicUsize>,
    map_tx: &mpsc::Sender<()>,
) -> Reply {
    match cmd {
        IpcCmd::Intensive { target, full_ports } => {
            if full_ports && matches!(target, Target::All) {
                return Reply::err("--full-ports cannot combine with --all");
            }
            let targets: Vec<(String, String)> = {
                let db = db.lock().unwrap();
                let devs = db.all_devices().unwrap_or_default();
                match target {
                    Target::All => devs
                        .into_iter()
                        .filter(|d| d.connected)
                        .map(|d| (d.mac, d.ip))
                        .collect(),
                    Target::Mac { mac } => devs
                        .into_iter()
                        .filter(|d| d.mac.eq_ignore_ascii_case(&mac))
                        .map(|d| (d.mac, d.ip))
                        .collect(),
                    Target::Ip { ip } => devs
                        .into_iter()
                        .filter(|d| d.ip == ip)
                        .map(|d| (d.mac, d.ip))
                        .collect(),
                }
            };
            if targets.is_empty() {
                return Reply::err("no matching device");
            }
            let n = targets.len();
            for (mac, ip) in targets {
                intensive_inflight.fetch_add(1, Ordering::Relaxed);
                if intensive_tx.try_send((mac, ip, full_ports)).is_err() {
                    intensive_inflight.fetch_sub(1, Ordering::Relaxed);
                }
            }
            let _ = map_tx.try_send(());
            Reply::ok(format!(
                "queued {n} intensive scan(s){}",
                if full_ports { " [full 65535]" } else { "" }
            ))
        }
        IpcCmd::Mute => {
            notify_on.store(false, Ordering::Relaxed);
            Reply::ok("muted")
        }
        IpcCmd::Unmute => {
            notify_on.store(true, Ordering::Relaxed);
            Reply::ok("unmuted")
        }
        IpcCmd::ToggleMute => {
            let prev = notify_on.fetch_xor(true, Ordering::Relaxed);
            Reply::ok(if prev { "muted" } else { "unmuted" })
        }
        IpcCmd::Rescan => {
            let _ = rescan_tx.try_send(());
            Reply::ok("rescan queued")
        }
        IpcCmd::Status => {
            let (total, online, with_ports, with_os) = {
                let db = db.lock().unwrap();
                let devs = db.all_devices().unwrap_or_default();
                let total = devs.len();
                let online = devs.iter().filter(|d| d.connected).count();
                let mut with_ports = 0usize;
                let mut with_os = 0usize;
                for d in &devs {
                    if d.os_guess.is_some() {
                        with_os += 1;
                    }
                    if db.ports_for(&d.mac).map(|v| !v.is_empty()).unwrap_or(false) {
                        with_ports += 1;
                    }
                }
                (total, online, with_ports, with_os)
            };
            Reply::data(serde_json::json!({
                "iface": iface,
                "total": total,
                "online": online,
                "with_ports": with_ports,
                "with_os": with_os,
                "notifications": notify_on.load(Ordering::Relaxed),
            }))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_scan_tick(
    scanner: Arc<ArpScanner>,
    db: Arc<Mutex<Db>>,
    oui: Arc<OuiDb>,
    notify_on: Arc<AtomicBool>,
    map_path: &std::path::Path,
    iface_name: &str,
    arp_passes: u32,
    arp_window_ms: u64,
    arp_flag: Arc<AtomicBool>,
    map_tx: mpsc::Sender<()>,
) {
    tracing::info!("scan start");
    let _ = map_path;
    let _ = iface_name;
    arp_flag.store(true, Ordering::Relaxed);
    let _ = map_tx.try_send(());
    let scan_ts = Utc::now();
    let events_result = tokio::task::spawn_blocking(move || -> Vec<(EventKind, Device)> {
        let hits = match scanner.scan_multi(
            arp_passes,
            Duration::from_millis(arp_window_ms),
            Duration::from_millis(500),
        ) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(?e, "scan err");
                return Vec::new();
            }
        };
        tracing::info!(hits = hits.len(), "processing hits");

        let mut dns_map: HashMap<String, Option<String>> = HashMap::new();
        {
            let handles: Vec<_> = hits
                .iter()
                .map(|h| {
                    let ip = h.ip.clone();
                    std::thread::spawn(move || {
                        let r = oximon::scan::reverse_dns(&ip);
                        (ip, r)
                    })
                })
                .collect();
            for h in handles {
                if let Ok((ip, name)) = h.join() {
                    dns_map.insert(ip, name);
                }
            }
        }
        tracing::info!("rdns done");

        let hit_macs: HashSet<String> = hits.iter().map(|h| h.mac.to_lowercase()).collect();
        let prior_connected: HashSet<String> = {
            let db = db.lock().unwrap();
            db.all_devices()
                .unwrap_or_default()
                .into_iter()
                .filter(|d| d.connected)
                .map(|d| d.mac.to_lowercase())
                .collect()
        };

        let mut new_events: Vec<(EventKind, Device)> = Vec::new();

        for hit in &hits {
            let mac = hit.mac.to_lowercase();
            let existing = {
                let db = db.lock().unwrap();
                db.get_device(&mac).ok().flatten()
            };
            let hostname = dns_map.get(&hit.ip).cloned().flatten();
            let vendor = oui.lookup(&mac).map(|s| s.to_string());

            let (first_seen, previous_ip, previous_host, previous_connected, last_intensive) =
                existing
                    .as_ref()
                    .map(|d| {
                        (
                            d.first_seen,
                            Some(d.ip.clone()),
                            d.hostname.clone(),
                            d.connected,
                            d.last_intensive,
                        )
                    })
                    .unwrap_or((scan_ts, None, None, false, None));

            let device = Device {
                mac: mac.clone(),
                ip: hit.ip.clone(),
                hostname: hostname.clone().or(previous_host.clone()),
                vendor: vendor
                    .clone()
                    .or_else(|| existing.as_ref().and_then(|d| d.vendor.clone())),
                first_seen,
                last_seen: scan_ts,
                connected: true,
                rtt_ms: hit.rtt_ms,
                last_intensive,
                os_guess: existing.as_ref().and_then(|d| d.os_guess.clone()),
            };

            {
                let db = db.lock().unwrap();
                if let Err(e) = db.upsert_device(&device) {
                    tracing::warn!(?e, mac=%mac, "upsert fail");
                }
            }

            let newly_connected = !previous_connected;
            if newly_connected {
                let db_l = db.lock().unwrap();
                let _ = db_l.insert_event(&mac, EventKind::Connect, scan_ts, None);
                drop(db_l);
                new_events.push((EventKind::Connect, device.clone()));
            }
            if let Some(prev) = previous_ip.as_deref() {
                if prev != hit.ip {
                    let db_l = db.lock().unwrap();
                    let _ = db_l.insert_event(
                        &mac,
                        EventKind::IpChange,
                        scan_ts,
                        Some(&format!("{prev} -> {}", hit.ip)),
                    );
                }
            }
            if let (Some(prev), Some(cur)) = (previous_host.as_deref(), hostname.as_deref()) {
                if prev != cur {
                    let db_l = db.lock().unwrap();
                    let _ = db_l.insert_event(
                        &mac,
                        EventKind::HostnameChange,
                        scan_ts,
                        Some(&format!("{prev} -> {cur}")),
                    );
                }
            }
        }

        let gone: Vec<String> = prior_connected.difference(&hit_macs).cloned().collect();
        for mac in gone {
            let d_opt = {
                let db_l = db.lock().unwrap();
                let _ = db_l.mark_disconnected(&mac, scan_ts);
                let _ = db_l.insert_event(&mac, EventKind::Disconnect, scan_ts, None);
                db_l.get_device(&mac).ok().flatten()
            };
            if let Some(d) = d_opt {
                new_events.push((EventKind::Disconnect, d));
            }
        }

        tracing::info!(hits = hits.len(), "scan tick");
        new_events
    })
    .await;

    match &events_result {
        Ok(v) => tracing::info!(n = v.len(), "scan tick complete"),
        Err(e) => tracing::error!(?e, "spawn_blocking join err"),
    }
    arp_flag.store(false, Ordering::Relaxed);
    let _ = map_tx.try_send(());
    if notify_on.load(Ordering::Relaxed) {
        if let Ok(events) = events_result {
            for (kind, dev) in events {
                notify::emit_detached(kind, dev);
            }
        }
    }
}
