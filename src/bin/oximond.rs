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
    /// scan mode: auto (arp + icmp fallback), arp (only), icmp (L3 only)
    #[arg(long, default_value = "auto")]
    scan_mode: String,
    /// nmap -sn per-host timeout for icmp fallback
    #[arg(long, default_value_t = 15)]
    icmp_timeout_s: u64,
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
    /// set or clear device alias/nickname
    Alias {
        /// target mac
        #[arg(long)]
        mac: String,
        /// new alias. omit or empty to clear
        #[arg(long)]
        name: Option<String>,
        /// clear alias
        #[arg(long)]
        clear: bool,
    },
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
            client_cmd(IpcCmd::Intensive { target, full_ports: *full_ports, vuln_scripts: false }).await
        }
        Some(Command::Mute) => client_cmd(IpcCmd::Mute).await,
        Some(Command::Unmute) => client_cmd(IpcCmd::Unmute).await,
        Some(Command::ToggleMute) => client_cmd(IpcCmd::ToggleMute).await,
        Some(Command::Status) => client_cmd(IpcCmd::Status).await,
        Some(Command::Rescan) => client_cmd(IpcCmd::Rescan).await,
        Some(Command::Alias { mac, name, clear }) => {
            let alias = if *clear { None } else { name.clone().filter(|s| !s.is_empty()) };
            client_cmd(IpcCmd::SetAlias { mac: mac.to_lowercase(), alias }).await
        }
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
    let sniff_iface = scanner.iface();
    oximon::sniff::spawn_passive_sniff(sniff_iface, db.clone());
    tracing::info!(
        iface = %iface_name,
        hosts = scanner.subnet_size(),
        "scanner ready"
    );

    let notify_on = Arc::new(AtomicBool::new(cfg.notify));
    let arp_scanning = Arc::new(AtomicBool::new(false));
    let intensive_inflight = Arc::new(AtomicUsize::new(0));
    let running: Arc<Mutex<Vec<oximon::html::RunningView>>> = Arc::new(Mutex::new(Vec::new()));
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
        let running_c = running.clone();
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
                let running_snap: Vec<oximon::html::RunningView> = running_c.lock().unwrap().clone();
                let _ = tokio::task::spawn_blocking(move || {
                    write_map_now(&db_c, &path, &iface, progress, running_snap.clone());
                    let snap = {
                        let db = db_c.lock().unwrap();
                        oximon::html::build_snapshot(&db, &iface, progress, running_snap)
                    };
                    let _ = live_tx.send(snap);
                })
                .await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });
    }

    // intensive worker pool
    let (intensive_tx, mut intensive_rx) = mpsc::channel::<intensive::Job>(1024);
    let intensive_sem = Arc::new(Semaphore::new(args.intensive_workers.max(1)));
    {
        let db = db.clone();
        let notify_flag = notify_on.clone();
        let sem = intensive_sem.clone();
        let map_tx = map_tx.clone();
        let inflight = intensive_inflight.clone();
        let running_c = running.clone();
        tokio::spawn(async move {
            while let Some(intensive::Job { mac, ip, full_ports, vuln_scripts }) = intensive_rx.recv().await {
                let permit = match sem.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let db_c = db.clone();
                let notify_flag = notify_flag.clone();
                let map_tx = map_tx.clone();
                let inflight = inflight.clone();
                let running = running_c.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let mac_c = mac.clone();
                    let ip_c = ip.clone();
                    let opts = intensive::Options { full_ports, vuln_scripts };
                    {
                        let mut r = running.lock().unwrap();
                        r.push(oximon::html::RunningView {
                            kind: "intensive".into(),
                            label: format!(
                                "nmap {}{}",
                                ip,
                                if full_ports { " (all 65535)" } else { "" }
                            ),
                            started_at: Utc::now().to_rfc3339(),
                        });
                    }
                    let _ = map_tx.try_send(());
                    let res =
                        tokio::task::spawn_blocking(move || intensive::run_with(&mac_c, &ip_c, opts))
                            .await;
                    match res {
                        Ok(Ok(r)) => {
                            let now = Utc::now();
                            let os = r.os_guess.clone();
                            let mut new_port_details: Vec<String> = Vec::new();
                            {
                                let mut db = db_c.lock().unwrap();
                                // diff: find newly-open ports not previously known
                                let prev: std::collections::HashSet<(u16, String)> = db
                                    .ports_for(&mac)
                                    .unwrap_or_default()
                                    .into_iter()
                                    .filter(|p| p.state == "open")
                                    .map(|p| (p.port, p.proto))
                                    .collect();
                                for p in &r.ports {
                                    if p.state == "open" && !prev.contains(&(p.port, p.proto.clone())) {
                                        new_port_details.push(format!(
                                            "{}/{} {}",
                                            p.port,
                                            p.proto,
                                            p.service.as_deref().unwrap_or("")
                                        ));
                                    }
                                }
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
                                // only emit NewPort events if this isn't the first scan (prev had data)
                                if !prev.is_empty() {
                                    for d in &new_port_details {
                                        let _ =
                                            db.insert_event(&mac, EventKind::NewPort, now, Some(d));
                                    }
                                }
                            }
                            if !new_port_details.is_empty() && notify_flag.load(Ordering::Relaxed) {
                                if let Some(dev) = {
                                    let db = db_c.lock().unwrap();
                                    db.get_device(&mac).ok().flatten()
                                } {
                                    for d in &new_port_details {
                                        let mut dev2 = dev.clone();
                                        dev2.hostname = Some(format!(
                                            "{} · {}",
                                            dev.hostname.as_deref().unwrap_or(""),
                                            d
                                        ));
                                        notify::emit_detached(EventKind::NewPort, dev2);
                                    }
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
                    {
                        let mut r = running.lock().unwrap();
                        r.retain(|op| !(op.kind == "intensive" && op.label.contains(&ip)));
                    }
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
            running: running.clone(),
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
                    arp_scanning.clone(), map_tx.clone(), running.clone(),
                    args.scan_mode.clone(), args.icmp_timeout_s,
                ).await;
                let _ = map_tx.try_send(());
                update_tray(&tray_handle, &db, &iface_name, notify_on.load(Ordering::Relaxed));
                if args.once { break; }
            }

            _ = rescan_rx.recv() => {
                run_scan_tick(
                    scanner.clone(), db.clone(), oui.clone(), notify_on.clone(),
                    &map_path, &iface_name, args.arp_passes, args.arp_window_ms,
                    arp_scanning.clone(), map_tx.clone(), running.clone(),
                    args.scan_mode.clone(), args.icmp_timeout_s,
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
                            let job = intensive::Job { mac, ip, full_ports: false, vuln_scripts: false };
                            if intensive_tx.try_send(job).is_err() {
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

/// Merge hits by IP. First writer wins on MAC (ARP trusted before ICMP/nmap).
/// Also try to replace any placeholder/bogus MACs from /proc/net/arp.
fn merge_hits(dst: &mut Vec<oximon::model::ScanHit>, src: Vec<oximon::model::ScanHit>) {
    let seen_ips: std::collections::HashSet<String> =
        dst.iter().map(|x| x.ip.clone()).collect();
    for hit in src {
        if !seen_ips.contains(&hit.ip) {
            dst.push(hit);
        }
    }
}

fn write_map_now(
    db: &Arc<Mutex<Db>>,
    path: &std::path::Path,
    iface: &str,
    progress: oximon::html::Progress,
    running: Vec<oximon::html::RunningView>,
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
    if let Err(e) = oximon::html::write_map(path, &devices, &events, &ports_by_mac, iface, progress, running) {
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
    intensive_tx: &mpsc::Sender<intensive::Job>,
    notify_on: &Arc<AtomicBool>,
    rescan_tx: &mpsc::Sender<()>,
    iface: &str,
    intensive_inflight: &Arc<AtomicUsize>,
    map_tx: &mpsc::Sender<()>,
) -> Reply {
    match cmd {
        IpcCmd::Intensive { target, full_ports, vuln_scripts } => {
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
                let job = intensive::Job { mac, ip, full_ports, vuln_scripts };
                if intensive_tx.try_send(job).is_err() {
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
        IpcCmd::SetAlias { mac, alias } => {
            let mac_l = mac.to_lowercase();
            let n = {
                let db_l = db.lock().unwrap();
                db_l.set_alias(&mac_l, alias.as_deref()).unwrap_or(0)
            };
            if n == 0 {
                return Reply::err("no such mac");
            }
            let _ = map_tx.try_send(());
            Reply::ok(match alias {
                Some(a) => format!("alias set: {mac_l} -> {a}"),
                None => format!("alias cleared: {mac_l}"),
            })
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
    running: Arc<Mutex<Vec<oximon::html::RunningView>>>,
    scan_mode: String,
    icmp_timeout_s: u64,
) {
    tracing::info!("scan start");
    let _ = map_path;
    let _ = iface_name;
    arp_flag.store(true, Ordering::Relaxed);
    {
        let mut r = running.lock().unwrap();
        r.push(oximon::html::RunningView {
            kind: "arp".into(),
            label: format!("arp sweep {}", scanner.iface_name()),
            started_at: Utc::now().to_rfc3339(),
        });
    }
    let _ = map_tx.try_send(());
    let scan_ts = Utc::now();
    let events_result = tokio::task::spawn_blocking(move || -> Vec<(EventKind, Device)> {
        let cidr = scanner.subnet_cidr().to_string();
        let iface_for_net = scanner.iface_name().to_string();
        let network_label = oximon::scan::detect_network(&iface_for_net);
        let mut hits: Vec<oximon::model::ScanHit> = Vec::new();
        let do_arp = matches!(scan_mode.as_str(), "auto" | "arp");
        let force_icmp = scan_mode == "icmp";
        if do_arp && !force_icmp {
            match scanner.scan_multi(
                arp_passes,
                Duration::from_millis(arp_window_ms),
                Duration::from_millis(500),
            ) {
                Ok(h) => hits = h,
                Err(e) => tracing::error!(?e, "arp scan err"),
            }
        }
        // auto = union of ARP + ICMP (not fallback-only)
        // dedup by IP (ARP trusted first; ICMP/nmap macs can be bogus on wifi)
        if scan_mode == "auto" || force_icmp {
            let iface = scanner.iface_name().to_string();
            if let Ok(h) = oximon::scan::scan_broadcast_icmp(&iface, 2) {
                let before = hits.len();
                merge_hits(&mut hits, h);
                tracing::info!(added = hits.len() - before, "broadcast icmp done");
            }

            tracing::info!(cidr = %cidr, arp_hits = hits.len(), "icmp sweep");
            match oximon::scan::scan_icmp(&cidr, icmp_timeout_s) {
                Ok(h) => {
                    tracing::info!(hits = h.len(), "icmp scan done");
                    merge_hits(&mut hits, h);
                }
                Err(e) => tracing::warn!(?e, "icmp scan err"),
            }
        }
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
                alias: existing.as_ref().and_then(|d| d.alias.clone()),
                last_network: Some(network_label.clone()),
            };

            {
                let db = db.lock().unwrap();
                if let Err(e) = db.upsert_device(&device) {
                    tracing::warn!(?e, mac=%mac, "upsert fail");
                }
                if let Err(e) = db.record_network(&mac, &network_label, scan_ts) {
                    tracing::warn!(?e, mac=%mac, "record_network fail");
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

        // prune event log
        {
            let db_l = db.lock().unwrap();
            if let Ok(n) = db_l.prune_events(10_000, 30) {
                if n > 0 {
                    tracing::debug!(pruned = n, "events pruned");
                }
            }
        }

        new_events
    })
    .await;

    match &events_result {
        Ok(v) => tracing::info!(n = v.len(), "scan tick complete"),
        Err(e) => tracing::error!(?e, "spawn_blocking join err"),
    }
    arp_flag.store(false, Ordering::Relaxed);
    {
        let mut r = running.lock().unwrap();
        r.retain(|op| op.kind != "arp");
    }
    let _ = map_tx.try_send(());
    if notify_on.load(Ordering::Relaxed) {
        if let Ok(events) = events_result {
            for (kind, dev) in events {
                notify::emit_detached(kind, dev);
            }
        }
    }
}
