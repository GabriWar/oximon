use anyhow::Result;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

use crate::model::{Device, Event, Port};

pub fn write_map(
    path: &Path,
    devices: &[Device],
    events: &[Event],
    ports: &HashMap<String, Vec<Port>>,
    iface: &str,
    progress: Progress,
    running: Vec<RunningView>,
) -> Result<()> {
    let gateway_ip = detect_gateway();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let html = render_inner(devices, events, ports, iface, gateway_ip.as_deref(), progress, running).1;
    let tmp = path.with_extension("html.tmp");
    std::fs::write(&tmp, html)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn detect_gateway() -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "default" && parts[1] == "via" {
            return Ok::<_, ()>(parts[2].to_string()).ok();
        }
    }
    None
}

#[derive(Serialize)]
struct NodeData<'a> {
    id: &'a str,
    label: String,
    ip: &'a str,
    mac: &'a str,
    hostname: Option<&'a str>,
    vendor: Option<&'a str>,
    os_guess: Option<&'a str>,
    os_kind: &'static str,
    rtt_ms: Option<f32>,
    first_seen: String,
    last_seen: String,
    connected: bool,
    is_gateway: bool,
    open_ports: usize,
    ports: Vec<PortView>,
    events: Vec<EventView>,
}

pub fn classify_os(os_guess: Option<&str>, vendor: Option<&str>) -> &'static str {
    let s = os_guess.unwrap_or("").to_lowercase();
    let v = vendor.unwrap_or("").to_lowercase();
    let hay = format!("{s} {v}");
    if hay.contains("windows") {
        "windows"
    } else if hay.contains("mac")
        || hay.contains("darwin")
        || hay.contains("apple")
        || hay.contains("ios")
    {
        "mac"
    } else if hay.contains("android") {
        "android"
    } else if hay.contains("mikrotik")
        || hay.contains("routeros")
        || hay.contains("openwrt")
        || hay.contains("cisco")
        || hay.contains("routerboard")
        || hay.contains("ubiquiti")
        || hay.contains("asus")
    {
        "router"
    } else if hay.contains("crestron") || hay.contains("printer") || hay.contains("iot") {
        "iot"
    } else if hay.contains("vmware") || hay.contains("virtualbox") || hay.contains("qemu") {
        "vm"
    } else if hay.contains("linux") || hay.contains("ubuntu") || hay.contains("debian") {
        "linux"
    } else {
        "unknown"
    }
}

#[derive(Serialize, Clone)]
struct PortView {
    port: u16,
    proto: String,
    state: String,
    service: Option<String>,
    banner: Option<String>,
}

#[derive(Serialize)]
struct EventView {
    ts: String,
    kind: String,
    detail: Option<String>,
}

#[derive(Serialize)]
struct Node<'a> {
    data: NodeData<'a>,
}

#[derive(Serialize)]
struct EdgeData {
    id: String,
    source: String,
    target: String,
}

#[derive(Serialize)]
struct Edge {
    data: EdgeData,
}

#[derive(Serialize)]
struct Graph<'a> {
    nodes: Vec<Node<'a>>,
    edges: Vec<Edge>,
}

#[derive(Serialize)]
struct Meta<'a> {
    iface: &'a str,
    generated_at: String,
    gateway_ip: Option<&'a str>,
    total: usize,
    connected: usize,
    with_ports: usize,
    with_os: usize,
    progress: Progress,
}

#[derive(Serialize, Clone, Copy, Default)]
pub struct Progress {
    pub arp_scanning: bool,
    pub intensive_inflight: usize,
}

#[derive(Serialize)]
struct Payload<'a> {
    meta: Meta<'a>,
    graph: Graph<'a>,
    events: Vec<FlatEvent<'a>>,
    running: Vec<RunningView>,
}

#[derive(Serialize, Clone, Debug)]
pub struct RunningView {
    pub kind: String,
    pub label: String,
    pub started_at: String,
}

#[derive(Serialize)]
struct FlatEvent<'a> {
    ts: String,
    mac: &'a str,
    ip: Option<&'a str>,
    label: Option<&'a str>,
    kind: &'static str,
    detail: Option<&'a str>,
}

pub fn build_payload_json(
    devices: &[Device],
    events: &[Event],
    ports: &HashMap<String, Vec<Port>>,
    iface: &str,
    gateway_ip: Option<&str>,
    progress: Progress,
    running: Vec<RunningView>,
) -> String {
    render_inner(devices, events, ports, iface, gateway_ip, progress, running).0
}

pub fn template_empty() -> String {
    TEMPLATE.replace("__PAYLOAD__", "null")
}

pub fn build_snapshot(
    db: &crate::db::Db,
    iface: &str,
    progress: Progress,
    running: Vec<RunningView>,
) -> String {
    let gateway_ip = detect_gateway();
    let devices = db.all_devices().unwrap_or_default();
    let events = db.recent_events(200).unwrap_or_default();
    let mut ports_by_mac: HashMap<String, Vec<Port>> = HashMap::new();
    for d in &devices {
        if let Ok(p) = db.ports_for(&d.mac) {
            ports_by_mac.insert(d.mac.clone(), p);
        }
    }
    build_payload_json(
        &devices,
        &events,
        &ports_by_mac,
        iface,
        gateway_ip.as_deref(),
        progress,
        running,
    )
}

fn render_inner(
    devices: &[Device],
    events: &[Event],
    ports: &HashMap<String, Vec<Port>>,
    iface: &str,
    gateway_ip: Option<&str>,
    progress: Progress,
    running: Vec<RunningView>,
) -> (String, String) {
    let mut events_by_mac: HashMap<&str, Vec<EventView>> = HashMap::new();
    for e in events {
        events_by_mac
            .entry(e.mac.as_str())
            .or_default()
            .push(EventView {
                ts: e.ts.to_rfc3339(),
                kind: e.kind.as_str().to_string(),
                detail: e.detail.clone(),
            });
    }

    let gateway_mac = devices
        .iter()
        .find(|d| Some(d.ip.as_str()) == gateway_ip)
        .map(|d| d.mac.clone());

    let nodes: Vec<Node> = devices
        .iter()
        .map(|d| {
            let dev_ports = ports.get(&d.mac).cloned().unwrap_or_default();
            let port_views: Vec<PortView> = dev_ports
                .iter()
                .map(|p| PortView {
                    port: p.port,
                    proto: p.proto.clone(),
                    state: p.state.clone(),
                    service: p.service.clone(),
                    banner: p.banner.clone(),
                })
                .collect();
            let is_gw = Some(d.ip.as_str()) == gateway_ip;
            let label = d.hostname.clone().unwrap_or_else(|| d.ip.clone());
            let os_kind = classify_os(d.os_guess.as_deref(), d.vendor.as_deref());
            Node {
                data: NodeData {
                    id: d.mac.as_str(),
                    label,
                    ip: d.ip.as_str(),
                    mac: d.mac.as_str(),
                    hostname: d.hostname.as_deref(),
                    vendor: d.vendor.as_deref(),
                    os_guess: d.os_guess.as_deref(),
                    os_kind,
                    rtt_ms: d.rtt_ms,
                    first_seen: d.first_seen.to_rfc3339(),
                    last_seen: d.last_seen.to_rfc3339(),
                    connected: d.connected,
                    is_gateway: is_gw,
                    open_ports: port_views.iter().filter(|p| p.state == "open").count(),
                    ports: port_views,
                    events: events_by_mac
                        .get(d.mac.as_str())
                        .cloned()
                        .unwrap_or_default(),
                },
            }
        })
        .collect();

    let edges: Vec<Edge> = if let Some(gw_mac) = gateway_mac.as_deref() {
        devices
            .iter()
            .filter(|d| d.mac != gw_mac)
            .map(|d| Edge {
                data: EdgeData {
                    id: format!("{}-{}", gw_mac, d.mac),
                    source: gw_mac.to_string(),
                    target: d.mac.clone(),
                },
            })
            .collect()
    } else {
        Vec::new()
    };

    let meta = Meta {
        iface,
        generated_at: chrono::Utc::now().to_rfc3339(),
        gateway_ip,
        total: devices.len(),
        connected: devices.iter().filter(|d| d.connected).count(),
        with_ports: devices
            .iter()
            .filter(|d| ports.get(&d.mac).map(|p| !p.is_empty()).unwrap_or(false))
            .count(),
        with_os: devices.iter().filter(|d| d.os_guess.is_some()).count(),
        progress,
    };

    let flat_events: Vec<FlatEvent> = events
        .iter()
        .take(200)
        .map(|e| {
            let (ip, label) = devices
                .iter()
                .find(|d| d.mac.eq_ignore_ascii_case(&e.mac))
                .map(|d| (Some(d.ip.as_str()), d.hostname.as_deref()))
                .unwrap_or((None, None));
            FlatEvent {
                ts: e.ts.to_rfc3339(),
                mac: e.mac.as_str(),
                ip,
                label,
                kind: e.kind.as_str(),
                detail: e.detail.as_deref(),
            }
        })
        .collect();

    let payload = Payload {
        meta,
        graph: Graph { nodes, edges },
        events: flat_events,
        running,
    };
    let payload_json = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into());

    let html = TEMPLATE.replace("__PAYLOAD__", &payload_json);
    (payload_json, html)
}


impl Clone for EventView {
    fn clone(&self) -> Self {
        Self {
            ts: self.ts.clone(),
            kind: self.kind.clone(),
            detail: self.detail.clone(),
        }
    }
}

const TEMPLATE: &str = include_str!("../assets/map.html");
