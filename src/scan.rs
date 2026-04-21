use anyhow::{Context, Result, anyhow};
use pnet::datalink::{self, Channel, Config as DlConfig, MacAddr, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use crate::model::ScanHit;

pub struct ArpScanner {
    iface: NetworkInterface,
    src_ip: Ipv4Addr,
    src_mac: MacAddr,
    subnet: Vec<Ipv4Addr>,
    subnet_cidr: String,
}

impl ArpScanner {
    pub fn autodetect(iface_hint: Option<&str>, subnet_hint: Option<&str>) -> Result<Self> {
        let iface = pick_iface(iface_hint)?;
        let src_mac = iface
            .mac
            .ok_or_else(|| anyhow!("iface {} has no mac", iface.name))?;
        let (src_ip, prefix) = pick_ipv4(&iface)?;
        let (subnet, subnet_cidr) = if let Some(cidr) = subnet_hint {
            (parse_cidr(cidr)?, cidr.to_string())
        } else {
            (hosts_for(src_ip, prefix), format!("{}/{}", subnet_base(src_ip, prefix), prefix))
        };
        Ok(Self {
            iface,
            src_ip,
            src_mac,
            subnet,
            subnet_cidr,
        })
    }

    pub fn subnet_cidr(&self) -> &str {
        &self.subnet_cidr
    }

    pub fn iface_name(&self) -> &str {
        &self.iface.name
    }

    pub fn iface(&self) -> NetworkInterface {
        self.iface.clone()
    }

    pub fn subnet_size(&self) -> usize {
        self.subnet.len()
    }

    pub fn scan(&self, recv_window: Duration) -> Result<Vec<ScanHit>> {
        self.scan_multi(3, recv_window, Duration::from_millis(500))
    }

    pub fn scan_multi(
        &self,
        passes: u32,
        recv_window: Duration,
        gap: Duration,
    ) -> Result<Vec<ScanHit>> {
        let dl_cfg = DlConfig {
            read_timeout: Some(Duration::from_millis(100)),
            write_timeout: Some(Duration::from_millis(200)),
            ..Default::default()
        };
        let (mut tx, mut rx) = match datalink::channel(&self.iface, dl_cfg)? {
            Channel::Ethernet(tx, rx) => (tx, rx),
            _ => return Err(anyhow!("unsupported channel")),
        };

        let mut hits: HashMap<Ipv4Addr, ScanHit> = HashMap::new();
        let mut best_rtt: HashMap<Ipv4Addr, f32> = HashMap::new();

        for pass in 0..passes.max(1) {
            tracing::debug!(pass = pass + 1, subnet_size = self.subnet.len(), "arp pass sending");
            let mut sent_at: HashMap<Ipv4Addr, Instant> = HashMap::with_capacity(self.subnet.len());
            for target in &self.subnet {
                let mut eth_buf = [0u8; 42];
                build_arp_request(&mut eth_buf, self.src_mac, self.src_ip, *target)?;
                if let Some(Err(e)) = tx.send_to(&eth_buf, None) {
                    tracing::debug!(?e, ip = %target, "arp send fail");
                }
                sent_at.insert(*target, Instant::now());
            }
            tracing::info!(pass = pass + 1, "arp sends done, recv window");

            let start = Instant::now();
            while start.elapsed() < recv_window {
                match rx.next() {
                    Ok(frame) => {
                        let Some(eth) = EthernetPacket::new(frame) else {
                            continue;
                        };
                        if eth.get_ethertype() != EtherTypes::Arp {
                            continue;
                        }
                        let Some(arp) = ArpPacket::new(eth.payload()) else {
                            continue;
                        };
                        if arp.get_operation() != ArpOperations::Reply {
                            continue;
                        }
                        let sender_ip = arp.get_sender_proto_addr();
                        let sender_mac = arp.get_sender_hw_addr();
                        let Some(sent_t) = sent_at.get(&sender_ip) else {
                            continue;
                        };
                        let rtt = sent_t.elapsed().as_secs_f32() * 1000.0;
                        match best_rtt.get(&sender_ip) {
                            Some(prev) if *prev <= rtt => {}
                            _ => {
                                best_rtt.insert(sender_ip, rtt);
                                hits.insert(
                                    sender_ip,
                                    ScanHit {
                                        ip: sender_ip.to_string(),
                                        mac: format_mac(sender_mac),
                                        rtt_ms: Some(rtt),
                                    },
                                );
                            }
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::TimedOut
                            || e.kind() == std::io::ErrorKind::WouldBlock
                        {
                            continue;
                        }
                        tracing::debug!(?e, "arp recv err");
                    }
                }
            }

            tracing::info!(pass = pass + 1, hits = hits.len(), "arp pass done");
            if pass + 1 < passes {
                std::thread::sleep(gap);
            }
        }
        tracing::info!(hits = hits.len(), "scan_multi returning");
        Ok(hits.into_values().collect())
    }
}

/// L3 ping sweep via `nmap -sn`. Returns alive IPs + MAC (when available via ARP cache).
pub fn scan_icmp(cidr: &str, timeout_s: u64) -> Result<Vec<ScanHit>> {
    let out = std::process::Command::new("nmap")
        .args([
            "--privileged",
            "-sn",
            "-n",
            "-T4",
            "--disable-arp-ping",
            "--host-timeout",
            &format!("{timeout_s}s"),
            "-oX",
            "-",
            cidr,
        ])
        .output()
        .context("nmap -sn exec")?;
    parse_nmap_hosts(&String::from_utf8_lossy(&out.stdout))
}

fn parse_nmap_hosts(xml: &str) -> Result<Vec<ScanHit>> {
    use quick_xml::events::Event as XmlEvent;
    use quick_xml::reader::Reader;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut hits: Vec<ScanHit> = Vec::new();
    let mut cur_ip: Option<String> = None;
    let mut cur_mac: Option<String> = None;
    let mut cur_up = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) | Ok(XmlEvent::Empty(e)) => {
                let name = e.name();
                let tag = std::str::from_utf8(name.as_ref()).unwrap_or("");
                match tag {
                    "host" => {
                        cur_ip = None;
                        cur_mac = None;
                        cur_up = false;
                    }
                    "status" => {
                        for a in e.attributes().flatten() {
                            if std::str::from_utf8(a.key.as_ref()).unwrap_or("") == "state" {
                                let v = a.unescape_value().unwrap_or_default().to_string();
                                cur_up = v == "up";
                            }
                        }
                    }
                    "address" => {
                        let mut addr: Option<String> = None;
                        let mut addrtype: Option<String> = None;
                        for a in e.attributes().flatten() {
                            let k = std::str::from_utf8(a.key.as_ref()).unwrap_or("");
                            let v = a.unescape_value().unwrap_or_default().to_string();
                            match k {
                                "addr" => addr = Some(v),
                                "addrtype" => addrtype = Some(v),
                                _ => {}
                            }
                        }
                        match (addr, addrtype.as_deref()) {
                            (Some(a), Some("ipv4")) => cur_ip = Some(a),
                            (Some(a), Some("mac")) => cur_mac = Some(a.to_lowercase()),
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            Ok(XmlEvent::End(e)) => {
                let name = e.name();
                if std::str::from_utf8(name.as_ref()).unwrap_or("") == "host" {
                    if cur_up {
                        if let Some(ip) = cur_ip.take() {
                            let mac = cur_mac.take().unwrap_or_else(|| {
                                read_arp_mac(&ip).unwrap_or_else(|| "00:00:00:00:00:00".into())
                            });
                            hits.push(ScanHit { ip, mac, rtt_ms: None });
                        }
                    }
                }
            }
            Ok(XmlEvent::Eof) => break,
            Err(e) => {
                tracing::warn!(?e, "icmp xml parse");
                break;
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(hits)
}

fn read_arp_mac(ip: &str) -> Option<String> {
    let content = std::fs::read_to_string("/proc/net/arp").ok()?;
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        if parts[0] == ip && parts[3] != "00:00:00:00:00:00" {
            return Some(parts[3].to_lowercase());
        }
    }
    None
}

pub fn reverse_dns(ip: &str) -> Option<String> {
    reverse_dns_timeout(ip, Duration::from_millis(400))
}

pub fn reverse_dns_timeout(ip: &str, timeout: Duration) -> Option<String> {
    use std::net::ToSocketAddrs;
    let addr = format!("{ip}:0");
    let sa = addr.to_socket_addrs().ok()?.next()?;
    let ip_owned = ip.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = dns_lookup::lookup_addr(&sa.ip()).ok();
        let _ = tx.send(r);
    });
    match rx.recv_timeout(timeout) {
        Ok(Some(h)) if h != ip_owned => Some(h),
        _ => None,
    }
}

fn pick_iface(hint: Option<&str>) -> Result<NetworkInterface> {
    let ifs = datalink::interfaces();
    if let Some(name) = hint {
        return ifs
            .into_iter()
            .find(|i| i.name == name)
            .with_context(|| format!("iface {name} not found"));
    }
    ifs.into_iter()
        .find(|i| i.is_up() && !i.is_loopback() && i.mac.is_some() && !i.ips.is_empty() && has_ipv4(i))
        .context("no usable iface (need up, non-loopback, ipv4)")
}

fn has_ipv4(i: &NetworkInterface) -> bool {
    i.ips.iter().any(|n| matches!(n.ip(), IpAddr::V4(_)))
}

fn pick_ipv4(iface: &NetworkInterface) -> Result<(Ipv4Addr, u8)> {
    for n in &iface.ips {
        if let IpAddr::V4(v4) = n.ip() {
            return Ok((v4, n.prefix()));
        }
    }
    Err(anyhow!("no ipv4 on iface {}", iface.name))
}

fn subnet_base(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let prefix = prefix.clamp(0, 32);
    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Ipv4Addr::from(u32::from(ip) & mask)
}

fn hosts_for(ip: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    let prefix = prefix.clamp(16, 32);
    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let base = u32::from(ip) & mask;
    let size: u32 = 1u32.checked_shl(32 - prefix as u32).unwrap_or(0);
    let mut out = Vec::with_capacity(size as usize);
    for i in 1..size.saturating_sub(1) {
        out.push(Ipv4Addr::from(base + i));
    }
    out
}

fn parse_cidr(s: &str) -> Result<Vec<Ipv4Addr>> {
    let (ip_s, prefix_s) = s.split_once('/').ok_or_else(|| anyhow!("bad cidr {s}"))?;
    let ip: Ipv4Addr = ip_s.parse()?;
    let prefix: u8 = prefix_s.parse()?;
    Ok(hosts_for(ip, prefix))
}

fn build_arp_request(
    buf: &mut [u8],
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    tgt_ip: Ipv4Addr,
) -> Result<()> {
    let mut eth = MutableEthernetPacket::new(buf).ok_or_else(|| anyhow!("eth buf too small"))?;
    eth.set_destination(MacAddr::broadcast());
    eth.set_source(src_mac);
    eth.set_ethertype(EtherTypes::Arp);

    let mut arp_buf = [0u8; 28];
    {
        let mut arp = MutableArpPacket::new(&mut arp_buf).ok_or_else(|| anyhow!("arp buf"))?;
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(src_mac);
        arp.set_sender_proto_addr(src_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(tgt_ip);
    }
    eth.set_payload(&arp_buf);
    Ok(())
}

fn format_mac(m: MacAddr) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m.0, m.1, m.2, m.3, m.4, m.5)
}
