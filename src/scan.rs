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
}

impl ArpScanner {
    pub fn autodetect(iface_hint: Option<&str>, subnet_hint: Option<&str>) -> Result<Self> {
        let iface = pick_iface(iface_hint)?;
        let src_mac = iface
            .mac
            .ok_or_else(|| anyhow!("iface {} has no mac", iface.name))?;
        let (src_ip, prefix) = pick_ipv4(&iface)?;
        let subnet = if let Some(cidr) = subnet_hint {
            parse_cidr(cidr)?
        } else {
            hosts_for(src_ip, prefix)
        };
        Ok(Self {
            iface,
            src_ip,
            src_mac,
            subnet,
        })
    }

    pub fn iface_name(&self) -> &str {
        &self.iface.name
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
