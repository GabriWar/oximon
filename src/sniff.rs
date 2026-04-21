use anyhow::{Context, Result};
use pnet::datalink::{self, Channel, Config as DlConfig, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use crate::db::Db;

pub fn spawn_passive_sniff(iface: NetworkInterface, db: Arc<Mutex<Db>>) {
    std::thread::Builder::new()
        .name("oximon-sniff".into())
        .spawn(move || {
            if let Err(e) = run(iface, db) {
                tracing::warn!(?e, "sniff exited");
            }
        })
        .ok();
}

fn run(iface: NetworkInterface, db: Arc<Mutex<Db>>) -> Result<()> {
    let cfg = DlConfig {
        read_timeout: Some(Duration::from_millis(500)),
        ..Default::default()
    };
    let (_tx, mut rx) = match datalink::channel(&iface, cfg).context("sniff channel")? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => anyhow::bail!("unsupported channel"),
    };
    tracing::info!(iface = %iface.name, "passive sniff started");
    loop {
        match rx.next() {
            Ok(frame) => {
                let Some(eth) = EthernetPacket::new(frame) else { continue };
                if eth.get_ethertype() != EtherTypes::Ipv4 {
                    continue;
                }
                let Some(ip4) = Ipv4Packet::new(eth.payload()) else { continue };
                if ip4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
                    continue;
                }
                let Some(udp) = UdpPacket::new(ip4.payload()) else { continue };
                let src_ip = ip4.get_source();
                let payload = udp.payload();
                match udp.get_destination() {
                    5353 => handle_mdns(payload, src_ip, &db),
                    1900 => handle_ssdp(payload, src_ip, &db),
                    137 => handle_nbns(payload, src_ip, &db),
                    67 | 68 => handle_dhcp(payload, src_ip, &db),
                    _ => {}
                }
                // mDNS also sent from src=5353
                if udp.get_source() == 5353 {
                    handle_mdns(payload, src_ip, &db);
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
                {
                    continue;
                }
                tracing::debug!(?e, "sniff recv err");
            }
        }
    }
}

fn clean_hostname(raw: &str) -> String {
    let s = raw.trim_end_matches('.');
    s.strip_suffix(".local")
        .unwrap_or(s)
        .trim_matches('.')
        .trim()
        .to_string()
}

fn update_for_ip(db: &Arc<Mutex<Db>>, ip: Ipv4Addr, hostname: &str) {
    let h = clean_hostname(hostname);
    if h.is_empty() {
        return;
    }
    let db_l = db.lock().unwrap();
    let Ok(Some(mac)) = db_l.find_mac_by_ip(&ip.to_string()) else {
        return;
    };
    match db_l.set_hostname_if_empty(&mac, &h) {
        Ok(n) if n > 0 => {
            tracing::info!(%mac, %ip, hostname = %h, "sniff set hostname");
        }
        _ => {}
    }
}

fn handle_mdns(payload: &[u8], src: Ipv4Addr, db: &Arc<Mutex<Db>>) {
    use simple_dns::Packet;
    use simple_dns::rdata::RData;
    let Ok(pkt) = Packet::parse(payload) else { return };
    // answers list: look for A records binding hostname → ip
    for ans in pkt.answers.iter() {
        let name = ans.name.to_string();
        match &ans.rdata {
            RData::A(a) => {
                let ip: Ipv4Addr = std::net::Ipv4Addr::from(a.address);
                update_for_ip(db, ip, &name);
            }
            RData::AAAA(_) => {
                // v6 — match by name to src_ip
                update_for_ip(db, src, &name);
            }
            _ => {}
        }
    }
    // additional records can also carry A/PTR
    for ans in pkt.additional_records.iter() {
        let name = ans.name.to_string();
        if let RData::A(a) = &ans.rdata {
            let ip: Ipv4Addr = std::net::Ipv4Addr::from(a.address);
            update_for_ip(db, ip, &name);
        }
    }
}

fn handle_ssdp(payload: &[u8], src: Ipv4Addr, db: &Arc<Mutex<Db>>) {
    let text = match std::str::from_utf8(payload) {
        Ok(s) => s,
        Err(_) => return,
    };
    // SSDP = HTTP-like. Lines: NOTIFY * HTTP/1.1 ... SERVER: foo/bar
    let mut server: Option<&str> = None;
    let mut usn: Option<&str> = None;
    for line in text.lines() {
        let (k, v) = match line.split_once(':') {
            Some(x) => x,
            None => continue,
        };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        match k.as_str() {
            "server" => server = Some(v),
            "usn" => usn = Some(v),
            _ => {}
        }
    }
    if let Some(s) = server.or(usn) {
        // server string like "Linux/5.10 UPnP/1.0 MyDevice/1.0"
        let short = s.split(' ').last().unwrap_or(s);
        if !short.is_empty() {
            update_for_ip(db, src, short);
        }
    }
}

fn handle_nbns(payload: &[u8], src: Ipv4Addr, db: &Arc<Mutex<Db>>) {
    // NBNS name-registration or response. Flags at offset 2-3, bit 15 = response.
    if payload.len() < 12 {
        return;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags & 0x8000) != 0;
    if !is_response {
        return;
    }
    // encoded name at offset 12: 1-byte length (0x20=32), then 32 bytes encoded, then 0x00.
    let first = payload[12] as usize;
    if first == 0 || first > payload.len() - 13 {
        return;
    }
    let name_enc = &payload[13..13 + first];
    if name_enc.len() != 32 {
        return;
    }
    let mut decoded = [0u8; 16];
    for (i, chunk) in name_enc.chunks_exact(2).enumerate() {
        if i >= 16 {
            break;
        }
        let hi = chunk[0].wrapping_sub(b'A');
        let lo = chunk[1].wrapping_sub(b'A');
        decoded[i] = (hi << 4) | (lo & 0xF);
    }
    // NetBIOS names are 15-char + 1 byte suffix, space-padded
    let name_bytes = &decoded[..15];
    let name = String::from_utf8_lossy(name_bytes).trim().to_string();
    if !name.is_empty() {
        update_for_ip(db, src, &name);
    }
}

fn handle_dhcp(payload: &[u8], src: Ipv4Addr, db: &Arc<Mutex<Db>>) {
    // DHCP options: magic cookie 99,130,83,99 at offset 236
    if payload.len() < 240 {
        return;
    }
    if &payload[236..240] != &[99u8, 130, 83, 99] {
        return;
    }
    let mut i = 240;
    while i < payload.len() {
        let opt = payload[i];
        if opt == 0xff {
            break;
        }
        if opt == 0x00 {
            i += 1;
            continue;
        }
        if i + 1 >= payload.len() {
            break;
        }
        let len = payload[i + 1] as usize;
        let val_start = i + 2;
        let val_end = val_start + len;
        if val_end > payload.len() {
            break;
        }
        if opt == 12 {
            // hostname
            if let Ok(s) = std::str::from_utf8(&payload[val_start..val_end]) {
                let h = s.trim().trim_matches('\0').to_string();
                if !h.is_empty() {
                    update_for_ip(db, src, &h);
                }
            }
        }
        i = val_end;
    }
}
