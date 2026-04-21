use anyhow::{Context, Result};
use pnet::datalink::NetworkInterface;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use crate::db::Db;

pub fn spawn_passive_sniff(iface: NetworkInterface, db: Arc<Mutex<Db>>) {
    let local_ip = iface
        .ips
        .iter()
        .find_map(|n| match n.ip() {
            IpAddr::V4(v) => Some(v),
            _ => None,
        })
        .unwrap_or(Ipv4Addr::UNSPECIFIED);
    let iface_name = iface.name.clone();

    // mDNS: 224.0.0.251:5353
    spawn_mcast_listener(
        "mdns",
        5353,
        Ipv4Addr::new(224, 0, 0, 251),
        local_ip,
        iface_name.clone(),
        db.clone(),
        handle_mdns,
    );
    // SSDP: 239.255.255.250:1900
    spawn_mcast_listener(
        "ssdp",
        1900,
        Ipv4Addr::new(239, 255, 255, 250),
        local_ip,
        iface_name.clone(),
        db.clone(),
        handle_ssdp,
    );
    // NBNS: broadcast 137
    spawn_broadcast_listener("nbns", 137, local_ip, iface_name.clone(), db.clone(), handle_nbns);

    // active mDNS service enumeration — periodic blast that forces devices to announce
    spawn_mdns_prober(local_ip);
}

fn make_reuse_socket(domain: Domain, ty: Type, proto: Option<Protocol>) -> Result<Socket> {
    let s = Socket::new(domain, ty, proto)?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true).ok();
    Ok(s)
}

fn spawn_mcast_listener<F>(
    label: &'static str,
    port: u16,
    group: Ipv4Addr,
    local_ip: Ipv4Addr,
    iface_name: String,
    db: Arc<Mutex<Db>>,
    handler: F,
) where
    F: Fn(&[u8], Ipv4Addr, &Arc<Mutex<Db>>) + Send + Sync + 'static,
{
    std::thread::Builder::new()
        .name(format!("oximon-sniff-{label}"))
        .spawn(move || {
            let sock = match bind_multicast(port, group, local_ip) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(?e, label, "sniff bind fail");
                    return;
                }
            };
            let _ = iface_name;
            sock.set_read_timeout(Some(Duration::from_millis(1000))).ok();
            tracing::info!(label, port, group = %group, "sniff listening");
            let mut buf = [0u8; 9000];
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        if let IpAddr::V4(v4) = src.ip() {
                            handler(&buf[..n], v4, &db);
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut
                        {
                            continue;
                        }
                        tracing::debug!(?e, label, "sniff recv err");
                    }
                }
            }
        })
        .ok();
}

fn bind_multicast(port: u16, group: Ipv4Addr, local_ip: Ipv4Addr) -> Result<UdpSocket> {
    let sock = make_reuse_socket(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    sock.bind(&SockAddr::from(addr))?;
    let sock: UdpSocket = sock.into();
    sock.join_multicast_v4(&group, &local_ip)
        .with_context(|| format!("join {group} on {local_ip}"))?;
    Ok(sock)
}

fn spawn_broadcast_listener<F>(
    label: &'static str,
    port: u16,
    _local_ip: Ipv4Addr,
    iface_name: String,
    db: Arc<Mutex<Db>>,
    handler: F,
) where
    F: Fn(&[u8], Ipv4Addr, &Arc<Mutex<Db>>) + Send + Sync + 'static,
{
    std::thread::Builder::new()
        .name(format!("oximon-sniff-{label}"))
        .spawn(move || {
            let sock = match make_reuse_socket(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(?e, label, "sniff socket err");
                    return;
                }
            };
            let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
            if let Err(e) = sock.bind(&SockAddr::from(SocketAddr::V4(addr))) {
                tracing::warn!(?e, label, port, "sniff bind fail");
                return;
            }
            sock.set_broadcast(true).ok();
            let sock: UdpSocket = sock.into();
            sock.set_read_timeout(Some(Duration::from_millis(1000))).ok();
            let _ = iface_name;
            tracing::info!(label, port, "sniff listening (broadcast)");
            let mut buf = [0u8; 9000];
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        if let IpAddr::V4(v4) = src.ip() {
                            handler(&buf[..n], v4, &db);
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut
                        {
                            continue;
                        }
                        tracing::debug!(?e, label, "sniff recv err");
                    }
                }
            }
        })
        .ok();
}

/// periodically send `_services._dns-sd._udp.local` PTR query to mDNS group → every
/// mDNS-capable device responds, we catch it in the mDNS listener
fn spawn_mdns_prober(local_ip: Ipv4Addr) {
    std::thread::Builder::new()
        .name("oximon-mdns-prober".into())
        .spawn(move || {
            let sock = match mdns_query_socket(local_ip) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(?e, "mdns prober socket fail");
                    return;
                }
            };
            loop {
                if let Err(e) = send_mdns_enumeration(&sock) {
                    tracing::debug!(?e, "mdns query send fail");
                }
                std::thread::sleep(Duration::from_secs(90));
            }
        })
        .ok();
}

fn mdns_query_socket(local_ip: Ipv4Addr) -> Result<UdpSocket> {
    let sock = make_reuse_socket(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    sock.bind(&SockAddr::from(addr))?;
    let _ = sock.set_multicast_if_v4(&local_ip);
    let sock: UdpSocket = sock.into();
    sock.set_multicast_loop_v4(false).ok();
    Ok(sock)
}

fn send_mdns_enumeration(sock: &UdpSocket) -> Result<()> {
    use simple_dns::{Name, Packet, Question, rdata::TYPE};
    let mut pkt = Packet::new_query(0);
    pkt.questions.push(Question::new(
        Name::new("_services._dns-sd._udp.local").context("name")?,
        TYPE::PTR.into(),
        simple_dns::CLASS::IN.into(),
        false,
    ));
    let buf = pkt.build_bytes_vec()?;
    sock.send_to(&buf, (Ipv4Addr::new(224, 0, 0, 251), 5353))?;
    tracing::debug!("mdns enumeration query sent");
    Ok(())
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
    for ans in pkt.answers.iter() {
        let name = ans.name.to_string();
        match &ans.rdata {
            RData::A(a) => {
                let ip: Ipv4Addr = Ipv4Addr::from(a.address);
                update_for_ip(db, ip, &name);
            }
            RData::PTR(p) => {
                // service enumeration replies
                let target = p.0.to_string();
                update_for_ip(db, src, &target);
            }
            RData::AAAA(_) => update_for_ip(db, src, &name),
            _ => {}
        }
    }
    for ans in pkt.additional_records.iter() {
        let name = ans.name.to_string();
        if let RData::A(a) = &ans.rdata {
            let ip: Ipv4Addr = Ipv4Addr::from(a.address);
            update_for_ip(db, ip, &name);
        }
    }
}

fn handle_ssdp(payload: &[u8], src: Ipv4Addr, db: &Arc<Mutex<Db>>) {
    let text = match std::str::from_utf8(payload) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut server: Option<&str> = None;
    let mut usn: Option<&str> = None;
    let mut nt: Option<&str> = None;
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        match k.as_str() {
            "server" => server = Some(v),
            "usn" => usn = Some(v),
            "nt" | "st" => nt = Some(v),
            _ => {}
        }
    }
    if let Some(s) = server {
        // usually "Linux/5.10 UPnP/1.0 Foo/1.0" - take last non-UPnP token
        let tail = s.split_whitespace().last().unwrap_or(s);
        if !tail.is_empty() && !tail.starts_with("UPnP") {
            update_for_ip(db, src, tail);
            return;
        }
    }
    if let Some(u) = usn.or(nt) {
        // "urn:schemas-upnp-org:device:MediaRenderer:1" → MediaRenderer
        if let Some(tail) = u.split(':').last() {
            if !tail.is_empty() {
                update_for_ip(db, src, tail);
            }
        }
    }
}

fn handle_nbns(payload: &[u8], src: Ipv4Addr, db: &Arc<Mutex<Db>>) {
    if payload.len() < 12 {
        return;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags & 0x8000) != 0;
    if !is_response {
        return;
    }
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
    let name_bytes = &decoded[..15];
    let name = String::from_utf8_lossy(name_bytes).trim().to_string();
    if !name.is_empty() {
        update_for_ip(db, src, &name);
    }
}
