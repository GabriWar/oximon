use anyhow::{Context, Result};
use chrono::Utc;
use quick_xml::events::Event as XmlEvent;
use quick_xml::reader::Reader;
use std::process::Command;

use crate::model::Port;

pub struct IntensiveResult {
    pub ports: Vec<Port>,
    pub os_guess: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    pub full_ports: bool,
}

pub fn run(mac: &str, ip: &str) -> Result<IntensiveResult> {
    run_with(mac, ip, Options::default())
}

pub fn run_with(mac: &str, ip: &str, opts: Options) -> Result<IntensiveResult> {
    let mut args: Vec<&str> = vec![
        "--privileged",
        "-sV",
        "-O",
        "--osscan-guess",
        "--version-light",
        "-Pn",
        "--open",
        "-T4",
    ];
    if opts.full_ports {
        args.push("-p-");
    } else {
        args.extend_from_slice(&["--top-ports", "1000"]);
    }
    args.extend_from_slice(&["-oX", "-", ip]);

    let out = Command::new("nmap")
        .args(&args)
        .output()
        .context("nmap exec (install nmap)")?;
    if !out.status.success() {
        tracing::warn!(status = ?out.status, "nmap non-zero");
    }
    let xml = String::from_utf8_lossy(&out.stdout);
    parse(mac, &xml)
}

fn parse(mac: &str, xml: &str) -> Result<IntensiveResult> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut ports: Vec<Port> = Vec::new();
    let mut os_guess: Option<String> = None;

    let mut cur_portid: Option<u16> = None;
    let mut cur_proto: Option<String> = None;
    let mut cur_state: Option<String> = None;
    let mut cur_service: Option<String> = None;
    let mut cur_banner: Option<String> = None;
    let mut buf = Vec::new();
    let ts = Utc::now();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) | Ok(XmlEvent::Empty(e)) => {
                let name = e.name();
                let tag = std::str::from_utf8(name.as_ref()).unwrap_or("").to_string();
                match tag.as_str() {
                    "port" => {
                        for a in e.attributes().flatten() {
                            let key = std::str::from_utf8(a.key.as_ref()).unwrap_or("");
                            let val = a.unescape_value().unwrap_or_default().to_string();
                            match key {
                                "portid" => cur_portid = val.parse().ok(),
                                "protocol" => cur_proto = Some(val),
                                _ => {}
                            }
                        }
                    }
                    "state" => {
                        for a in e.attributes().flatten() {
                            if std::str::from_utf8(a.key.as_ref()).unwrap_or("") == "state" {
                                cur_state =
                                    Some(a.unescape_value().unwrap_or_default().to_string());
                            }
                        }
                    }
                    "service" => {
                        let mut name_v: Option<String> = None;
                        let mut product: Option<String> = None;
                        let mut version: Option<String> = None;
                        for a in e.attributes().flatten() {
                            let k = std::str::from_utf8(a.key.as_ref()).unwrap_or("");
                            let v = a.unescape_value().unwrap_or_default().to_string();
                            match k {
                                "name" => name_v = Some(v),
                                "product" => product = Some(v),
                                "version" => version = Some(v),
                                _ => {}
                            }
                        }
                        cur_service = name_v;
                        let banner = [product.as_deref(), version.as_deref()]
                            .into_iter()
                            .flatten()
                            .collect::<Vec<_>>()
                            .join(" ");
                        if !banner.is_empty() {
                            cur_banner = Some(banner);
                        }
                    }
                    "osmatch" => {
                        if os_guess.is_none() {
                            for a in e.attributes().flatten() {
                                if std::str::from_utf8(a.key.as_ref()).unwrap_or("") == "name" {
                                    os_guess =
                                        Some(a.unescape_value().unwrap_or_default().to_string());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(XmlEvent::End(e)) => {
                let name = e.name();
                let tag = std::str::from_utf8(name.as_ref()).unwrap_or("");
                if tag == "port" {
                    if let (Some(port), Some(proto)) = (cur_portid, cur_proto.take()) {
                        ports.push(Port {
                            mac: mac.to_string(),
                            port,
                            proto,
                            state: cur_state.take().unwrap_or_else(|| "unknown".into()),
                            service: cur_service.take(),
                            banner: cur_banner.take(),
                            ts,
                        });
                    }
                    cur_portid = None;
                }
            }
            Ok(XmlEvent::Eof) => break,
            Err(e) => {
                tracing::warn!(?e, "xml parse warn");
                break;
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(IntensiveResult { ports, os_guess })
}
