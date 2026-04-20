use anyhow::Result;
use notify_rust::Notification;

use crate::model::{Device, EventKind};

pub async fn emit(kind: EventKind, device: &Device) -> Result<()> {
    let (summary, body) = format_msg(kind, device);
    Notification::new()
        .summary(&summary)
        .body(&body)
        .appname("oximon")
        .icon("network-wired")
        .show_async()
        .await?;
    Ok(())
}

pub fn emit_detached(kind: EventKind, device: Device) {
    tokio::spawn(async move {
        if let Err(e) = emit(kind, &device).await {
            tracing::debug!(?e, "notify emit fail");
        }
    });
}

fn format_msg(kind: EventKind, d: &Device) -> (String, String) {
    let host = d.hostname.as_deref().unwrap_or("?");
    let vendor = d.vendor.as_deref().unwrap_or("?");
    match kind {
        EventKind::Connect => (
            format!("device online: {}", d.ip),
            format!("{} ({})\n{}\n{}", host, vendor, d.mac, d.ip),
        ),
        EventKind::Disconnect => (
            format!("device offline: {}", d.ip),
            format!("{} ({})\n{}", host, vendor, d.mac),
        ),
        EventKind::IpChange => (
            format!("ip change: {}", d.mac),
            format!("{} now at {}", host, d.ip),
        ),
        EventKind::HostnameChange => (
            format!("hostname change: {}", d.mac),
            format!("now: {}", host),
        ),
        EventKind::IntensiveDone => (
            format!("scan done: {}", d.ip),
            format!(
                "{} → os: {}",
                host,
                d.os_guess.as_deref().unwrap_or("unknown")
            ),
        ),
    }
}
