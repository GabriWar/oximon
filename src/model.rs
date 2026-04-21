use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub connected: bool,
    pub rtt_ms: Option<f32>,
    pub last_intensive: Option<DateTime<Utc>>,
    pub os_guess: Option<String>,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventKind {
    Connect,
    Disconnect,
    IpChange,
    HostnameChange,
    IntensiveDone,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Connect => "connect",
            EventKind::Disconnect => "disconnect",
            EventKind::IpChange => "ip_change",
            EventKind::HostnameChange => "hostname_change",
            EventKind::IntensiveDone => "intensive_done",
        }
    }

    pub fn parse(s: &str) -> Option<EventKind> {
        Some(match s {
            "connect" => EventKind::Connect,
            "disconnect" => EventKind::Disconnect,
            "ip_change" => EventKind::IpChange,
            "hostname_change" => EventKind::HostnameChange,
            "intensive_done" => EventKind::IntensiveDone,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: i64,
    pub mac: String,
    pub kind: EventKind,
    pub ts: DateTime<Utc>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub mac: String,
    pub port: u16,
    pub proto: String,
    pub state: String,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub ts: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ScanHit {
    pub ip: String,
    pub mac: String,
    pub rtt_ms: Option<f32>,
}
