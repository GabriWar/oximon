use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub scan_interval_secs: u64,
    pub intensive_refresh_hours: u64,
    pub iface: Option<String>,
    pub subnet: Option<String>,
    pub notify: bool,
    pub oui_max_age_days: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan_interval_secs: 60,
            intensive_refresh_hours: 24,
            iface: None,
            subnet: None,
            notify: true,
            oui_max_age_days: 30,
        }
    }
}

impl Config {
    pub fn scan_interval(&self) -> Duration {
        Duration::from_secs(self.scan_interval_secs)
    }
}
