use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime};

const OUI_URL: &str = "https://standards-oui.ieee.org/oui/oui.csv";

pub struct OuiDb {
    map: HashMap<String, String>,
}

impl OuiDb {
    pub fn load_or_fetch<P: AsRef<Path>>(path: P, max_age: Duration) -> Result<Self> {
        let path = path.as_ref();
        let need_fetch = match std::fs::metadata(path) {
            Ok(m) => m
                .modified()
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .map(|age| age > max_age)
                .unwrap_or(true),
            Err(_) => true,
        };
        if need_fetch {
            if let Err(e) = fetch(path) {
                if !path.exists() {
                    return Err(e);
                }
                tracing::warn!(?e, "oui fetch failed, using stale cache");
            }
        }
        Self::load(path)
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_path(path.as_ref())
            .with_context(|| format!("open oui csv: {}", path.as_ref().display()))?;
        let mut map = HashMap::new();
        for rec in rdr.records() {
            let rec = rec?;
            if rec.len() < 3 {
                continue;
            }
            let prefix = rec.get(1).unwrap_or("").trim().replace('-', "").to_uppercase();
            let vendor = rec.get(2).unwrap_or("").trim().to_string();
            if !prefix.is_empty() && !vendor.is_empty() {
                map.insert(prefix, vendor);
            }
        }
        Ok(Self { map })
    }

    pub fn empty() -> Self {
        Self { map: HashMap::new() }
    }

    pub fn lookup(&self, mac: &str) -> Option<&str> {
        let clean: String = mac
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>()
            .to_uppercase();
        for n in (1..=clean.len().min(8)).rev() {
            if let Some(v) = self.map.get(&clean[..n]) {
                return Some(v.as_str());
            }
        }
        None
    }
}

fn fetch(path: &Path) -> Result<()> {
    tracing::info!(url = OUI_URL, "fetching oui db");
    let body = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?
        .get(OUI_URL)
        .send()?
        .error_for_status()?
        .bytes()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, &body)?;
    Ok(())
}
