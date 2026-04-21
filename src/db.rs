use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

use crate::model::{Device, Event, EventKind, Port};

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                hostname TEXT,
                vendor TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                connected INTEGER NOT NULL DEFAULT 0,
                rtt_ms REAL,
                last_intensive TEXT,
                os_guess TEXT,
                alias TEXT
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                kind TEXT NOT NULL,
                ts TEXT NOT NULL,
                detail TEXT
            );
            CREATE INDEX IF NOT EXISTS events_mac_ts ON events(mac, ts DESC);
            CREATE INDEX IF NOT EXISTS events_ts ON events(ts DESC);

            -- migrations for existing dbs
            "#,
        )?;
        // attempt alias column add (ignore error if exists)
        let _ = self.conn.execute("ALTER TABLE devices ADD COLUMN alias TEXT", []);
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS ports (
                mac TEXT NOT NULL,
                port INTEGER NOT NULL,
                proto TEXT NOT NULL,
                state TEXT NOT NULL,
                service TEXT,
                banner TEXT,
                ts TEXT NOT NULL,
                PRIMARY KEY (mac, port, proto)
            );
            "#,
        )?;
        Ok(())
    }

    pub fn upsert_device(&self, d: &Device) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO devices (mac, ip, hostname, vendor, first_seen, last_seen, connected, rtt_ms, last_intensive, os_guess, alias)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ON CONFLICT(mac) DO UPDATE SET
                ip = excluded.ip,
                hostname = COALESCE(excluded.hostname, devices.hostname),
                vendor = COALESCE(excluded.vendor, devices.vendor),
                last_seen = excluded.last_seen,
                connected = excluded.connected,
                rtt_ms = excluded.rtt_ms
            "#,
            params![
                d.mac,
                d.ip,
                d.hostname,
                d.vendor,
                d.first_seen.to_rfc3339(),
                d.last_seen.to_rfc3339(),
                d.connected as i32,
                d.rtt_ms,
                d.last_intensive.map(|t| t.to_rfc3339()),
                d.os_guess,
                d.alias,
            ],
        )?;
        Ok(())
    }

    pub fn set_alias(&self, mac: &str, alias: Option<&str>) -> Result<usize> {
        let n = self.conn.execute(
            "UPDATE devices SET alias = ?2 WHERE mac = ?1",
            params![mac, alias],
        )?;
        Ok(n)
    }

    pub fn mark_disconnected(&self, mac: &str, ts: DateTime<Utc>) -> Result<()> {
        self.conn.execute(
            "UPDATE devices SET connected = 0, last_seen = ?2 WHERE mac = ?1",
            params![mac, ts.to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn get_device(&self, mac: &str) -> Result<Option<Device>> {
        let d = self
            .conn
            .query_row(
                r#"SELECT mac, ip, hostname, vendor, first_seen, last_seen, connected, rtt_ms, last_intensive, os_guess, alias
                   FROM devices WHERE mac = ?1"#,
                params![mac],
                row_to_device,
            )
            .optional()?;
        Ok(d)
    }

    pub fn all_devices(&self) -> Result<Vec<Device>> {
        let mut stmt = self.conn.prepare(
            r#"SELECT mac, ip, hostname, vendor, first_seen, last_seen, connected, rtt_ms, last_intensive, os_guess, alias
               FROM devices ORDER BY connected DESC, ip ASC"#,
        )?;
        let rows = stmt
            .query_map([], row_to_device)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn prune_events(&self, keep_last_n: i64, max_age_days: i64) -> Result<usize> {
        let n1 = self.conn.execute(
            "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY ts DESC LIMIT ?1)",
            params![keep_last_n],
        )?;
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(max_age_days)).to_rfc3339();
        let n2 = self.conn.execute("DELETE FROM events WHERE ts < ?1", params![cutoff])?;
        Ok(n1 + n2)
    }

    pub fn insert_event(&self, mac: &str, kind: EventKind, ts: DateTime<Utc>, detail: Option<&str>) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO events (mac, kind, ts, detail) VALUES (?1, ?2, ?3, ?4)",
            params![mac, kind.as_str(), ts.to_rfc3339(), detail],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn recent_events(&self, limit: i64) -> Result<Vec<Event>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, mac, kind, ts, detail FROM events ORDER BY ts DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |row| {
                let kind_s: String = row.get(2)?;
                let ts_s: String = row.get(3)?;
                Ok(Event {
                    id: row.get(0)?,
                    mac: row.get(1)?,
                    kind: EventKind::parse(&kind_s).unwrap_or(EventKind::Connect),
                    ts: parse_ts(&ts_s),
                    detail: row.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn replace_ports(&mut self, mac: &str, ports: &[Port]) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM ports WHERE mac = ?1", params![mac])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO ports (mac, port, proto, state, service, banner, ts) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for p in ports {
                stmt.execute(params![
                    p.mac,
                    p.port as i64,
                    p.proto,
                    p.state,
                    p.service,
                    p.banner,
                    p.ts.to_rfc3339()
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn ports_for(&self, mac: &str) -> Result<Vec<Port>> {
        let mut stmt = self.conn.prepare(
            "SELECT mac, port, proto, state, service, banner, ts FROM ports WHERE mac = ?1 ORDER BY port ASC",
        )?;
        let rows = stmt
            .query_map(params![mac], |row| {
                let ts_s: String = row.get(6)?;
                Ok(Port {
                    mac: row.get(0)?,
                    port: row.get::<_, i64>(1)? as u16,
                    proto: row.get(2)?,
                    state: row.get(3)?,
                    service: row.get(4)?,
                    banner: row.get(5)?,
                    ts: parse_ts(&ts_s),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn set_intensive_done(&self, mac: &str, ts: DateTime<Utc>, os_guess: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE devices SET last_intensive = ?2, os_guess = COALESCE(?3, os_guess) WHERE mac = ?1",
            params![mac, ts.to_rfc3339(), os_guess],
        )?;
        Ok(())
    }
}

fn row_to_device(row: &rusqlite::Row<'_>) -> rusqlite::Result<Device> {
    let first_seen_s: String = row.get(4)?;
    let last_seen_s: String = row.get(5)?;
    let last_intensive_s: Option<String> = row.get(8)?;
    Ok(Device {
        mac: row.get(0)?,
        ip: row.get(1)?,
        hostname: row.get(2)?,
        vendor: row.get(3)?,
        first_seen: parse_ts(&first_seen_s),
        last_seen: parse_ts(&last_seen_s),
        connected: row.get::<_, i64>(6)? != 0,
        rtt_ms: row.get(7)?,
        last_intensive: last_intensive_s.as_deref().map(parse_ts),
        os_guess: row.get(9)?,
        alias: row.get(10).ok(),
    })
}

fn parse_ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}
