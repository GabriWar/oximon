use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Cmd {
    Intensive {
        target: Target,
        #[serde(default)]
        full_ports: bool,
    },
    Mute,
    Unmute,
    ToggleMute,
    Status,
    Rescan,
    SetAlias {
        mac: String,
        #[serde(default)]
        alias: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    All,
    Mac { mac: String },
    Ip { ip: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    pub msg: Option<String>,
    pub data: Option<serde_json::Value>,
}

impl Reply {
    pub fn ok(msg: impl Into<String>) -> Self {
        Self { ok: true, msg: Some(msg.into()), data: None }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self { ok: false, msg: Some(msg.into()), data: None }
    }
    pub fn data(v: serde_json::Value) -> Self {
        Self { ok: true, msg: None, data: Some(v) }
    }
}

pub fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(p).join("oximon.sock")
    } else {
        let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
        PathBuf::from(format!("/tmp/oximon-{user}.sock"))
    }
}

pub async fn send_cmd(cmd: &Cmd) -> Result<Reply> {
    let path = socket_path();
    let mut stream = UnixStream::connect(&path)
        .await
        .with_context(|| format!("connect {} (daemon running?)", path.display()))?;
    let line = serde_json::to_string(cmd)?;
    stream.write_all(line.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.shutdown().await.ok();
    let (rh, _wh) = stream.split();
    let mut reader = BufReader::new(rh);
    let mut resp = String::new();
    reader.read_line(&mut resp).await?;
    let reply: Reply = serde_json::from_str(resp.trim())
        .with_context(|| format!("parse reply: {resp}"))?;
    Ok(reply)
}

pub struct CommandEnvelope {
    pub cmd: Cmd,
    pub reply: tokio::sync::oneshot::Sender<Reply>,
}

pub async fn serve(
    path: &Path,
    tx: tokio::sync::mpsc::Sender<CommandEnvelope>,
) -> Result<()> {
    let _ = std::fs::remove_file(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(path)?;
    tracing::info!(path = %path.display(), "ipc listening");
    loop {
        let (mut stream, _) = listener.accept().await?;
        let tx = tx.clone();
        tokio::spawn(async move {
            let (rh, mut wh) = stream.split();
            let mut reader = BufReader::new(rh);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            let cmd: Cmd = match serde_json::from_str(line.trim()) {
                Ok(c) => c,
                Err(e) => {
                    let r = Reply::err(format!("bad cmd: {e}"));
                    let _ = wh.write_all(serde_json::to_string(&r).unwrap_or_default().as_bytes()).await;
                    let _ = wh.write_all(b"\n").await;
                    return;
                }
            };
            let (otx, orx) = tokio::sync::oneshot::channel();
            if tx.send(CommandEnvelope { cmd, reply: otx }).await.is_err() {
                return;
            }
            let reply = orx.await.unwrap_or_else(|_| Reply::err("no reply"));
            let _ = wh
                .write_all(serde_json::to_string(&reply).unwrap_or_default().as_bytes())
                .await;
            let _ = wh.write_all(b"\n").await;
        });
    }
}
