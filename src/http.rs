use anyhow::{Context, Result};
use axum::Router;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::{broadcast, mpsc};

use crate::db::Db;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Db>>,
    pub intensive_tx: mpsc::Sender<(String, String, bool)>,
    pub rescan_tx: mpsc::Sender<()>,
    pub notify_on: Arc<AtomicBool>,
    pub iface: String,
    pub live_tx: broadcast::Sender<String>,
    pub arp_scanning: Arc<AtomicBool>,
    pub intensive_inflight: Arc<AtomicUsize>,
    pub map_tx: mpsc::Sender<()>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_ui))
        .route("/api/state", get(api_state))
        .route("/api/intensive", post(api_intensive))
        .route("/api/mute", post(api_mute))
        .route("/api/unmute", post(api_unmute))
        .route("/api/toggle_mute", post(api_toggle_mute))
        .route("/api/rescan", post(api_rescan))
        .route("/api/status", get(api_status))
        .route("/ws", get(ws_handler))
        .with_state(state)
}

pub async fn serve(addr: SocketAddr, state: AppState) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    tracing::info!(%addr, "http server listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

async fn serve_ui() -> Html<String> {
    Html(crate::html::template_empty())
}

async fn api_state(State(state): State<AppState>) -> impl IntoResponse {
    let json = {
        let db = state.db.lock().unwrap();
        crate::html::build_snapshot(&db, &state.iface, progress_of(&state))
    };
    ([(axum::http::header::CONTENT_TYPE, "application/json")], json)
}

fn progress_of(s: &AppState) -> crate::html::Progress {
    crate::html::Progress {
        arp_scanning: s.arp_scanning.load(Ordering::Relaxed),
        intensive_inflight: s.intensive_inflight.load(Ordering::Relaxed),
    }
}

async fn api_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let (total, online, with_ports, with_os) = {
        let db = state.db.lock().unwrap();
        let devs = db.all_devices().unwrap_or_default();
        let total = devs.len();
        let online = devs.iter().filter(|d| d.connected).count();
        let mut with_ports = 0usize;
        let mut with_os = 0usize;
        for d in &devs {
            if d.os_guess.is_some() {
                with_os += 1;
            }
            if db.ports_for(&d.mac).map(|v| !v.is_empty()).unwrap_or(false) {
                with_ports += 1;
            }
        }
        (total, online, with_ports, with_os)
    };
    Json(serde_json::json!({
        "iface": state.iface,
        "total": total,
        "online": online,
        "with_ports": with_ports,
        "with_os": with_os,
        "notifications": state.notify_on.load(Ordering::Relaxed),
    }))
}

#[derive(Deserialize)]
struct IntensiveReq {
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    all: bool,
    #[serde(default)]
    full_ports: bool,
}

async fn api_intensive(
    State(state): State<AppState>,
    Json(req): Json<IntensiveReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if req.full_ports && req.all {
        return Err((
            StatusCode::BAD_REQUEST,
            "full_ports cannot combine with all".into(),
        ));
    }
    let targets: Vec<(String, String)> = {
        let db = state.db.lock().unwrap();
        let devs = db.all_devices().unwrap_or_default();
        if req.all {
            devs.into_iter()
                .filter(|d| d.connected)
                .map(|d| (d.mac, d.ip))
                .collect()
        } else if let Some(mac) = &req.mac {
            devs.into_iter()
                .filter(|d| d.mac.eq_ignore_ascii_case(mac))
                .map(|d| (d.mac, d.ip))
                .collect()
        } else if let Some(ip) = &req.ip {
            devs.into_iter()
                .filter(|d| d.ip == *ip)
                .map(|d| (d.mac, d.ip))
                .collect()
        } else {
            return Err((StatusCode::BAD_REQUEST, "specify mac, ip, or all".into()));
        }
    };
    if targets.is_empty() {
        return Err((StatusCode::NOT_FOUND, "no matching device".into()));
    }
    let n = targets.len();
    for (mac, ip) in targets {
        state.intensive_inflight.fetch_add(1, Ordering::Relaxed);
        if state.intensive_tx.try_send((mac, ip, req.full_ports)).is_err() {
            state.intensive_inflight.fetch_sub(1, Ordering::Relaxed);
        }
    }
    let _ = state.map_tx.try_send(());
    Ok(Json(serde_json::json!({
        "ok": true,
        "queued": n,
        "full_ports": req.full_ports,
    })))
}

async fn api_mute(State(state): State<AppState>) -> Json<serde_json::Value> {
    state.notify_on.store(false, Ordering::Relaxed);
    Json(serde_json::json!({"ok": true, "notifications": false}))
}

async fn api_unmute(State(state): State<AppState>) -> Json<serde_json::Value> {
    state.notify_on.store(true, Ordering::Relaxed);
    Json(serde_json::json!({"ok": true, "notifications": true}))
}

async fn api_toggle_mute(State(state): State<AppState>) -> Json<serde_json::Value> {
    let prev = state.notify_on.fetch_xor(true, Ordering::Relaxed);
    Json(serde_json::json!({"ok": true, "notifications": !prev}))
}

async fn api_rescan(State(state): State<AppState>) -> Json<serde_json::Value> {
    let _ = state.rescan_tx.try_send(());
    Json(serde_json::json!({"ok": true}))
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut socket: WebSocket, state: AppState) {
    let mut rx = state.live_tx.subscribe();
    let init = {
        let db = state.db.lock().unwrap();
        crate::html::build_snapshot(&db, &state.iface, progress_of(&state))
    };
    if socket.send(Message::Text(init.into())).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(m) => { if socket.send(Message::Text(m.into())).await.is_err() { break; } }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            },
            client = socket.recv() => match client {
                Some(Ok(Message::Ping(p))) => { let _ = socket.send(Message::Pong(p)).await; }
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(_)) => break,
                _ => {}
            }
        }
    }
}
