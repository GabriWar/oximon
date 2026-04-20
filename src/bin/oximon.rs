use anyhow::Result;
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use oximon::db::Db;
use oximon::ipc::{self, Cmd as IpcCmd, Target};
use oximon::model::{Device, Event as DevEvent, Port};
use oximon::paths;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, TableState};
use std::io;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(name = "oximon", about = "oximon TUI")]
struct Args {
    /// refresh interval ms
    #[arg(long, default_value_t = 1000)]
    refresh_ms: u64,
}

struct Ui {
    devices: Vec<Device>,
    events: Vec<DevEvent>,
    ports: Vec<Port>,
    selected: TableState,
    last_refresh: Instant,
    flash: Option<(String, Instant)>,
}

impl Ui {
    fn new() -> Self {
        Self {
            devices: Vec::new(),
            events: Vec::new(),
            ports: Vec::new(),
            selected: TableState::default(),
            last_refresh: Instant::now() - Duration::from_secs(60),
            flash: None,
        }
    }

    fn set_flash(&mut self, msg: impl Into<String>) {
        self.flash = Some((msg.into(), Instant::now()));
    }

    fn selected_mac(&self) -> Option<String> {
        self.selected
            .selected()
            .and_then(|i| self.devices.get(i))
            .map(|d| d.mac.clone())
    }

    fn refresh(&mut self, db: &Db) -> Result<()> {
        self.devices = db.all_devices()?;
        self.events = db.recent_events(50)?;
        let sel = self.selected.selected().unwrap_or(0).min(self.devices.len().saturating_sub(1));
        if !self.devices.is_empty() {
            self.selected.select(Some(sel));
            let mac = &self.devices[sel].mac;
            self.ports = db.ports_for(mac).unwrap_or_default();
        } else {
            self.ports.clear();
        }
        self.last_refresh = Instant::now();
        Ok(())
    }

    fn next(&mut self) {
        if self.devices.is_empty() {
            return;
        }
        let cur = self.selected.selected().unwrap_or(0);
        self.selected.select(Some((cur + 1) % self.devices.len()));
    }

    fn prev(&mut self) {
        if self.devices.is_empty() {
            return;
        }
        let cur = self.selected.selected().unwrap_or(0);
        let n = self.devices.len();
        self.selected.select(Some((cur + n - 1) % n));
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let res = run(&mut term, args.refresh_ms);

    disable_raw_mode()?;
    crossterm::execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    res
}

fn run<B: ratatui::backend::Backend>(term: &mut Terminal<B>, refresh_ms: u64) -> Result<()> {
    let db_path = paths::state_db()?;
    let db = Db::open(&db_path)?;
    let mut ui = Ui::new();
    ui.refresh(&db)?;
    let refresh = Duration::from_millis(refresh_ms);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    loop {
        term.draw(|f| draw(f, &mut ui))?;

        let timeout = refresh.saturating_sub(ui.last_refresh.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(());
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        ui.next();
                        ui.refresh(&db)?;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        ui.prev();
                        ui.refresh(&db)?;
                    }
                    KeyCode::Char('r') => ui.refresh(&db)?,
                    KeyCode::Char('R') => {
                        let msg = rt.block_on(send_ipc(IpcCmd::Rescan));
                        ui.set_flash(msg);
                    }
                    KeyCode::Char('i') => {
                        if let Some(mac) = ui.selected_mac() {
                            let msg = rt.block_on(send_ipc(IpcCmd::Intensive {
                                target: Target::Mac { mac },
                            }));
                            ui.set_flash(msg);
                        }
                    }
                    KeyCode::Char('a') => {
                        let msg = rt.block_on(send_ipc(IpcCmd::Intensive {
                            target: Target::All,
                        }));
                        ui.set_flash(msg);
                    }
                    KeyCode::Char('m') => {
                        let msg = rt.block_on(send_ipc(IpcCmd::ToggleMute));
                        ui.set_flash(msg);
                    }
                    _ => {}
                }
            }
        }
        if ui.last_refresh.elapsed() >= refresh {
            ui.refresh(&db)?;
        }
    }
}

async fn send_ipc(cmd: IpcCmd) -> String {
    match ipc::send_cmd(&cmd).await {
        Ok(r) => r.msg.unwrap_or_else(|| if r.ok { "ok".into() } else { "err".into() }),
        Err(e) => format!("ipc: {e}"),
    }
}

fn draw(f: &mut ratatui::Frame, ui: &mut Ui) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(12), Constraint::Length(1)])
        .split(f.area());

    draw_devices(f, root[0], ui);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(root[1]);

    draw_events(f, bottom[0], ui);
    draw_detail(f, bottom[1], ui);
    draw_status(f, root[2], ui);
}

fn draw_devices(f: &mut ratatui::Frame, area: Rect, ui: &mut Ui) {
    let header = Row::new(
        ["", "IP", "MAC", "hostname", "vendor", "rtt", "last_seen"]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().add_modifier(Modifier::BOLD))),
    );

    let rows: Vec<Row> = ui
        .devices
        .iter()
        .map(|d| {
            let marker = if d.connected { "●" } else { "○" };
            let color = if d.connected { Color::Green } else { Color::DarkGray };
            let rtt = d.rtt_ms.map(|v| format!("{v:.1}ms")).unwrap_or_default();
            Row::new(vec![
                Cell::from(marker).style(Style::default().fg(color)),
                Cell::from(d.ip.clone()),
                Cell::from(d.mac.clone()),
                Cell::from(d.hostname.clone().unwrap_or_default()),
                Cell::from(d.vendor.clone().unwrap_or_default()),
                Cell::from(rtt),
                Cell::from(d.last_seen.format("%H:%M:%S").to_string()),
            ])
        })
        .collect();

    let tbl = Table::new(
        rows,
        [
            Constraint::Length(2),
            Constraint::Length(15),
            Constraint::Length(17),
            Constraint::Length(22),
            Constraint::Length(22),
            Constraint::Length(8),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!(" devices [{}] ", ui.devices.len()))
            .borders(Borders::ALL),
    )
    .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");

    f.render_stateful_widget(tbl, area, &mut ui.selected);
}

fn draw_events(f: &mut ratatui::Frame, area: Rect, ui: &Ui) {
    let items: Vec<ListItem> = ui
        .events
        .iter()
        .map(|e| {
            let color = match e.kind {
                oximon::model::EventKind::Connect => Color::Green,
                oximon::model::EventKind::Disconnect => Color::Red,
                oximon::model::EventKind::IntensiveDone => Color::Cyan,
                _ => Color::Yellow,
            };
            let detail = e.detail.as_deref().unwrap_or("");
            ListItem::new(Line::from(vec![
                Span::styled(e.ts.format("%H:%M:%S ").to_string(), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{:<17} ", e.mac), Style::default().fg(Color::White)),
                Span::styled(format!("{:<12} ", e.kind.as_str()), Style::default().fg(color)),
                Span::raw(detail.to_string()),
            ]))
        })
        .collect();

    let list = List::new(items).block(Block::default().title(" events ").borders(Borders::ALL));
    f.render_widget(list, area);
}

fn draw_detail(f: &mut ratatui::Frame, area: Rect, ui: &Ui) {
    let sel = ui.selected.selected();
    let lines: Vec<Line> = match sel.and_then(|i| ui.devices.get(i)) {
        None => vec![Line::from("no device selected")],
        Some(d) => {
            let mut v = vec![
                Line::from(vec![Span::styled("mac     ", Style::default().fg(Color::DarkGray)), Span::raw(d.mac.clone())]),
                Line::from(vec![Span::styled("ip      ", Style::default().fg(Color::DarkGray)), Span::raw(d.ip.clone())]),
                Line::from(vec![Span::styled("host    ", Style::default().fg(Color::DarkGray)), Span::raw(d.hostname.clone().unwrap_or("?".into()))]),
                Line::from(vec![Span::styled("vendor  ", Style::default().fg(Color::DarkGray)), Span::raw(d.vendor.clone().unwrap_or("?".into()))]),
                Line::from(vec![Span::styled("os      ", Style::default().fg(Color::DarkGray)), Span::raw(d.os_guess.clone().unwrap_or("?".into()))]),
                Line::from(vec![Span::styled("first   ", Style::default().fg(Color::DarkGray)), Span::raw(d.first_seen.format("%Y-%m-%d %H:%M").to_string())]),
            ];
            if !ui.ports.is_empty() {
                v.push(Line::from(Span::styled("ports", Style::default().add_modifier(Modifier::BOLD))));
                for p in &ui.ports {
                    let svc = p.service.as_deref().unwrap_or("");
                    let banner = p.banner.as_deref().unwrap_or("");
                    v.push(Line::from(format!(
                        "  {}/{:<4} {:<7} {} {}",
                        p.port, p.proto, p.state, svc, banner
                    )));
                }
            }
            v
        }
    };
    let p = Paragraph::new(lines).block(Block::default().title(" detail ").borders(Borders::ALL));
    f.render_widget(p, area);
}

fn draw_status(f: &mut ratatui::Frame, area: Rect, ui: &Ui) {
    let mut spans = vec![
        Span::styled(" oximon ", Style::default().bg(Color::Blue).fg(Color::White)),
        Span::raw("  q quit  j/k select  r refresh  i intensive  a scan-all  m mute  R rescan"),
    ];
    if let Some((msg, t)) = ui.flash.as_ref() {
        if t.elapsed() < Duration::from_secs(4) {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                format!("[{msg}]"),
                Style::default().fg(Color::Yellow),
            ));
        }
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}
