use ksni::{Tray, menu::*};
use tokio::sync::mpsc::UnboundedSender;

#[derive(Debug, Clone)]
pub enum TrayAction {
    ToggleMute,
    ScanAll,
    Quit,
}

pub struct OximonTray {
    pub notifications: bool,
    pub total: usize,
    pub online: usize,
    pub iface: String,
    pub tx: UnboundedSender<TrayAction>,
}

impl Tray for OximonTray {
    fn icon_name(&self) -> String {
        if self.notifications {
            "network-wired".into()
        } else {
            "network-offline".into()
        }
    }

    fn title(&self) -> String {
        "oximon".into()
    }

    fn id(&self) -> String {
        "oximon".into()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "oximon".into(),
            description: format!(
                "{} devices · {} online · notifications {}",
                self.total,
                self.online,
                if self.notifications { "on" } else { "muted" }
            ),
            icon_name: String::new(),
            icon_pixmap: Vec::new(),
        }
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        vec![
            StandardItem {
                label: format!(
                    "oximon · {} · {}/{} online",
                    self.iface, self.online, self.total
                ),
                enabled: false,
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            CheckmarkItem {
                label: "notifications".into(),
                checked: self.notifications,
                activate: Box::new(|t: &mut OximonTray| {
                    let _ = t.tx.send(TrayAction::ToggleMute);
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "scan all (intensive)".into(),
                icon_name: "system-search".into(),
                activate: Box::new(|t: &mut OximonTray| {
                    let _ = t.tx.send(TrayAction::ScanAll);
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "quit".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|t: &mut OximonTray| {
                    let _ = t.tx.send(TrayAction::Quit);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}
