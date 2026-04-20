# oximon (WIP)

rust rewrite of [moni.py](https://github.com/GabriWar/moni.py). network monitor.

**status: WIP. breaks. expect rough edges.**

## what it is

- passive ARP sweep of your subnet (pure rust, `pnet`) → devices + vendor (OUI) + hostname (rDNS) + rtt
- on-demand `nmap -sV -O` intensive scan → ports, services, banners, os fingerprint
- sqlite state in `~/.local/share/oximon/`
- ratatui TUI + systray + desktop notifications
- local HTTP server w/ live cytoscape.js map at `http://127.0.0.1:3737/`

## build + run

```sh
cargo build --release
sudo setcap cap_net_raw,cap_net_admin+eip target/release/oximond
sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)
./target/release/oximond
```

open `http://127.0.0.1:3737/` for the web UI.

## cli

```sh
oximond                                  # daemon
oximond intensive --ip X.X.X.X           # trigger scan
oximond intensive --ip X.X.X.X --full-ports
oximond intensive --all
oximond mute / unmute / toggle-mute / rescan / status
oximon                                   # TUI
```

## flags

| flag | default | |
|------|---------|--|
| `--subnet` | auto | CIDR override |
| `--iface` | auto | iface override |
| `--arp-passes` | `3` | ARP sweep passes |
| `--arp-window-ms` | `1500` | recv window per pass |
| `--intensive-workers` | `16` | parallel nmap |
| `--host` | `127.0.0.1` | http bind |
| `--port` | `3737` | http port |
| `--no-tray`, `--no-http`, `--no-notify` | | disable bits |

## license

MIT
