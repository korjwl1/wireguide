<p align="center">
  <img src="build/darwin/icons.icns" width="128" alt="WireGuide icon" />
</p>

<h1 align="center">WireGuide</h1>

<p align="center">
  A cross-platform WireGuard VPN client that actually works on macOS.
</p>

<p align="center">
  <a href="https://github.com/korjwl1/wireguide/releases/latest"><img src="https://img.shields.io/github/v/release/korjwl1/wireguide?style=flat-square" alt="Release" /></a>
  <a href="#install"><img src="https://img.shields.io/badge/homebrew-tap-blue?style=flat-square" alt="Homebrew" /></a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey?style=flat-square" alt="Platform" />
  <a href="LICENSE"><img src="https://img.shields.io/github/license/korjwl1/wireguide?style=flat-square" alt="License" /></a>
</p>

---

## Why WireGuide?

The official WireGuard client on macOS has long-standing issues that make it unreliable for daily use:

- **Silent DNS failures** — DNS configuration via `networksetup` is applied to a single service, not all of them. Switching between Wi-Fi and Ethernet mid-session silently breaks DNS resolution.
- **No route monitor** — When the upstream gateway changes (Wi-Fi switch, sleep/wake), wg-quick's `monitor_daemon` re-applies endpoint bypass routes. The official macOS app doesn't do this, causing the tunnel to silently die.
- **No kill switch** — Traffic leaks to the ISP when the tunnel goes down. The official client offers no firewall-level protection.
- **No auto-reconnect** — After sleep/wake or network change, the tunnel stays dead until the user manually reconnects.
- **Outdated UI** — The macOS app hasn't seen meaningful updates in years.

WireGuide fixes all of these by implementing the full `wg-quick` logic in Go (line-by-line verified against the reference `darwin.bash`, `linux.bash`, and the official `wireguard-windows` source), wrapped in a modern GUI.

---

## Screenshots

<table>
<tr>
<td><img src="docs/screenshots/main-connected.png" width="400" alt="Main — connected" /></td>
<td><img src="docs/screenshots/editor.png" width="400" alt="Config editor" /></td>
</tr>
<tr>
<td><img src="docs/screenshots/logs.png" width="400" alt="Logs" /></td>
<td><img src="docs/screenshots/settings.png" width="400" alt="Settings" /></td>
</tr>
</table>

<p align="center">
  <img src="docs/screenshots/tray.png" width="200" alt="System tray" />
</p>

---

## Features

| Feature | Description |
|---------|-------------|
| **Tunnel Management** | Import, create, edit, export `.conf` files. Drag-and-drop import. |
| **Config Editor** | CodeMirror 6 with WireGuard syntax highlighting and autocompletion |
| **System Tray** | Connection status badge, 1-click connect/disconnect |
| **Kill Switch** | Blocks all non-VPN traffic (macOS pf / Linux nftables / Windows WFAS) |
| **DNS Leak Protection** | Forces DNS through the VPN tunnel only |
| **Auto-Reconnect** | Exponential backoff with dead-connection detection |
| **Sleep/Wake Recovery** | Automatic reconnect after system sleep |
| **Route Monitor** | Re-applies endpoint bypass routes on gateway changes (wg-quick parity) |
| **Diagnostics** | Ping test, DNS leak test, route table visualization |
| **Auto-Update** | Checks GitHub Releases on startup, brew upgrade or direct install |
| **Speed Dashboard** | Real-time RX/TX graph |
| **i18n** | English, Korean, Japanese |
| **Dark / Light / System Theme** | Follows macOS appearance |

---

## Install

### macOS (Homebrew)

```bash
brew tap korjwl1/tap
brew install --cask wireguide
```

### macOS (Manual)

Download `WireGuide-vX.X.X-macOS-arm64.zip` from [Releases](https://github.com/korjwl1/wireguide/releases), unzip, and move to `/Applications`.

### Build from Source

```bash
# Prerequisites
brew install go node
go install github.com/go-task/task/v3/cmd/task@latest
go install github.com/wailsapp/wails/v3/cmd/wails3@latest

# Build
task build

# Run
./bin/wireguide
```

---

## Architecture

```
┌─────────────────────┐         ┌──────────────────────────┐
│   GUI Process        │  UDS    │   Helper Process (root)  │
│   (Wails + Svelte)   │◄──────►│   wireguard-go + wgctrl  │
│                      │ JSON-  │   TUN / routing / DNS     │
│   Wails bindings ──► │  RPC   │   kill switch / firewall  │
│   CodeMirror editor  │        │   reconnect monitor       │
│   System tray        │        │   route monitor           │
└─────────────────────┘         └──────────────────────────┘
```

- **Single binary** — The same `wireguide` binary runs as either GUI or helper, selected by `--helper` flag.
- **Privilege separation** — The GUI runs unprivileged. The helper runs as root (spawned via `osascript` on macOS, `pkexec` on Linux, UAC on Windows) and manages the TUN device, routing, and firewall.
- **IPC** — JSON-RPC over Unix domain socket (macOS/Linux) or named pipe (Windows). Peer credential verification prevents unauthorized access.
- **Helper lifecycle** — The helper stays alive as long as a tunnel is active (wg-quick semantics). Shuts down 10 seconds after the last GUI disconnects with no active tunnel.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Go 1.23+ |
| GUI | [Wails v3](https://wails.io) |
| Frontend | Svelte + Vite |
| WireGuard | [wireguard-go](https://git.zx2c4.com/wireguard-go) (embedded) + [wgctrl-go](https://github.com/WireGuard/wgctrl-go) |
| IPC | JSON-RPC over Unix socket / Named pipe |
| Editor | [CodeMirror 6](https://codemirror.net/) |
| Firewall | macOS `pf` / Linux `nftables` / Windows `netsh advfirewall` |

---

## License

MIT
