# WireGuide

Cross-platform WireGuard desktop client for macOS, Windows, and Linux.

## Features

- **Tunnel Management** — Import, edit, export .conf files with drag-and-drop
- **System Tray** — Dynamic tunnel menu, 1-click connect/disconnect
- **CodeMirror Editor** — WireGuard syntax highlighting + autocompletion
- **Kill Switch** — Block all traffic when VPN drops (pf/nftables/WFP)
- **DNS Leak Protection** — Force DNS through VPN tunnel
- **Auto-reconnect** — Exponential backoff + dead connection detection
- **Sleep/Wake Recovery** — Automatic reconnect after system sleep
- **WiFi Auto-connect** — SSID-based rules (trusted/untrusted networks)
- **Split Tunneling UI** — "All Traffic" / "Custom Subnets" presets
- **Conflict Detection** — Detects route conflicts with Tailscale and other WG interfaces
- **Speed Dashboard** — Real-time RX/TX graph + connection history
- **Key Generation** — Create WireGuard key pairs in-app
- **Auto-update** — Check + install from GitHub Releases
- **Mini Mode** — Compact floating status widget
- **Diagnostics** — CIDR calculator, endpoint ping, speed test
- **DNS Leak Test** — Verify DNS queries go through VPN
- **Route Visualization** — See which traffic goes where
- **i18n** — English, Korean, Japanese
- **Dark/Light/System Theme**

## Architecture

```
wireguide (GUI, 12MB)     wireguided (daemon, 16MB)
     |                           |
     +--- gRPC over UDS ---------+
     |                           |
  Svelte + Wails v3        wireguard-go + wgctrl
                            TUN / routing / DNS
                            kill switch / firewall
```

## Build

```bash
# Prerequisites
brew install go protobuf
go install github.com/wailsapp/wails/v3/cmd/wails3@v3.0.0-alpha.74

# Build GUI
wails3 build

# Build daemon
go build -o bin/wireguided cmd/wireguided/main.go

# Run
sudo ./bin/wireguided &   # Start daemon (requires root for TUN)
./bin/wireguide            # Start GUI (unprivileged)
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Go 1.25+ |
| GUI Framework | Wails v3 (alpha) |
| Frontend | Svelte + TypeScript + Vite |
| WireGuard | wireguard-go (embedded) + wgctrl-go |
| IPC | gRPC over Unix Socket |
| Editor | CodeMirror 6 |
| Firewall | macOS pf / Linux nftables / Windows WFP |

## Future Considerations

- **Per-app split tunneling** — Route specific applications through VPN (requires OS-level traffic interception)
- **CI/CD** — GitHub Actions cross-platform builds + Homebrew/winget/deb/rpm packaging
- **Code signing** — macOS notarization + Windows Authenticode

## License

MIT
