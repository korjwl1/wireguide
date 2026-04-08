# WireGuide Architecture & Design

## Overview

WireGuide is a **two-process** WireGuard VPN client:

- **GUI process** (unprivileged) — Wails v3 + Svelte webview, system tray, config editor
- **Helper process** (root) — wireguard-go TUN, routing, DNS, firewall, reconnect

They communicate over **JSON-RPC 2.0** on a Unix domain socket (`/var/run/wireguide/wireguide.sock`). The helper is installed as a macOS LaunchDaemon with `KeepAlive=true`.

```
┌──────────────────────────────┐     ┌──────────────────────────────┐
│   GUI (user)                 │     │   Helper (root)              │
│                              │     │                              │
│  Wails v3 + Svelte           │     │  wireguard-go + wgctrl       │
│  Config editor (CodeMirror)  │────▶│  TUN device (utunN)          │
│  System tray                 │◀────│  DNS (networksetup)          │
│  Diagnostics                 │     │  Routes (route cmd)          │
│  Settings                    │ UDS │  Kill switch (pf)            │
│  Update checker              │     │  Reconnect monitor           │
│                              │     │  Route monitor               │
└──────────────────────────────┘     └──────────────────────────────┘
```

## Why Two Processes?

WireGuard requires root to create TUN devices and modify routing tables. Rather than running the entire GUI as root:

- **GUI stays unprivileged** — a compromised webview can't touch the network stack
- **Helper does only privileged work** — smaller attack surface
- **Helper survives GUI restarts** — closing the window doesn't kill the VPN
- **LaunchDaemon KeepAlive** — helper auto-restarts on crash

This mirrors the architecture of `wg-quick` (which also runs as root) but wraps it in a persistent daemon with IPC.

## Connection Lifecycle

### Connect

```
GUI                          Helper                      OS
 │                            │                           │
 │── Connect(config) ────────▶│                           │
 │                            │── NewEngine(config)       │
 │                            │   ├─ resolve endpoints    │
 │                            │   ├─ create TUN ─────────▶│ utunN
 │                            │   ├─ apply WG config      │
 │                            │   └─ bring device up      │
 │                            │── SetMTU ────────────────▶│
 │                            │── AssignAddress ─────────▶│
 │                            │── BringUp ───────────────▶│
 │                            │── AddRoutes ─────────────▶│ 0.0.0.0/1, 128.0.0.0/1
 │                            │   └─ bypass routes ──────▶│ endpoint → gateway
 │                            │── SetDNS ────────────────▶│ networksetup
 │                            │── SaveActiveState         │
 │◀── status: connected ──────│                           │
```

### Endpoint DNS Resolution — Chicken-and-Egg

Peer endpoints are resolved **before** installing split routes. If we resolved after, the DNS query itself would route through the tunnel (which isn't established yet), creating a loop.

```go
// engine.go: resolve FIRST, then routes
ips, _ := net.DefaultResolver.LookupHost(ctx, host)  // uses ISP DNS
// ... later in connect_phases.go ...
netMgr.AddRoutes(ifaceName, allowedIPs, ...)          // installs 0.0.0.0/1
// After this point, DNS queries go through tunnel — but endpoints are already resolved
```

This is the same approach wg-quick uses (`wg show <iface> endpoints` before `route add`).

## Network Management (macOS)

### DNS

DNS is applied to **every** network service (`networksetup -listallnetworkservices`), not just the primary one. macOS can switch primary between Wi-Fi and Ethernet mid-session.

Original DNS per service is saved in memory, restored on disconnect. For crash recovery (no memory), `ResetDNSToSystemDefault()` clears to DHCP defaults.

**Post-write verification**: after applying DNS, we read back to confirm at least one service accepted the change. macOS can silently drop DNS changes (MDM profiles, permission issues).

### Routes

**Split tunnel**: `0.0.0.0/1` + `128.0.0.0/1` via utunN (wg-quick approach).

**Endpoint bypass**: host routes for each peer endpoint via the upstream gateway. This prevents encrypted WG packets from looping through the tunnel.

**`-ifscope` pinning** (optional): when WiFi and Ethernet are both active, macOS can flap between interfaces for bypass routes. `-ifscope <iface>` pins to a specific physical interface. The upstream interface is cached **before** split routes are installed (afterwards, `route get` would return utun).

### Route Monitor

Equivalent to wg-quick's `monitor_daemon`. Watches `route -n monitor` for kernel route table changes and:

1. Compares current gateway against cached value
2. If changed: deletes old bypass routes, re-adds with new gateway
3. Re-applies DNS (macOS can reassign on network switch)
4. Re-reads live endpoints from wgctrl (roaming support)

**Anti-loop protection**: caches `lastGatewayV4/V6` to skip spurious RTM events. Without this, our own `route add` commands trigger reapply in a tight loop.

## Kill Switch (macOS pf)

Rules are loaded into the `com.apple.wireguide` anchor. macOS ships with `anchor "com.apple/*" all` in pf.conf, so our anchor is automatically evaluated — **we never modify the main ruleset**.

```
# WireGuide kill switch rules (loaded into anchor)
pass quick on lo0 all                           # loopback
pass out quick proto udp to 1.2.3.4 port 443   # WG endpoint
pass out quick proto udp from any port 68 to any port 67  # DHCP
pass out quick proto udp from any port 546 to any port 547 # DHCPv6
pass quick on utun6 all                         # tunnel interface
anchor "com.apple.wireguide/dns"                # DNS sub-anchor
block drop out all                              # block everything else
block drop in all
```

**Why anchor-only**: previous approach saved main pf rules via `pfctl -sr` and re-loaded with anchor reference. This broke on macOS Tahoe because `pfctl -sr` outputs `scrub-anchor` directives that cause syntax errors when fed back to `pfctl -f`.

## Reconnect

### Sleep/Wake Detection

Two mechanisms (both send to the same channel):

1. **NSWorkspace.didWakeNotification** (cgo) — instant detection
2. **Wall-clock polling** (fallback) — 10s interval, 30s threshold

### Health Check (optional, off by default)

Polls handshake age via wgctrl every 30 seconds. If no handshake for 180 seconds (`RejectAfterTime`), triggers reconnect. Recommended only with `PersistentKeepalive` — without it, idle tunnels exceed the threshold naturally.

### Reconnect Flow

```
Wake detected
  → triggerReconnect()
    → suspendFirewall()     # disable kill switch (old utun rules)
    → manager.Disconnect()
    → reconnectFn()         # manager.Connect(cachedConfig)
    → resumeFirewall()      # re-enable with NEW utun + endpoints
```

**Exponential backoff**: 5s initial, 60s max, unlimited attempts.

**Firewall suspend/resume**: on reconnect, utun name changes (utun4→utun5). Old kill switch rules block the new interface. Suspending before disconnect and resuming after connect with fresh interface/endpoints prevents this deadlock.

## Helper Version Sync

GUI and helper share the same binary (`wireguide` / `wireguide --helper`). On startup, `ensureHelper` pings the helper and compares `AppVersion`:

- Match → use existing helper
- Mismatch → Shutdown RPC → `ForceReinstall` → `installAndLoadDaemon` (bootout old, copy new binary, bootstrap)

This handles `brew upgrade` which replaces the app bundle but leaves the old helper running via KeepAlive.

## IPC Protocol

JSON-RPC 2.0 over Unix domain socket. Socket permissions: `0600`, peer UID verified via `SO_PEERCRED`.

| Method | Direction | Description |
|--------|-----------|-------------|
| `Helper.Ping` | GUI→Helper | Version check, liveness |
| `Tunnel.Connect` | GUI→Helper | Start VPN tunnel |
| `Tunnel.Disconnect` | GUI→Helper | Stop specific or all tunnels |
| `Tunnel.Status` | GUI→Helper | Connection state + stats |
| `Firewall.SetKillSwitch` | GUI→Helper | Enable/disable pf rules |
| `Monitor.SetHealthCheck` | GUI→Helper | Toggle health check |
| `event.status` | Helper→GUI | 1 Hz status broadcast |
| `event.reconnect` | Helper→GUI | Reconnect state changes |
| `event.log` | Helper→GUI | Structured log entries |

## Error Handling

### Typed Errors

```go
type TunnelError struct {
    Kind    ErrorKind  // ErrAlreadyConnected, ErrNetwork, ErrTimeout, etc.
    Message string
    Cause   error
}
```

Frontend can type-assert `ErrorKind` to show different UI for "already connected" vs "DNS failed" vs "timeout".

### Crash Recovery

Active tunnel state is persisted to `{dataDir}/active-tunnel.json` after all connect phases succeed. On helper restart:

1. Load state file
2. Restore routing state (table/fwmark)
3. Restore DNS from pre-modification snapshot (or reset to DHCP defaults)
4. Remove stale routes
5. Flush firewall anchors
6. Clear state file

### Panic Recovery

All background goroutines wrapped in `goSafe()` — recovers panics, logs stack trace, restarts up to 5 times with 1s backoff. IPC connection handlers individually wrapped to prevent one bad RPC from crashing the helper.

## Update Flow

| Install method | Update mechanism |
|---------------|-----------------|
| Homebrew | `brew update && brew upgrade --cask wireguide` (GUI triggers) |
| Binary zip | Opens GitHub Releases page in browser |

Homebrew cask `uninstall` block only quits the app (no sudo). Helper cleanup is in `zap` (full removal only). This allows `brew upgrade` without sudo.

## Design Decisions

### Why wireguard-go instead of NetworkExtension?

| | wireguard-go | NetworkExtension |
|---|---|---|
| Platforms | macOS, Windows, Linux | Apple only |
| Kill switch | Full control (pf/nftables) | Limited (on-demand rules) |
| Sleep/wake | Custom handler | Commented out in Passepartout |
| App Store | Not possible | Required |
| Root required | Yes (TUN device) | No (sandboxed) |

WireGuide chose wireguard-go for cross-platform support and full control over networking. The tradeoff is requiring root and not being distributable via App Store.

### Why Go + Wails instead of Swift/Electron?

- **Go**: same language as wireguard-go, no FFI overhead, single binary
- **Wails v3**: native webview (not Chromium), ~15MB binary vs ~150MB Electron
- **Svelte**: smallest bundle size among major frameworks, no virtual DOM

### Why pf anchors instead of modifying main ruleset?

macOS Tahoe's `pfctl -sr` outputs `scrub-anchor` directives that cause syntax errors when re-loaded. Using anchors avoids touching the main ruleset entirely — `com.apple.*` wildcard evaluates our rules automatically.
