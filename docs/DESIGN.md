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

## Multi-Tunnel Architecture

WireGuide supports **multiple simultaneous WireGuard tunnels**. The `tunnel.Manager` maintains a `map[string]*tunnelEntry` keyed by tunnel name, where each entry holds its own independent state:

```go
type tunnelEntry struct {
    state       domain.State
    engine      *Engine
    cfg         *domain.WireGuardConfig
    connectedAt time.Time
    netMgr      network.NetworkManager  // per-tunnel network state
}
```

### Per-Tunnel NetworkManager

Each tunnel gets its **own `NetworkManager` instance** created via `netMgrFactory` during `Connect()`. This ensures one tunnel's route/DNS cleanup cannot affect another. The manager propagates global settings (like pin interface) to each tunnel's `NetworkManager`.

### DNS Union

When multiple tunnels are active, DNS servers are merged into a **union set**. On connect, the new tunnel's DNS is merged with all existing tunnels' DNS via `AllDNSServers()`. On disconnect, if other tunnels remain, their combined DNS is re-applied through one of the remaining tunnels' `NetworkManager` instances.

### Full-Tunnel Conflict Detection

Only one full-tunnel (`0.0.0.0/0`) can be active at a time. `Connect()` rejects a new full-tunnel config if any existing connected tunnel is already routing all traffic, returning `ErrFullTunnelConflict`.

### Key Methods

| Method | Description |
|--------|-------------|
| `Connect(cfg)` | Creates per-tunnel `NetworkManager`, runs connect phases, adds to `tunnels` map |
| `DisconnectTunnel(name)` | Tears down a specific tunnel by name |
| `DisconnectAll()` | Tears down all active tunnels (used during shutdown) |
| `Disconnect()` | Legacy single-tunnel compat: disconnects the first active tunnel |
| `ActiveTunnels()` | Returns sorted names of all connected/connecting tunnels |
| `AllStatuses()` | Returns `ConnectionStatus` for every tunnel entry |
| `StatusFor(name)` | Returns status of a specific tunnel |
| `AllDNSServers()` | Returns union of DNS servers from all connected tunnels |

## Connection Lifecycle

### Connect (Multi-Tunnel)

```
GUI                          Helper                      OS
 │                            │                           │
 │── Connect(config) ────────▶│                           │
 │                            │── claim connecting slot   │
 │                            │   (reject if full-tunnel  │
 │                            │    conflict detected)     │
 │                            │── create per-tunnel       │
 │                            │   NetworkManager          │
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
 │                            │── SetDNS (union) ────────▶│ networksetup
 │                            │── SaveActiveState         │
 │◀── status: connected ──────│                           │
```

The manager lock (`mu`) is held only for state reads/writes, never during the slow phase operations (ifconfig, route, networksetup). This keeps `Status()` / `IsConnected()` / `ActiveTunnel()` non-blocking even while a long `Connect` or `Disconnect` is in flight.

### Disconnect

On disconnect, each tunnel cleans up via its own `NetworkManager`. If other tunnels remain active, their DNS union is re-applied. Crash-recovery state is cleared per-tunnel.

### Security Hardening: No Script Execution

Pre/PostUp/Down script execution has been **removed** as a security hardening measure. The config parser still accepts these fields so existing configs import without error, but the scripts are silently ignored.

### Endpoint DNS Resolution -- Chicken-and-Egg

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

### Pin Interface (`-ifscope`)

When WiFi and Ethernet are both active, macOS can flap between interfaces for bypass routes. `-ifscope <iface>` pins to a specific physical interface. The upstream interface is cached **before** split routes are installed (afterwards, `route get` would return utun).

Pin interface is a **Manager-level setting** (`SetPinInterface(bool)`). When toggled:
1. The setting is stored on the `Manager` struct
2. Propagated to every active tunnel's `NetworkManager` via the `SetPinInterface` interface
3. Applied to any future tunnels created via `Connect()`

Controlled via the `Network.SetPinInterface` IPC method from the GUI Settings panel.

### Route Monitor

Equivalent to wg-quick's `monitor_daemon`. The change source is OS-specific — macOS uses the `PF_ROUTE` socket (`route -n monitor` equivalent), Linux subscribes to `NETLINK_ROUTE`, Windows registers `NotifyIpInterfaceChange`/`NotifyRouteChange2` callbacks via `iphlpapi`. All three feed the same reapply path, which:

1. Compares current gateway against cached value
2. If changed: deletes old bypass routes, re-adds with new gateway
3. Re-applies DNS (macOS can reassign on network switch)
4. Re-reads live endpoints from wgctrl (roaming support)

**Anti-loop protection**: caches `lastGatewayV4/V6` to skip spurious RTM events. Without this, our own `route add` commands trigger reapply in a tight loop.

## Kill Switch

Per-platform backends, all driven by the same `Firewall.SetKillSwitch` IPC method:

- **macOS** — `pf` rules in the `com.apple.wireguide` anchor (details below)
- **Linux** — `nftables` table `wireguide_killswitch`, output chain `policy drop` with allow rules for loopback/tunnel/endpoint/DHCP. Input chain is strict (`policy drop`) — see [issue note](#linux-input-chain-strict)
- **Windows** — WFP (Filtering Platform) provider + sublayer at weight `0xFFFF`, `ALE_AUTH_CONNECT_V4/V6` block filters plus allow exceptions for the tunnel LUID, loopback, DHCP/NDP, and the resolved peer endpoint. No `netsh advfirewall` is touched, matching the official wireguard-windows behavior

### macOS pf

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

### Lifecycle: applied at connect time, not at boot

The kill switch is a **connect-path state transition**, deliberately NOT
restored when the helper (re)starts. With `kill_switch: true` in
config.json, a reboot leaves the firewall open until the first tunnel
comes up — at which point the connect path (GUI `applyFirewallSettings`,
or helper-side `applyPostConnectFirewall` for automation connects)
re-enables it. Auto-applying at boot would block ALL traffic on a machine
with no tunnel up, which is "always-on VPN" semantics — a separate,
opt-in feature if ever wanted, not a restore. (Other persisted
helper-side settings — health check, pin-interface, log level — ARE
restored at helper startup, because they only change behaviour while
tunnels are up.)

## Automation (per-tunnel connect/disconnect rules, issue #12)

### Model

Each tunnel owns an ordered list of `condition → action` rules
(`internal/wifi/automation.go`). A condition is one of:

- `ssid` — the current Wi-Fi SSID equals a value
- `subnet` — a physical-interface IP is inside a CIDR
- `network` — the default gateway's MAC equals a value (a precise,
  medium-agnostic network fingerprint that disambiguates two networks
  sharing a subnet like `192.168.0.0/24`; MACs compare by bare hex, so
  separator/case don't matter)
- `none_match` — the fallback ("otherwise")

The action is `connect` or `disconnect`. `Evaluate` walks the rules top to
bottom: the **first** matching concrete condition wins; if none match, the
first `none_match` rule applies; else the tunnel is left untouched. **Order
is priority** (drag-reorderable in the GUI). A rule disconnects a tunnel
**regardless of how it was brought up** — but a tunnel with *no* rules is
never auto-touched. Legacy `Settings.WifiRules` (SSID-only auto-connect +
global trusted list) is migrated once into this model by
`Settings.EnsureAutomation`.

### Evaluation triggers (helper-side)

Rules are evaluated **entirely inside the helper** (`reevaluateAutomation`
in `internal/helper/wifi_rules.go`), so they fire whether or not a GUI is
alive. `reevalMu` serialises evaluations. Triggers:

```
current network context = { SSID, physical IPs, gateway MAC }
  ├─ SSID change      → wifiMon (CoreWLAN via GUI on macOS 14+) — instant
  ├─ network change   → macOS: the shared `route -n monitor` subscription
  │                     (SubscribeNetworkChange) — instant, ~zero added cost
  └─ poll (30s)       → Windows/Linux fallback (no process-wide monitor yet)

for each tunnel with rules:
  Evaluate(rules, ctx) → StateConnect  → doConnectHeld (same as manual)
                         StateDisconnect → disconnectAutoManaged
                         StateUnmanaged  → leave as-is
```

The gateway MAC is read unprivileged and locale-independently:
`route -n get default` + `arp` on macOS, `/proc/net/{route,arp}` on Linux,
`GetBestRoute`+`SendARP` on Windows.

### macOS 14+ Location Services Workaround

On macOS 14+, `CoreWLAN` requires the app to appear in **System Settings →
Privacy → Location Services** before it can read the current SSID. The
helper runs as a root `LaunchDaemon` (outside the app bundle) so it can't
obtain that permission; the GUI polls SSID via `CoreWLAN` and forwards
changes over the `Wifi.ReportSSID` IPC method (`Monitor.LastSSID` is the
helper's authoritative current SSID).

### Authoring

Rules are edited in the GUI (tunnel detail → **Automation**: condition/
action rows, self-entry with current-value autocomplete, drag-to-reorder,
inline MAC/CIDR validation) or from the CLI (`wireguide ctl automation
add/rm/rules`, and `wireguide ctl automation` for a read-only preview of
the current decision). Both edit `Settings.Automation` in `config.json`,
which the helper rereads on every evaluation — no restart needed.

### Post-Connect Refresh

After a rule connects a tunnel the helper broadcasts `event.auto_connect`;
the GUI runs `applyFirewallSettings()` (same as a manual connect) to
re-apply kill switch / DNS protection, and the 1 Hz `event.status`
broadcast drives the UI state update.

### Lock Ordering

The helper's locks:

- `reevalMu` — serialises whole Automation re-evaluations so the three
  triggers (SSID change, network change, poll) can't drive connect/
  disconnect concurrently. Held around an evaluation, which internally
  takes the locks below.
- `connectMu` — serializes connect/disconnect operations
- `mu` — protects `activeCfgs` and other manager state
- `wifiMu` — protects `autoConnectedBy`

Rule: within an evaluation, always acquire in the order
`connectMu → mu → wifiMu`. Never hold a lower-priority lock when acquiring
a higher one.

## Reconnect

### Sleep/Wake Detection

Native suspend/wake detection per OS, with a wall-clock fallback that runs on every platform:

1. **macOS** — `NSWorkspace.didWakeNotification` via cgo (instant)
2. **Linux** — `systemd-logind` `PrepareForSleep` signal over DBus (instant)
3. **Windows** — `PowerRegisterSuspendResumeNotification` against a message-only window (instant)
4. **Wall-clock polling** (fallback, all platforms) — 10s interval, 30s threshold; covers the case where the native signal is missing (no logind, DBus down, etc.)

### Health Check (optional, off by default)

Polls handshake age via wgctrl every 30 seconds. If no handshake for 180 seconds (`RejectAfterTime`), triggers **per-tunnel reconnect**. The monitor calls `AllStatuses()` to check each tunnel individually -- if a specific tunnel's handshake is stale, only that tunnel is disconnected and reconnected via `triggerReconnectTunnel(name)`.

Recommended only with `PersistentKeepalive` — without it, idle tunnels exceed the threshold naturally.

### Reconnect Callback

`ReconnectFunc` accepts a tunnel name parameter:

```go
type ReconnectFunc func(name string) error
```

In the helper, `reconnectFn(name)` looks up the cached config from `activeCfgs map[string]*WireGuardConfig`:
- **name non-empty**: reconnects only that specific tunnel
- **name empty** (legacy sleep/wake path): reconnects all cached tunnels

### Reconnect Flow

```
Health check detects stale handshake on tunnel "work"
  → triggerReconnectTunnel("work")
    → suspendFirewall()            # disable kill switch (old utun rules)
    → manager.DisconnectTunnel("work")
    → reconnectFn("work")         # manager.Connect(cachedCfgs["work"])
    → resumeFirewall()            # re-enable with NEW utun + endpoints

Wake detected (all tunnels)
  → triggerReconnect()
    → triggerReconnectTunnel("")   # reconnects all cached tunnels
```

**Exponential backoff**: 5s initial, 60s max, unlimited attempts.

**Firewall suspend/resume**: on reconnect, utun name changes (utun4->utun5). Old kill switch rules block the new interface. Suspending before disconnect and resuming after connect with fresh interface/endpoints prevents this deadlock.

## Helper Version Sync

GUI and helper share the same binary (`wireguide` / `wireguide --helper`). On startup, `ensureHelper` pings the helper and compares `AppVersion`:

- Match -> use existing helper
- Mismatch -> Shutdown RPC -> `ForceReinstall` -> `installAndLoadDaemon` (bootout old, copy new binary, bootstrap)

This handles `brew upgrade` which replaces the app bundle but leaves the old helper running via KeepAlive.

## IPC Protocol

JSON-RPC 2.0 over Unix domain socket. Socket permissions: `0600`, peer UID verified via `SO_PEERCRED`.

| Method | Direction | Description |
|--------|-----------|-------------|
| `Helper.Ping` | GUI->Helper | Version check, liveness |
| `Helper.Shutdown` | GUI->Helper | Graceful helper shutdown |
| `Helper.ForceShutdown` | GUI->Helper | Bypass graceful teardown; `os.Exit` after best-effort firewall cleanup. Used by the upgrade path when `Shutdown` is wedged. |
| `Helper.Subscribe` | GUI->Helper | Subscribe to event notifications |
| `Helper.SetLogLevel` | GUI->Helper | Change runtime log level |
| `Tunnel.Connect` | GUI->Helper | Start VPN tunnel (`ConnectRequest`) |
| `Tunnel.Disconnect` | GUI->Helper | Stop tunnel (`DisconnectRequest`, optional `TunnelName`) |
| `Tunnel.Rename` | GUI->Helper | Rename tunnel (`RenameRequest`) — atomic update under `connectMu` |
| `Tunnel.Status` | GUI->Helper | Connection state + stats |
| `Tunnel.IsConnected` | GUI->Helper | Boolean connected check |
| `Tunnel.ActiveName` | GUI->Helper | Name of first active tunnel |
| `Tunnel.ActiveTunnels` | GUI->Helper | List all active tunnel names (`ActiveTunnelsResponse`) |
| `Firewall.SetKillSwitch` | GUI->Helper | Enable/disable pf rules |
| `Firewall.SetDNSProtection` | GUI->Helper | Enable/disable DNS-only pf rules |
| `Monitor.SetHealthCheck` | GUI->Helper | Toggle per-tunnel health check |
| `Network.SetPinInterface` | GUI->Helper | Toggle `-ifscope` route pinning |
| `Wifi.ReportSSID` | GUI->Helper | Forward current SSID from GUI (macOS 14+ Location Services workaround) |
| `event.status` | Helper->GUI | 1 Hz status broadcast (includes `active_tunnels` list) |
| `event.reconnect` | Helper->GUI | Reconnect state changes |
| `event.log` | Helper->GUI | Structured log entries |
| `event.wifi_ssid` | Helper->GUI | SSID changed (`WifiSSIDPayload{OldSSID, NewSSID}`) |
| `event.auto_connect` | Helper->GUI | Wi-Fi rule fired and connected (`AutoConnectPayload{TunnelName}`) |
| `event.critical_error` | Helper->GUI | A background goroutine exceeded the `goSafe` restart budget; tunnel state may not match reality. The GUI surfaces this via a banner/toast. |

### Key Request/Response Types

| Type | Used By | Notes |
|------|---------|-------|
| `ConnectRequest` | `Tunnel.Connect` | Contains `*WireGuardConfig` |
| `DisconnectRequest` | `Tunnel.Disconnect` | Optional `TunnelName`; empty = disconnect first active tunnel |
| `RenameRequest` | `Tunnel.Rename` | `OldName`, `NewName` |
| `ActiveTunnelsResponse` | `Tunnel.ActiveTunnels` | `Names []string` |
| `SetPinInterfaceRequest` | `Network.SetPinInterface` | `Enabled bool` |
| `SetHealthCheckRequest` | `Monitor.SetHealthCheck` | `Enabled bool` |
| `SetLogLevelRequest` | `Helper.SetLogLevel` | `Level string` |
| `MultiStatusResponse` | `Tunnel.Status` | Aggregate state + per-tunnel `[]ConnectionStatus` |
| `ReportSSIDRequest` | `Wifi.ReportSSID` | `SSID string` |
| `WifiSSIDPayload` | `event.wifi_ssid` | `OldSSID`, `NewSSID` |
| `AutoConnectPayload` | `event.auto_connect` | `TunnelName string` |

## Error Handling

### Typed Errors

```go
type TunnelError struct {
    Kind    ErrorKind  // ErrAlreadyConnected, ErrNetwork, ErrTimeout, etc.
    Message string
    Cause   error
}
```

Frontend can type-assert `ErrorKind` to show different UI for "already connected" vs "DNS failed" vs "timeout". Multi-tunnel adds `ErrFullTunnelConflict` (two full-tunnels conflict) and `ErrTransitionInProgress` (another connect/disconnect in flight for the same tunnel name).

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
