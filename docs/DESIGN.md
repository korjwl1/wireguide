# WireGuide Architecture & Design

## Overview

WireGuide is a **two-process** WireGuard VPN client:

- **GUI process** (unprivileged) — Wails v3 + Svelte webview, system tray, config editor
- **Helper process** (root) — wireguard-go TUN, routing, DNS, firewall, reconnect

They communicate over **JSON-RPC 2.0**. On macOS, launchd owns
`/var/run/com.wireguide.helper.sock` (0600, installing user as owner), and
starts the root helper on contact. `RunAtLoad=false` prevents boot execution;
`KeepAlive={AfterInitialDemand:true, SuccessfulExit:false}` restarts crashes
after demand. The helper adopts the listener without unlinking it, verifies
peer credentials, and gates automation until the first GUI control connection.
A transient CLI probe does not grant that control lease. Same-boot desired recovery is separate from new automation and may run
without a GUI. With no GUI or desired tunnels it exits after 15 seconds when activated (60 seconds for a direct
start); after GUI detachment the grace is 10 seconds. Same-boot crash recovery
retains existing desired tunnel intent. Clean quit cancels GUI probes before
shutting down the helper, so they cannot activate it again.

Installation, upgrades and repair can require administrator authorization;
a healthy installed job starts through its socket. Legacy socket migration
asks the old helper to shut down before replacing it. Temporary disappearance
of the app bundle never deletes the helper or its recovery state. Uninstall
requires a manual removal or Homebrew zap; no native app/CLI helper uninstaller
is provided. Removing only the app leaves a dormant launchd registration. See
[README removal instructions](../README.md#macos-removal-and-helper-cleanup).

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

- **GUI stays unprivileged** — it cannot modify the network stack directly. The helper authenticates the configured local user, who is authorized to request VPN operations over IPC; this is not binary attestation or a sandbox against a compromised GUI
- **Helper does only privileged work** — smaller attack surface
- **Helper survives GUI restarts** — closing the window doesn't kill the VPN
- **LaunchDaemon KeepAlive (crash-only)** — helper auto-restarts on crash, but never runs at boot and exits on its own once no GUI and no tunnels remain

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

On macOS, each global-DNS adapter checkpoints the exact service DNS/search
snapshot before changing preferences. The manager shares one original baseline
across those journals: a later tunnel must not record an earlier tunnel's VPN
DNS as the user's original settings. Newly discovered services extend the
baseline; failed checkpoints prevent writes and remain pending for retry.

DNS protection derives per-resolver permits from the longest matching
AllowedIPs prefix across all connected tunnels. A resolver outside every
managed tunnel is permitted by address through normal system routing, so a
split tunnel with a public resolver is usable. Table=off does not imply a
managed route. Equal-prefix tunnel paths permit both interfaces; OS metrics
choose between them. The kill switch remains an independent outer restriction.

This adapts the per-resolver approach proposed in
[PR #50](https://github.com/korjwl1/wireguide/pull/50), while retaining the
existing helper, Windows address-based DNS permits and wg-quick routing model.
A resolver's route is checked against all connected tunnel configs. Both
the original PR source and this implementation retain /0-specific firewall
auto-enable semantics ([WireGuard's documented distinction](https://git.zx2c4.com/wireguard-windows/tree/docs/netquirk.md)).

A periodic helper reconciliation retries failed DNS and kill-switch changes
with bounded backoff and skips healthy, unchanged sets. Kill-switch intent is
separate from actual backend state: failed On/Off requests, connect rollback
and resume retain the requested setting. Each successful reconnect suspension
owns one level; only the last resume applies current rules. Explicit reapply
cannot bypass suspension. Failed suspension rolls back without an owner and
keeps the transport up for retry. Deferred resume also runs on reconnect panic;
the dead retry slot is removed. Shutdown prevents later rule installation. Linux deletion errors retain the active state and
propagate to the caller; startup removes stale kernel DNS tables even without
a tunnel crash journal. Linux kernel integration tests run in an isolated
container namespace with CAP_NET_ADMIN and WIREGUIDE_TEST_NFT=1.

On macOS, WireGuide holds its own PF enable reference (`pfctl -E`) and
releases only that token (`-X`). The atomically written recovery journal
includes the boot-session UUID; tokens from an earlier boot are never used.
Legacy enabled/disabled snapshots do not authorize globally disabling PF.
Failed flush/release operations retain state for retry. Existing main rules
with the required anchor are preserved, and DNS remains installed when the
kill switch is replaced or disabled. Token lifecycle and operation failures
are tested through a PF execution seam; live PF coexistence still requires
target-machine verification.

#### Coverage of the detailed #48 contributor report

The [bitworks-io comment](https://github.com/korjwl1/wireguide/issues/48#issuecomment-6102386212)
and [PR #50](https://github.com/korjwl1/wireguide/pull/50) were checked against
this branch again on 2026-10-13. Reading the report did not mean every item
had been implemented: the second audit found missing signal handling,
journal-independent PF startup cleanup, PF activation rollback, and immediate
firewall reconciliation on disconnect errors. These are now implemented.

| Report item | Implementation / verification |
|---|---|
| Helper-owned wanted DNS state; ignore legacy GUI server list | `dns_protection.go`; handler and multi-tunnel tests |
| Reconcile connect, disconnect, automation, watchdog, restore and resume | Serialized helper transitions plus periodic DNS retry; error returns now also rebuild rules immediately |
| Retry failures without removing a surviving tunnel's permits | DNS and kill-switch wanted/applied journals retry failures with backoff; failed permit removals remain tracked; interface reuse cancels obsolete removals |
| Per-resolver tunnel/physical permits; DNS-less/no protected tunnel | Longest prefix across connected configs; physical address permits; empty sets remove rules |
| PF ordered anchor updates and rollback | DNS sub-anchor prepared before main replacement; failed activation restores the committed main rules; rollback failure is returned |
| PF reference ownership and existing main rules | Same-boot `-E`/`-X` token; existing required wildcard preserved |
| Flush both PF anchors at every helper start | `RecoverSavedRules` sweeps owned anchors even without a journal; no global PF disable |
| Linux table replacement, `oifname`, stale-table cleanup and deletion errors | Implemented; replacement also verified against real nftables in an isolated kernel namespace |
| Bounded SIGTERM/SIGINT graceful cleanup | Registered before initialization; normal helper cleanup, three-second deadline even during an already-running cleanup; real macOS and isolated Linux subprocess signal tests |

The implementation retains the current separate kill-switch and DNS models
under serialized firewall operations, rather than importing PR #50's entire
unified reconciler. `/1` route pairs participate in resolver routing but do
not change `/0`-specific automatic firewall policy, preserving the documented
WireGuard distinction linked above.

The comment also links separate feature PRs. [#51](https://github.com/korjwl1/wireguide/pull/51)
(`~domain` split DNS), [#52](https://github.com/korjwl1/wireguide/pull/52)
(negated automation, settle/manual-override and LAN-overlap policy), and
[#53](https://github.com/korjwl1/wireguide/pull/53) (launchd socket activation)
are integrated on this branch with the compatibility corrections documented
in the review below. Split DNS keeps ordinary system resolvers available for
unmatched names and preserves per-domain ownership in diagnostics. Negated
rules wait for known, settled input; session manual overrides use the underlying
network identity as well as the SSID. Transport recovery continues for manual
On. Socket activation preserves the current shutdown, watchdog and crash
recovery paths; automatic orphan self-uninstall is excluded. Native macOS
resolver/PF coexistence, Linux systemd-resolved and Windows full/split
coexistence still require target-machine execution.

The [review of PRs #51, #52 and #53](analysis/pr-51-52-53-review.md) records
merge conflicts, product fit, behavioral counterexamples and an integration
sequence against the current branch.

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

- **macOS** — `pf` rules in the `com.apple/wireguide` anchor (details below)
- **Linux** — `nftables` table `wireguide_killswitch`, output chain `policy drop` with allow rules for loopback/tunnel/endpoint/DHCP. Input chain is strict (`policy drop`) — see [issue note](#linux-input-chain-strict)
- **Windows** — WFP (Filtering Platform) provider + sublayer at weight `0xFFFF`, `ALE_AUTH_CONNECT_V4/V6` block filters plus allow exceptions for the tunnel LUID, loopback, DHCP/NDP, and the resolved peer endpoint. No `netsh advfirewall` is touched, matching the official wireguard-windows behavior

### macOS pf

Rules are loaded into the `com.apple/wireguide` anchor (slash, not dot — pf's `*` wildcard doesn't cross the `/` path separator, so a dot-named anchor would never match the system wildcard). macOS ships with `anchor "com.apple/*" all` in pf.conf, so our anchor is automatically evaluated — **we never modify the main ruleset**.

```
# WireGuide kill switch rules (loaded into anchor)
pass quick on lo0 all                           # loopback
pass out quick proto udp to 1.2.3.4 port 443   # WG endpoint
pass out quick proto udp from any port 68 to any port 67  # DHCP
pass out quick proto udp from any port 546 to any port 547 # DHCPv6
pass quick on utun6 all                         # tunnel interface
anchor "dns"                                    # DNS sub-anchor (com.apple/wireguide/dns)
block drop out all                              # block everything else
block drop in all
```

**Why anchor-only**: previous approach saved main pf rules via `pfctl -sr` and re-loaded with anchor reference. This broke on macOS Tahoe because `pfctl -sr` outputs `scrub-anchor` directives that cause syntax errors when fed back to `pfctl -f`.

### Lifecycle: applied at connect time, not at boot

An idle helper start or reboot does not enable the kill switch from a saved
setting alone. A subsequent manual or automation connect applies the setting.
This preserves the user's normal connectivity when no VPN session is wanted.

Same-boot crash recovery is different: eligible desired tunnel intent restores
the previous kill-switch blockade **before** reconnecting. An explicit saved or
live Off vetoes stale journal intent. Health check, pin-interface and log-level
settings load at helper startup; they affect behavior while tunnels are up.

On Windows, base and per-tunnel kill-switch filter IDs are tracked independently
from DNS and endpoint-loop protection. Disabling the kill switch deletes only
its filters and widens DNS permits in the same WFP transaction. It leaves
endpoint protection installed in the existing dynamic session. DNS permits
with an interface match that interface's LUID; normal-routing exceptions have
no LUID condition and are excluded while the kill switch is on. A failed
transaction preserves the previous filters and their tracked IDs for retry.

## Automation (per-tunnel connect/disconnect rules, issue #12)

### Model

Each tunnel owns an ordered list of `condition → action` rules
(`internal/automation/automation.go`). A condition is one of:

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
  Evaluate(rules, ctx) → StateConnect  → doConnectHeld (unless watchdog-blocked)
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

Within an evaluation, acquire `reevalMu → connectMu → mu → wifiMu`.
Desired-state persistence acquires `desiredMu` before its `mu → wifiMu`
snapshot and disk write; callers must release `mu`/`wifiMu` before persistence.
The tunnel DNS checkpoint mutex serializes journals and baseline replacement;
its slow fsync runs outside `Manager.mu`, keeping status queries responsive.

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

**Firewall suspend/resume**: on reconnect, utun name changes (utun4->utun5).
Old rules can block the new interface. Successful suspensions are counted;
only the last matching resume rebuilds rules from current tunnels and wanted
settings. Failed suspension preserves the old transport and retries later.
Resume runs on success, failure, cancellation and panic. An OS apply failure
keeps wanted state and remains pending for periodic retry. See the
[PR adoption checklist](analysis/pr-adoption-checklist.md) for verified paths
and deliberate differences from the contributor proposals.

### Loop watchdog and forced disconnect

Loop protection never uses a traffic-rate cutoff: a fast one-way upload
is valid traffic.

On Windows, every tunnel's outer UDP sender is guarded. The native
`BindSocketToInterface` API constrains packets to a non-tunnel default-route
interface, following the [official userspace client](https://github.com/WireGuard/wireguard-windows/blob/v0.1.1/tunnel/defaultroutemonitor.go).
No underlay or a failed bind drops sends until protection succeeds. The
binding is applied before the first handshake and reapplied when sockets
reopen. Route notifications and a periodic fallback retry failed bindings;
callbacks use a fixed pair of native trampolines across reconnects. Endpoint
bypass routes and WFP filters remain additional protection.
The bind serializes socket reopen with close, but close interrupts the native
socket before waiting for guarded sends to finish. Windows RIO sends can wait
for completion; waiting for them before closing the socket would deadlock.

On macOS, endpoint host routes are maintained along the lines of
[wg-quick](https://git.zx2c4.com/wireguard-tools/tree/src/wg-quick/darwin.bash).
The route monitor checks for removed bypasses even if the gateway has not
changed. Outer sends are paused during route replacement and resume only
after kernel forwarding decisions are verified. This also covers transitions
to and from blackhole routes: Darwin's RTM_CHANGE does not change those flags,
so a blackhole must be replaced while sends are paused.
The network manager owns reopening the send gate under its route lock,
including initial verification. Connection completion must not reopen it
independently: a subsequent route repair may already have paused traffic.

A separate macOS watchdog queries RTM_GET every five seconds using live
peer endpoints from the engine, including roaming. This uses the same
[native route-query approach as Tailscale](https://github.com/tailscale/tailscale/blob/main/net/netns/netns_darwin.go).
A route through the same tunnel immediately blocks outer sends and triggers
forced disconnect. Missing routes and blackholes are safe outages, not loop
evidence. Unknown query results pause sends and retry; they do not claim a
loop. Initial route verification also rolls back unsafe connects.

On a trip, `tunnel.Manager` sends the session identity to the helper. The
helper checks that the same session is still connected, records a durable
automation block, and tears the tunnel down through its normal state path:
reconnect cache, desired-tunnel list, retry, kill-switch permit, and DNS rules.
The block survives a helper restart. A successful manual Connect clears it;
automatic rules and crash restore cannot bring the tunnel back first.

Regression tests cover deleted endpoint routes with an unchanged gateway,
blackhole promotion while sends are paused, failed repair remaining blocked,
socket reopen, failed binding and recovery, and concurrent send/rebind. The
macOS RTM_GET reader is also checked against live IPv4/IPv6 loopback routes.
Integration tests run two wireguard-go devices over real loopback UDP sockets
to verify handshakes, bidirectional encrypted traffic, gate pause/recovery,
and socket recreation. They simulate interface-binding syscalls. Additional
tests cover connect/repair gate ownership, close interrupting a stalled send,
verification failure rolling back before DNS, and independent tunnel gates
with DNS union, endpoint firewall cleanup and reconnect.
Before release, verify a real peer on both OSes: sustained high-rate uploads,
Wi-Fi/Ethernet handoff, endpoint bypass deletion, missing underlay recovery,
and helper restart after a forced disconnect. Cross-builds do not validate
Windows kernel behavior.

## macOS Menu Bar (issues #45, #46)

The macOS tray uses a small Cocoa bridge with its own NSStatusItem and a
permanently attached NSMenu. AppKit owns click/keyboard menu tracking and
dismissal; no event monitor, synthesized mouse-down or private Wails handle
is required. Menu mutations are dispatched to the main queue. Selected
actions return to a Go goroutine before any helper RPC or shutdown work.
Windows/Linux continue to use Wails' platform tray. A standalone Cocoa
integration fixture validates menu persistence, action dispatch and cleanup
with WIREGUIDE_TEST_TRAY=1; macOS 27 still requires reproduction testing.

The macOS glyph is an NSImage template (issue #46), allowing AppKit to apply
the correct per-display appearance and inactive emphasis. A separate
transparent, non-interactive view draws the green connection badge and
follows the button's appearsDisabled state. Accessibility exposes the
connection state as text, and menu glyphs retain the existing connected /
handshake distinction. No private status-window search or guessed icon
color is required. The Cocoa fixture checks template mode, badge visibility,
inactive emphasis and click passthrough; physical multi-monitor testing
remains necessary.

The glyph comes from Wails' `SystrayMacTemplate`, which carries a faint
rounded-square outline (alpha 7–26) around the W. `trayGlyph` crops the canvas
first, then clears everything outside the W's opaque body plus a 2px margin
and scales the W to full alpha. Keeping that outline in a template image is
what drew the low-opacity box around the icon in #45.

## Helper Version Sync

GUI and helper share the same binary (`wireguide` / `wireguide --helper`). On startup, `ensureHelper` pings the helper and compares `AppVersion`:

- Match -> use existing helper
- Mismatch -> Shutdown RPC -> `ForceReinstall` -> `installAndLoadDaemon` (bootout old, copy new binary, bootstrap)

This handles `brew upgrade` which replaces the app bundle but leaves the old helper running via KeepAlive.

## IPC Protocol

JSON-RPC 2.0 over a Unix domain socket (macOS/Linux; permissions `0600`, peer UID verified via `SO_PEERCRED`/`LOCAL_PEERCRED`) or a named pipe (Windows; the pipe's ACL is scoped to the launching user's SID and each connection's peer SID is verified — issue #20).

| Method | Direction | Description |
|--------|-----------|-------------|
| `Helper.Ping` | GUI->Helper | Version check, liveness |
| `Helper.Shutdown` | GUI->Helper | Graceful helper shutdown |
| `Helper.ForceShutdown` | GUI->Helper | Bypass graceful teardown; `os.Exit` after best-effort firewall cleanup. Used by the upgrade path when `Shutdown` is wedged. |
| `Helper.Subscribe` | GUI->Helper | Subscribe to event notifications |
| `Helper.SetLogLevel` | GUI->Helper | Change runtime log level |
| `Helper.RequestQuit` | CLI->Helper | Ask the helper to shut the app down (`wireguide ctl stop`) |
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
| `Automation.Preview` | CLI->Helper | Read-only dump of the current network context + per-tunnel rule decision (`wireguide ctl automation`) |
| `event.status` | Helper->GUI | 1 Hz status broadcast (includes `active_tunnels` list) |
| `event.reconnect` | Helper->GUI | Reconnect state changes |
| `event.log` | Helper->GUI | Structured log entries |
| `event.wifi_ssid` | Helper->GUI | SSID changed (`WifiSSIDPayload{OldSSID, NewSSID}`) |
| `event.auto_connect` | Helper->GUI | Wi-Fi rule fired and connected (`AutoConnectPayload{TunnelName}`) |
| `event.critical_error` | Helper->GUI | A background goroutine exceeded the `goSafe` restart budget; tunnel state may not match reality. The GUI surfaces this via a banner/toast. |
| `event.settings_changed` | Helper->GUI | Broadcast whenever a setting changes over IPC (`SettingsChangedPayload`), keeping other clients — e.g. the GUI after a `wireguide ctl set` — in sync |
| `event.quit` | Helper->GUI | Helper asks the GUI to quit (relays `Helper.RequestQuit` from `wireguide ctl stop`) |

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
| Homebrew | `brew upgrade --cask --greedy wireguide` (GUI triggers; `HOMEBREW_NO_AUTO_UPDATE=1` since the checker already knows the target version) |
| Binary zip | Opens GitHub Releases page in browser |

The Homebrew path is verified, not trusted: after `brew` exits 0, the installed
bundle's `CFBundleShortVersionString` is compared against the release version and
a mismatch is surfaced as an error (a cask marked `auto_updates`, or an upgrade
that silently no-ops, can otherwise "succeed" without installing anything —
issue #38). Progress phases are emitted to the GUI as `update_progress` events,
and a Homebrew 6 `untrusted tap` failure triggers `brew trust` + one retry.

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

macOS Tahoe's `pfctl -sr` outputs `scrub-anchor` directives that cause syntax errors when re-loaded. Using anchors avoids touching the main ruleset entirely — the `com.apple/*` wildcard evaluates our rules automatically.


### Independent review follow-up (2026-10-15)

The [Claude review of 68fdca0](analysis/claude-integration-review-20261015.md)
found additional omissions; the [disposition](analysis/claude-review-disposition.md)
records the fixes. Firewall snapshots now use manager lifecycle state rather
than wgctrl telemetry; a failed stats query cannot erase a live permit. DNS
intent is loaded before background workers start. Cached wanted transports
keep the helper alive during retry gaps and are exposed through IPC 1.3 so
headless recovery can be stopped from the CLI. Legacy connect locks unwind
on panic. Signal shutdown reserves part of its deadline for parallel best-
effort firewall/DNS fallback; stalled OS commands can still outlast that cap,
so recovery journals remain necessary.

PF enforcement is checked by the safety net and restored after an external
PF disable. Invalid same-boot tokens do not wedge release. DNS permits cannot
open off-tunnel exceptions through the kill switch on macOS/Windows; Windows
KS activation and DNS narrowing commit in one transaction. WFP IDs and flags
are updated only after commit. Mixed DNS diagnostics evaluate default and
supplemental resolvers separately and retain both leak and incomplete-check
results. Manual overrides use positive evidence of a network change; missing
ARP and IPv6 prefix churn do not clear an explicit Off.

## Review follow-up: profile and event ownership (2026-10-15)

IPC 1.4 adds `Tunnel.Delete`. Like rename, deletion executes under the
helper's `connectMu`: checking the active set and removing the config cannot
be interleaved by automation or recovery. GUI deletion rejects an active
transport. CLI deletion explicitly disconnects first and withdraws pending
recovery intent. It uses a reachable headless helper too. Offline local
removal is permitted only when the socket/pipe is absent or refuses a
connection; timeout, permission and protocol failures do not authorize it.
The GUI setup path upgrades helpers with older protocol minors even when
the app version string is unchanged. Background recovery requests reopening
for setup instead of authorizing an upgrade itself.

Config and metadata mutations share the existing `.imports.lock` across
processes. A metadata update verifies the config inside that lock. Paired
config/metadata reads use it too; individual atomic snapshots remain cheap
reads. A lock first created by a Unix root helper belongs to the user profile
directory's owner. New profiles start with fresh metadata rather than
inheriting an orphan from an earlier deletion.

IPC event setup has a separate bounded context and an immutable
connection/handler pair per subscription. Replacement and client shutdown
close the previous stream. The existing GUI health tick repairs an event-only
failure while retaining the working control connection. GUI history changes
are serialized and stop accepting status events once shutdown closes history.
Shared status and operation error types live in `domain`; `reconnect` depends
on those types and its consumer-owned manager interface, not the engine package.


### Firewall suspension during reconnect

The current helper policy suspends kill switch and DNS protection during tunnel
reconstruction so endpoint resolution and interface replacement can proceed.
This creates an unprotected interval, including for other connected tunnels.
Atomic replacement of an individual backend ruleset does not remove this
higher-level policy gap. Preserving a default blockade while permitting only
bootstrap DNS and endpoint UDP requires a separate cross-platform policy change;
it must preserve multi-tunnel ownership and failure recovery.


### Model and adapter boundaries

`internal/automation` owns condition evaluation, legacy rule migration and
settling. It uses only the standard library. `internal/wifi` owns OS detection
and monitor lifetime; storage and CLI rule consumers do not import that adapter.
`internal/version` supplies build identity without the update downloader.

Helper intent persistence, pending restore and startup orchestration live in
`desired_store.go`, `pending_restore.go` and `restore.go`. Linux and Windows
network adapters separate DNS and routing in the same platform package.

GUI preferences use optional-field `SettingsPatch` writes under the settings
file lock. Saving a preference never replaces another writer's automation
rules. A failed live apply retains saved intent and exposes a retryable error.
Profile rename/delete return a structured warning if the committed file change
succeeds but automation migration fails.

The helper retries failed DNS cleanup while retaining its original baseline and
crash journal under a separate retired-record identity. Failed cleanup does
not block new connections or let a same-named profile overwrite its predecessor's
journal. Retired work runs only when no transport is active; failed startup
recovery also preserves its original baseline. All active macOS global-DNS
monitors track the same resolver union.
Linux interface DNS contributions are withdrawn even when siblings remain.

The macOS GUI reservation uses the OS private per-user temporary directory,
independent of TMPDIR. A new binary first contacts an old reservation when a
pre-migration binary is still running, including after an in-place bundle update.
