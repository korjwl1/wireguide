# WireGuard Desktop Client: Technical Research

## 1. wgctrl-go (golang.zx2c4.com/wireguard/wgctrl)

### What It Is

wgctrl-go is an official Go library (MIT license) that provides a **unified API for configuring existing WireGuard devices** across multiple platforms. It implements the WireGuard configuration protocol, abstracting away platform-specific communication mechanisms.

### What It Provides

- **`New() (*Client, error)`** -- Creates a new WireGuard control client
- **`Client.Device(name string)`** -- Query a WireGuard device by interface name
- **`Client.Devices()`** -- List all WireGuard devices on the system
- **`Client.ConfigureDevice(name string, cfg wgtypes.Config)`** -- Apply configuration (private key, listen port, peers, allowed IPs, etc.)
- **`Client.Close()`** -- Release resources

The `wgtypes` sub-package provides types like `Device`, `Peer`, `Config`, `PeerConfig`, `Key`, etc.

### Platform Support

| Platform | Mechanism | Notes |
|----------|-----------|-------|
| Linux | Generic Netlink | Full read/write |
| Windows | ioctl interface | Full read/write |
| FreeBSD | ioctl interface | Full read/write |
| OpenBSD | ioctl interface | **Read-only** |
| Userspace (wireguard-go) | Userspace config protocol (UNIX socket / named pipe) | Full read/write |

Platform detection is automatic with fallback: the library tries kernel-native first, then falls back to userspace if unavailable.

### Explicit Limitations (Out of Scope)

The library **explicitly states** that the following are out of scope:

- **Creating/deleting WireGuard interfaces** -- Cannot call `ip link add wg0 type wireguard` equivalent
- **Assigning IP addresses** to interfaces
- **Configuring routing tables**
- **DNS configuration**
- **Interface lifecycle management** (up/down)

It **only** handles the WireGuard-specific configuration: private keys, listen ports, peers, pre-shared keys, allowed IPs, keepalives, and endpoint addresses.

### Comparison to Shelling Out to wg-quick

wgctrl-go replaces **only the `wg` tool** (the low-level config utility), not `wg-quick` (which handles the full tunnel lifecycle including interface creation, IP assignment, routing, and DNS). To replicate what wg-quick does, you would need wgctrl-go PLUS platform-specific code for everything else.

---

## 2. Full Go-Based WireGuard Stack

### The Two Libraries

**wireguard-go** (`golang.zx2c4.com/wireguard`):
- Full userspace WireGuard protocol implementation in Go
- Creates TUN devices via `tun.CreateTUN(name, mtu)` -- platform-specific implementations exist for Linux (`tun_linux.go`), macOS (`tun_darwin.go`), and Windows (`tun_windows.go`)
- On macOS: uses utun driver, interface names must be `utun[0-9]+`
- On Windows: uses Wintun driver (DLL must be present)
- On Linux: opens `/dev/net/tun` clone device
- Can also run as an in-process library, not just a standalone daemon

**wgctrl-go** (`golang.zx2c4.com/wireguard/wgctrl`):
- Configures WireGuard parameters on existing devices (as described above)

### Using Both Together

Yes, you can combine wireguard-go + wgctrl-go to create and configure WireGuard tunnels **without** calling wg-quick or the wg CLI tool. The flow would be:

1. **wireguard-go**: `tun.CreateTUN("utun3", 1420)` -- creates the TUN device
2. **wireguard-go**: `device.NewDevice(tunDevice, conn.NewDefaultBind(), ...)` -- starts WireGuard protocol
3. **wgctrl-go**: `client.ConfigureDevice("utun3", config)` -- sets private key, peers, etc.

### What You Still Must Handle Yourself

Even with both libraries, you need **platform-specific code** for:

| Responsibility | Linux | macOS | Windows |
|---------------|-------|-------|---------|
| **IP address assignment** | netlink (`RTM_NEWADDR`) | `ifconfig` or ioctl | `netsh` or Windows API |
| **Route table manipulation** | netlink (`RTM_NEWROUTE`) | `route add` or ioctl | `netsh` or Windows API |
| **DNS resolver configuration** | resolvconf / systemd-resolved / `/etc/resolv.conf` | `scutil --dns` / `networksetup` | `netsh` or WMI/PowerShell |
| **Interface up/down** | netlink (`IFF_UP`) | `ifconfig up` | Windows API |
| **MTU setting** | netlink | `ifconfig mtu` | netsh |

### The Netstack Alternative (No Root Required)

wireguard-go also includes a **netstack** mode (`tun/netstack`) that uses gVisor's userspace TCP/IP stack:

```go
tnet, err := netstack.CreateNetTUN(localAddresses, dnsAddresses, mtu)
```

In this mode:
- **No OS-level TUN device** is created
- **No root/admin privileges** needed
- The OS only sees encrypted UDP packets
- Applications must explicitly use the virtual network stack (e.g., `tnet.DialContext`)
- This is what **wireproxy** uses to create a SOCKS5/HTTP proxy without root

**Limitation**: Netstack mode cannot transparently tunnel all system traffic -- it only works for applications that explicitly use the virtual stack's dial/listen functions. It is unsuitable for a traditional VPN client that routes all traffic.

---

## 3. Comparison: Go-Native vs Subprocess Approach

### Option A: Go-Native (wireguard-go + wgctrl-go + custom platform code)

**Pros:**
- No external dependencies at runtime (no need for `wg-quick`, `wireguard-tools`, or `wireguard-go` binary to be installed)
- Fine-grained error handling -- Go error types instead of parsing stderr
- Programmatic control over every aspect of the tunnel lifecycle
- Single binary distribution (everything compiled in)
- Can monitor tunnel state in-process (no polling subprocess)
- Used successfully by major projects: **Tailscale** and **NetBird** both embed wireguard-go

**Cons:**
- Must implement platform-specific networking code for 3 OSes:
  - Linux: netlink for routes/addresses (Go libraries exist: `vishvananda/netlink`)
  - macOS: `ifconfig`/`route` commands or raw ioctl (less well-supported in Go)
  - Windows: Wintun DLL dependency, `netsh` or Win32 API calls
- DNS configuration is the hardest part -- every OS handles it differently and there is no good cross-platform abstraction
- Significant development effort for routing table management
- Must track upstream wireguard-go changes
- Wintun driver DLL must be bundled on Windows
- Privilege escalation still required for TUN device creation (except netstack mode)

### Option B: Subprocess (wg-quick on macOS/Linux, wireguard.exe on Windows)

**Pros:**
- wg-quick handles **everything**: interface creation, IP assignment, routing, DNS, MTU, pre/post scripts
- Battle-tested, maintained by WireGuard project
- Dramatically less code to write and maintain
- DNS "just works" (resolvconf on Linux, scutil on macOS, Windows native)
- Routing "just works" (including complex AllowedIPs-based routing with fwmark)
- wg-quick is actively maintained (releases through 2026)
- Well-documented failure modes

**Cons:**
- External dependency: users must install wireguard-tools (or you bundle it)
- Error handling requires parsing subprocess output/exit codes
- Cross-platform inconsistency: wg-quick behaves differently across OSes
- On Windows, wg-quick does not exist in the same form -- need `wireguard.exe /installtunnelservice` or the WireGuard Windows tunnel service
- Harder to get real-time status (must poll `wg show` or read interface stats)
- Distribution complexity: must ensure wireguard-tools version compatibility
- Subprocess calls can fail silently or produce locale-dependent output

### Option C: Rust with defguard_wireguard_rs (Relevant to Your Project)

Since your project is in **Rust**, this deserves special attention:

**defguard_wireguard_rs** provides a unified Rust API that goes **far beyond** what wgctrl-go offers:

- `create_interface()` / `remove_interface()` -- full interface lifecycle
- IP address assignment
- Peer configuration and management
- **Peer routing** (`configure_peer_routing()`)
- DNS resolver configuration
- Works on: Linux (kernel + userspace), macOS (userspace via wireguard-go), Windows (kernel via WireGuard-NT DLL), FreeBSD, NetBSD

This is the closest thing to a "do everything" WireGuard library. It is what the **DefGuard client** uses internally.

**Trade-off**: On macOS, it still uses wireguard-go under the hood for the userspace implementation. On Windows, it requires the WireGuard-NT DLL (`wireguard.dll`).

### Recommendation Matrix

| Factor | Go-Native | Subprocess (wg-quick) | Rust (defguard_wireguard_rs) |
|--------|-----------|----------------------|------------------------------|
| Cross-platform uniformity | Medium | Low (different tools per OS) | **High** |
| Dependency management | Good (single binary) | Poor (external tools) | Good (single binary + DLL on Windows) |
| Error handling | **Excellent** | Poor (string parsing) | **Excellent** |
| Packaging complexity | **Low** | Medium-High | Low-Medium |
| Maintenance burden | **High** (must maintain platform code) | Low | Medium |
| Privilege escalation | Still needed | Still needed | Still needed |
| DNS handling | Must implement per-OS | Built-in | **Built-in** |
| Routing handling | Must implement per-OS | Built-in | **Built-in** |
| Development effort | Very High | **Low** | Medium |
| Real-time status | In-process | Polling required | In-process |

---

## 4. Existing Open-Source WireGuard Client Projects

### Desktop GUI Clients

#### DefGuard Client
- **URL**: https://github.com/DefGuard/client
- **Language/Framework**: Rust (backend) + TypeScript/React (frontend) via **Tauri**
- **WireGuard approach**: Uses `defguard_wireguard_rs` library directly -- no subprocess to wg-quick
- **Cross-platform**: macOS, Windows, Linux
- **Status**: **Actively maintained** (v1.6.7, March 2026). 359 stars, 41 releases
- **Notable features**: Multi-factor authentication (TOTP/Email + WireGuard PSK), connection statistics, multi-location support
- **Relevance**: This is the most architecturally similar project to what you are building. Worth studying closely.

#### WireGuardStatusbar (macos-menubar-wireguard)
- **URL**: https://github.com/aequitas/macos-menubar-wireguard
- **Language/Framework**: Swift (macOS native)
- **WireGuard approach**: **Subprocess** -- wraps `wg-quick` via XPC privileged helper
- **Cross-platform**: macOS only
- **Status**: **Superseded** by official WireGuard app, minimal maintenance
- **Architecture**: Menubar app + Privileged Helper (LaunchDaemon) communicating via XPC -- exactly the pattern in your project plan

#### Wireguird
- **URL**: https://github.com/UnnoTed/wireguird
- **Language/Framework**: Go + GTK
- **WireGuard approach**: Likely subprocess (wg-quick)
- **Cross-platform**: Linux only
- **Status**: Low activity, niche project
- **Notable**: Mimics the official Windows WireGuard GUI but for Linux/GTK

#### WireGUI
- **URL**: https://github.com/Devsfy/wiregui
- **Language/Framework**: Electron-based
- **WireGuard approach**: Subprocess
- **Cross-platform**: Linux and Windows
- **Status**: **Abandoned** -- developer no longer uses WireGuard

#### wireguard-gui (0xle0ne)
- **URL**: https://github.com/0xle0ne/wireguard-gui
- **Language/Framework**: Tauri + Next.js
- **WireGuard approach**: Likely subprocess
- **Cross-platform**: Linux only
- **Status**: Small/early project

#### GUI-WireGuard (universish)
- **URL**: https://github.com/universish/GUI-wireguard
- **Language/Framework**: Rust + Qt
- **WireGuard approach**: Integrated with wireguard-tools
- **Cross-platform**: RPM-based Linux only (Fedora, AlmaLinux)
- **Status**: Small/niche project

#### WireGuardclient2FA-tauri
- **URL**: https://github.com/TimKieu/WireGuardclient2FA-tauri
- **Language/Framework**: Tauri + React + Rust
- **WireGuard approach**: Unknown
- **Cross-platform**: Unknown
- **Status**: Small project, appears to be a DefGuard fork/variant

### Larger WireGuard-Based Projects (Not Pure Clients, but Relevant Architecture)

#### Tailscale
- **URL**: https://github.com/tailscale/tailscale
- **Language**: Go
- **WireGuard approach**: **Fully Go-native** -- embeds a forked wireguard-go, manages TUN devices, routing, DNS all in-process
- **Cross-platform**: macOS, Windows, Linux, iOS, Android
- **Status**: **Very active**, commercial product. The gold standard for Go-native WireGuard integration
- **Relevance**: Proves the Go-native approach works at scale, but required enormous engineering investment

#### NetBird
- **URL**: https://github.com/netbirdio/netbird
- **Language**: Go
- **WireGuard approach**: **Go-native** -- uses wireguard-go embedded, manages interfaces programmatically
- **Cross-platform**: macOS, Windows, Linux
- **Status**: **Very active**, 12k+ stars
- **Relevance**: Another proof that Go-native wireguard management works cross-platform

#### Firezone
- **URL**: https://github.com/firezone/firezone
- **Language**: Rust (clients), Elixir (server)
- **WireGuard approach**: Uses Rust-based WireGuard implementation in clients
- **Cross-platform**: macOS, Windows, Linux, iOS, Android
- **Status**: **Very active**, 8.5k stars, Apache 2.0 + Elastic 2.0 license
- **Relevance**: Proves the Rust-native approach works for cross-platform VPN clients

#### Wireproxy
- **URL**: https://github.com/octeep/wireproxy
- **Language**: Go
- **WireGuard approach**: **Fully Go-native** using wireguard-go + **netstack** (no TUN device, no root)
- **Cross-platform**: macOS, Windows, Linux
- **Status**: Active
- **Relevance**: Demonstrates the netstack approach for rootless WireGuard, but cannot route all system traffic

### Rust WireGuard Libraries (Not Clients, but Building Blocks)

#### defguard_wireguard_rs
- **URL**: https://github.com/DefGuard/wireguard-rs
- **What**: Unified Rust API for WireGuard interface management (create, configure, route, DNS)
- **Status**: Active (v0.7.8, Sept 2025), 299 stars
- **Key**: The most complete Rust library for WireGuard management. Handles interface creation, IP assignment, peer routing, and DNS -- unlike wgctrl-go which only does configuration.

#### BoringTun (Cloudflare)
- **URL**: https://github.com/cloudflare/boringtun
- **What**: Userspace WireGuard protocol implementation in Rust (crypto + packet handling only, no network stack)
- **Status**: Active, deployed on millions of devices (Cloudflare WARP)
- **Bindings**: C ABI, JNI (Java), Swift bridging header
- **Key difference from defguard_wireguard_rs**: BoringTun is low-level (protocol only), while defguard_wireguard_rs is high-level (full interface management)

---

## Summary and Recommendations for Your Project

Given that your project is a **Rust + egui** desktop client targeting macOS, Windows, and Linux:

### Most Pragmatic Path: Hybrid Approach

**Phase 1 (MVP)**: Use subprocess calls to `wg-quick` (macOS/Linux). This matches your current plan and gets you to a working product fastest.

**Phase 2 (Maturity)**: Evaluate migrating to `defguard_wireguard_rs` for a library-based approach. This would:
- Eliminate the wireguard-tools dependency
- Give you programmatic error handling
- Provide a more unified cross-platform experience
- Still require wireguard-go on macOS and WireGuard-NT DLL on Windows

### Key Project to Study

The **DefGuard client** (https://github.com/DefGuard/client) is the closest architectural match to your project: Rust + Tauri (similar to Rust + egui), cross-platform, uses defguard_wireguard_rs for native WireGuard management. Their codebase would be the most valuable reference for solving platform-specific issues (privilege escalation, DNS, routing).

### Windows Strategy Note

Windows is the most divergent platform. wg-quick does not exist on Windows in the traditional sense. Options:
1. Shell out to `wireguard.exe /installtunnelservice <config>` (official Windows app approach)
2. Use WireGuard-NT DLL directly via FFI (what defguard_wireguard_rs does)
3. Bundle a Windows service that manages WireGuard-NT

This is the strongest argument for eventually moving to a library approach rather than subprocess.
