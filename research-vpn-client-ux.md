# VPN Desktop Client UX Research

## 1. OpenVPN Connect Desktop App -- Detailed Screen Analysis

### 1.1 Main Connection Screen
- Single-profile focus: The main screen shows the currently selected/active profile prominently
- Large connect/disconnect toggle
- Connection throughput graph visible when connected (real-time bandwidth visualization)
- Connection duration timer (though users report bugs where it gets stuck at 00:00:00)
- Profile name and server hostname displayed

### 1.2 Profile/Server List (My Profiles)
- Accessed via hamburger menu (three horizontal lines) in the top-left corner
- Shows list of all imported .ovpn profiles
- Each profile entry shows: profile name, hostname, type, username
- Add icon (+) to import new profiles
- **Version 3.7.x (old)**: All profiles visible in one flat list with inline on/off toggles -- users could quick-switch between profiles in 1-2 clicks
- **Version 3.8+ (new, controversial)**: Removed inline toggles; users must select a profile, navigate to it, then connect separately. Excessive padding/whitespace reduced information density. Users with just 4 profiles had to scroll.

### 1.3 Settings Page
Split into two sections:

**Application Settings:**
| Setting | Options |
|---------|---------|
| Device ID | UUID display + copy button |
| VPN Protocol | Adaptive / TCP / UDP |
| Connection Timeout | 10sec, 30sec, 1min, 2min, Continuous Retry |
| Launch Options | Start app / Connect latest / Restore connection / None |
| Seamless Tunnel | Toggle (blocks internet while VPN reconnects) |
| Minimize on Launch | Toggle |
| Captive Portal Detection | Toggle |
| Software Update | Daily / Weekly / Monthly / Never |
| Theme | System / Light / Dark |
| Disconnect Confirmation Dialog | Toggle |

**Advanced Settings:**
| Setting | Options |
|---------|---------|
| Security Level | Preferred / Legacy / Insecure |
| Enforce TLS 1.3 | Toggle |
| Enable DCO | Toggle (data channel offload) |
| Block IPv6 | Toggle |
| DNS Fallback | Toggle (Google DNS as backup) |
| Allow local DNS resolvers | Toggle |

### 1.4 Import Profile Flow
Three methods supported:

**URL Import:**
1. Menu -> My Profiles -> Add icon (+)
2. "Import Profile" screen appears
3. Enter VPN server URL -> tap "Continue"
4. Browser opens for authentication (Basic/MFA/SAML)
5. "Import Profile" confirmation dialog appears
6. Tap "Confirm"
7. Profile becomes main/active profile

**File Upload:**
1. Menu -> My Profiles -> Add icon (+)
2. "Import Profile" screen appears
3. Click "Upload File" button
4. OS file picker opens, navigate to .ovpn file
5. Confirmation dialog appears
6. Click "OK"

**Drag and Drop (Windows/macOS):**
1. Drag .ovpn file onto any screen in the app
2. Confirmation dialog appears
3. Click "OK"

**Double-Click (Windows/macOS):**
1. Double-click any .ovpn file in file explorer
2. App opens, confirmation dialog appears
3. Click "OK"

### 1.5 Connection Status View
- Connection status text (Connected/Disconnected)
- Throughput graph (real-time bandwidth)
- Connection duration timer
- Server hostname/IP

### 1.6 Other Screens
- **Log viewer**: Users report it is poorly designed with limited filtering
- **About/version info**

---

## 2. What Makes OpenVPN Connect "Simple" (Strengths)

1. **Single-focus main screen**: Shows one active connection prominently rather than overwhelming with options
2. **Drag-and-drop profile import**: Extremely low friction -- just drop a .ovpn file anywhere on the app
3. **Double-click .ovpn association**: File type association means users can import by just double-clicking
4. **Minimal required interaction**: Connect with one tap after profile import
5. **Sensible defaults**: Adaptive protocol selection, auto-reconnect built-in
6. **Seamless Tunnel feature**: Internet blocking during reconnection (kill switch equivalent) as a simple toggle
7. **Captive portal detection**: Automatically handles wifi login pages
8. **Theme support**: System/Light/Dark follows OS preference
9. **Clean separation**: Application settings vs. Advanced settings keeps the common case simple while power users can dig deeper

---

## 3. Common Complaints About OpenVPN Connect UX

### From GitHub Issues (OpenVPN/openvpn#852):
- **"New UI is awfully inconvenient"**: Version 3.8 removed quick on/off toggles for multiple profiles
- **"Multiple profiles were shown in 1x list when the app opens, now there is 1 = more clicks = bad"**
- **Excessive padding and whitespace**: "So much padding and bloat around each one I have to scroll up and down to see them all (I only have 4 profiles saved)"
- **Loss of information density**: Old UI had "great information density" and was "far better than most VPN clients on the market"
- **More clicks for same task**: Switching profiles now requires: open profile menu -> select profile -> enable. Previously: just toggle in the list.

### From Forums and Reviews:
- **Confusing profile management**: No way to see which devices are using which profile
- **Poor logging**: "Terrible logging function"
- **"Open-source ugly and un-intuitive UI"**: General sentiment that it looks dated
- **Status display bugs**: Shows "disconnected" while simultaneously showing a connected throughput graph
- **Duration timer stuck**: Connection timer showing 00:00:00 even when connected
- **No credential persistence**: App fails to save login credentials in some cases
- **App not opening**: Multiple forum threads about the app simply not launching

### Key Lesson:
> OpenVPN Connect v3.7.x was widely praised for its information density and quick toggles. The v3.8 redesign prioritized aesthetics over functionality and was broadly rejected. **Information density and minimal clicks matter more than visual polish for VPN clients.**

---

## 4. Competitor VPN Client UX Analysis

### 4.1 Mullvad VPN Desktop App

**Architecture**: Electron-based (Rust daemon + React frontend). Open source.

**Main Screen:**
- Map view as background (with animation toggle in settings)
- Connection status prominently displayed at top: "CONNECTED" or "DISCONNECTED"
- Top bar color changes: green (connected), red (disconnected)
- Expandable connection details (click arrow next to "CONNECTED"): entry IP, port, transport protocol, exit IP
- "Switch location" button to change server
- "Reconnect" button to switch to another server in the same region

**System Tray:**
- Padlock icon changes: green+locked (connected), red (disconnected), green+red dot (blocking/error)
- Yellow dot on padlock for updates or expiring account time

**Server Selection:**
- Hierarchical: Country -> City -> Individual server
- Scroll with mouse wheel or scrollbar
- Search field for quick lookup
- Unavailable servers shown with red dot + greyed name
- Filter button: ownership (Mullvad-owned vs. rented), provider filtering

**Settings (organized sections):**
- VPN Settings: Launch on startup, auto-connect, local network sharing, DNS blockers, IPv6, kill switch (always on, non-toggleable), lockdown mode, tunnel protocol (WireGuard/OpenVPN)
- WireGuard Settings: Port selection, obfuscation (Shadowsocks, UDP-over-TCP), quantum-resistant tunnels, IP version, MTU
- OpenVPN Settings: Transport protocol, bridge mode, Mssfix
- UI Settings: Notifications, monochromatic tray icon, language, taskbar pinning, minimized startup, map animation
- DAITA: Traffic pattern obfuscation
- Multihop: Dual-server routing
- Split tunneling: Per-application VPN exclusion
- API access: Connection method management with testing
- Support: Problem reporting, FAQ links
- App info: Version, changelog, beta program

**Notifications:**
- Tiered system: critical alerts always display
- Account expiry warnings start 3 days before expiration
- "Update available" messaging on connection screen

**Account Management:**
- Separate screen: account number, device name, time remaining, "buy more credit" button, voucher redemption, logout
- 5-device limit with removal dialog

**Kill Switch:**
- Always active, non-toggleable -- this is a deliberate design choice
- When VPN drops, shows "BLOCKING INTERNET" state
- Persists until secure connection made or user manually disconnects

**What Makes Mullvad's UX Great:**
1. Color-coded status is instantly readable (red = danger, green = safe)
2. Kill switch is always on -- removes decision fatigue
3. Server filtering by ownership/provider is a power-user feature done simply
4. Single settings page, no tabs or nested navigation
5. Monochromatic tray icon option (blends with OS)
6. Search in server list
7. Blocking state is clearly communicated -- user knows they are safe even when disconnected

### 4.2 IVPN Desktop App

**Architecture**: Electron-based (daemon + Electron UI). Open source.

**Main Screen:**
- Map view showing public IP and location
- Quick-access buttons for Firewall and AntiTracker
- Protocol switching easily accessible
- Clear visual verification of connected status

**Server Selection:**
- Searchable server list
- Server sorting
- Favorite servers with star/bookmark
- "Exclude for Fastest server" option

**Account Page:**
- QR code for quick setup on other devices

**Design Philosophy:**
- Single unified codebase for Linux, macOS, and Windows
- Dark theme support (Windows)
- Focus on making frequently used settings accessible
- Improved server discovery through search

**Key UX Patterns:**
1. Map-based visualization of connection
2. Favorites system for frequently used servers
3. QR code for cross-device setup
4. Accessible Firewall/AntiTracker toggles on main screen

### 4.3 Tailscale Desktop App

**Architecture**: Go daemon + native UI per platform. Not open source (clients are open source).

**macOS Windowed App (new):**
- Searchable device list with connection status indicators
- Selecting a device shows detail panel on the right (split view)
- One-click actions: copy MagicDNS name, copy IP, ping, send files via Taildrop
- Exit node selection: searchable, with one recommended based on latency/performance/location
- "Mini player" mode: collapses to minimal UI showing just connection status + exit node control
- Red dot on Dock icon for critical errors
- Product tour on first install/update for onboarding

**macOS Menu Bar:**
- Runs alongside windowed app (not replaced)
- Quick access to connect/disconnect, switch accounts

**Windows System Tray:**
- Octagonal blue/white logo icon
- Tray menu shows: account name, connection status, device's Tailscale IP

**Key UX Innovations:**
1. **Mini player concept**: Brilliant for users who just want status at a glance
2. **Recommended exit node**: Reduces decision fatigue (auto-picks best server)
3. **Dock icon red dot**: OS-native error indicator without popups
4. **Onboarding product tour**: Guides new users through features
5. **Dual interface** (menu bar + windowed): Users choose their preferred interaction model
6. **Search everywhere**: Device list, exit nodes all searchable

### 4.4 WireGuard Official Windows App

**Main Window ("Manage WireGuard Tunnels"):**
- Left panel: Tunnel list (all imported .conf tunnels)
- Right panel: Selected tunnel details (config text, connection status, statistics)
- Bottom-left: "+" button -> "Add empty tunnel" / "Import tunnel(s) from file"
- Activate/Deactivate button for selected tunnel
- Edit button to modify config text
- Transfer statistics: received/sent bytes, latest handshake time

**System Tray:**
- Each tunnel appears as a menu item
- Click to activate/deactivate

**Strengths:**
- Straightforward, no-nonsense interface
- Config text visible and editable
- Real-time log viewer for debugging
- Statistics (RX/TX, handshake time)

**Weaknesses:**
- Raw config text editing is intimidating for non-technical users
- No visual status indicators beyond text
- No kill switch UI (must manually set "Block untunneled traffic" in config editor)
- No auto-connect rules
- No split tunneling UI
- No connection animation or transition feedback
- Ugly/dated UI aesthetic
- Filename length cap causes cryptic "Invalid name" errors on import
- Claims connected even when endpoint is unreachable (no dead connection detection)
- No confirmation dialog before connecting
- On-demand mode doesn't remember prior state when switching tunnels

### 4.5 WireGuard Official macOS App

**Interface:**
- Menu bar icon (primary interaction point)
- "Manage Tunnels" window: similar to Windows (tunnel list + detail panel)
- On-demand options: auto-activate on WiFi/Ethernet, exclude private IPs
- Auto-generates public/private key pairs when adding empty tunnel
- Real-time log viewer

**Critical Issues (as of 2024-2026):**
- **Abandoned since 2022**: No releases, no merged PRs, issues disabled on GitHub
- **macOS Tahoe incompatibility**: Network Extension causes CPU wakeup storms
- **Split DNS non-functional**: PR approved but never merged
- **App Store only**: Requires Apple ID, no direct download option
- Maintainer acknowledged resource constraints but never recruited community help

---

## 5. UX Patterns That Make a VPN Client Feel "Polished"

### 5.1 Connection Animation/Feedback
- **Color transitions**: Background/header smoothly transitions from red -> yellow (connecting) -> green (connected). Mullvad does this excellently.
- **Progress indicators**: Subtle spinner or pulsing animation during handshake
- **Haptic/audio feedback**: Optional subtle sound on connect/disconnect (Tailscale does a subtle animation)
- **Avoid**: Hard state jumps with no intermediate "connecting" state. Users need to see that something is happening.

### 5.2 Status Indicators
- **Traffic light colors**: Universal understanding -- red (disconnected/danger), yellow/amber (connecting/warning), green (connected/safe)
- **System tray icon states**: At minimum 3 states (disconnected, connecting, connected). Mullvad adds a 4th (blocking).
- **Monochromatic option**: Some users prefer tray icons that match OS theme (Mullvad offers this)
- **IP address display**: Show the VPN IP when connected for quick verification
- **Connection details on demand**: Expandable panel for technical details (protocol, port, server IP, handshake time)

### 5.3 Error Messaging
- **Contextual errors**: "Could not resolve endpoint 'vpn.example.com:51820' -- check your internet connection" rather than generic "Connection failed"
- **Actionable suggestions**: Every error should tell the user what to try next
- **Blocking state communication**: Mullvad's "BLOCKING INTERNET" is clear and reassuring (it's protecting you, not broken)
- **Config validation before connect**: Parse and highlight errors in the config before attempting connection, not after failure
- **Avoid**: Raw WireGuard log output as error messages

### 5.4 Onboarding/First-Run Experience
- **Empty state with clear CTA**: "No tunnels configured. Import a .conf file or create one." with prominent buttons
- **Drag-and-drop hint**: Visual drop zone indicator for .conf files
- **Product tour**: Tailscale shows a brief tour of features on first launch
- **Quick start**: Minimize steps between install and first connection (import file -> connect, 2 steps)
- **Avoid**: Blank windows with no guidance. The official WireGuard apps drop you into an empty tunnel list with no hint of what to do next.

### 5.5 Tray Icon Behavior
- **Always present**: Icon should remain in tray even when main window is closed
- **Distinct states**: Visually different icons for disconnected/connecting/connected
- **Right-click menu**: Quick tunnel list with connect/disconnect toggles, Settings, Quit
- **Left-click**: Show/hide main window (macOS: show menu, Windows: show/hide window)
- **Tooltip**: Show connection status + tunnel name + duration on hover
- **Notification on state change**: OS notification when connection drops unexpectedly (not on intentional disconnect)
- **Close button behavior**: Minimize to tray, not quit. First time, show a notification: "App is still running in the system tray"

---

## 6. WireGuard Client UX Improvements Users Would Appreciate

Based on all research, these are the most impactful UX improvements over the official WireGuard apps:

### 6.1 Critical (Must-Have for Differentiation)

1. **Kill switch toggle**: The official app buries this in config text (`BlockUntunnelledTraffic`). Make it a prominent, labeled toggle.

2. **Dead connection detection + auto-reconnect**: Official app shows "connected" even when endpoint is down. Monitor handshake timestamps; if no handshake within configurable timeout, show warning and offer/attempt reconnect.

3. **Friendly config import**: Instead of editing raw INI text, provide a form-based UI:
   - Server address field with hostname resolution check
   - Key fields with show/hide toggle and paste button
   - AllowedIPs with presets: "Route all traffic" (0.0.0.0/0) vs "Only specified subnets"
   - DNS field with common presets (Cloudflare, Google, system default)
   - Validation with human-readable error messages

4. **Connection status with live stats**: RX/TX speed (not just cumulative bytes), latest handshake time with age indicator ("2 seconds ago" turning yellow at >2min), connection duration.

5. **Auto-connect rules**: Connect automatically on specific WiFi networks, on boot, or on wake from sleep.

6. **Proper error messages**: Instead of "Invalid name" for a too-long filename, say "Tunnel name must be 15 characters or fewer."

### 6.2 Important (Strong Differentiators)

7. **Quick-switch between tunnels**: One-click switching from tray menu, like the old OpenVPN Connect v3.7 approach. Each tunnel has an inline toggle.

8. **Split tunneling UI**: Visual editor for AllowedIPs with CIDR helper. Presets for common scenarios. Show what traffic goes through VPN vs direct.

9. **Drag-and-drop + batch import**: Drop multiple .conf files at once. Show a preview list before importing.

10. **Dark/light mode**: Follow system theme automatically.

11. **DNS leak protection**: As a toggle, not requiring manual firewall rules.

12. **Search/filter tunnels**: Essential when managing more than 5-10 tunnels.

13. **Config export**: Re-export .conf files for backup or sharing to other devices.

### 6.3 Nice-to-Have (Delight Features)

14. **Connection animation**: Smooth color transition from disconnected -> connecting -> connected state.

15. **Mini mode / compact view**: Like Tailscale's mini player -- a tiny floating widget showing just status + connect button.

16. **Recommended/fastest server**: If user has multiple tunnels, auto-recommend the one with lowest latency (ping test on handshake).

17. **QR code import**: Scan a QR code from screen or image file (common for WireGuard configs shared from routers).

18. **Tray icon with speed indicator**: Show current up/down speed as a tooltip or even as a tiny graph in the tray.

19. **Connection history/log**: Timeline of connect/disconnect events with duration and data transferred.

20. **Keyboard shortcuts**: Ctrl/Cmd+1-9 to quick-connect tunnels. Global hotkey to toggle VPN.

---

## 7. Design Principles for Our WireGuard Client

Based on all the above research, the following principles should guide the UX:

### Principle 1: Information Density Over Decoration
The OpenVPN Connect v3.8 backlash proves that users prefer dense, functional layouts over spacious, "modern" designs. Every pixel should convey useful information.

### Principle 2: One-Click for the Common Case
Connecting to a VPN should be 1 click from the tray icon. Switching tunnels should be 1 click. The most frequent actions must have the shortest paths.

### Principle 3: Traffic Light Status System
Red/Yellow/Green is universally understood. Use it consistently across: main window header, tray icon, notification dot.

### Principle 4: Progressive Disclosure
Main screen shows only: tunnel name, status, connect button, live stats. Advanced details (config text, handshake details, log) are one click deeper. Settings split into Basic and Advanced sections.

### Principle 5: Fail Loudly and Helpfully
Never silently fail. Never show "connected" when the tunnel is dead. Every error gets a human-readable message and an actionable suggestion.

### Principle 6: Protect by Default
Kill switch should be easy to enable (prominent toggle, not buried in config). DNS leak protection should be on by default. Reconnect automatically after sleep/wake.

### Principle 7: Import Should Be Effortless
Support every import method: drag-and-drop, file picker, double-click .conf file association, clipboard paste, QR code scan, URL import. Batch import for multiple files.

---

## Sources

- [OpenVPN Connect Settings (Windows)](https://openvpn.net/connect-docs/app-settings-windows.html)
- [OpenVPN Connect User Guide](https://openvpn.net/connect-docs/user-guide.html)
- [OpenVPN Connect Import Profile](https://openvpn.net/connect-docs/import-profile.html)
- [OpenVPN Connect UI Complaint (GitHub #852)](https://github.com/OpenVPN/openvpn/issues/852)
- [OpenVPN Connect App Info](https://openvpn.net/connect/)
- [Using the Mullvad VPN App](https://mullvad.net/en/help/using-mullvad-vpn-app)
- [Mullvad VPN GitHub](https://github.com/mullvad/mullvadvpn-app)
- [Redesigning Mullvad VPN (Behance)](https://www.behance.net/gallery/74594901/Redesigning-Mullvad-VPN)
- [IVPN Desktop App (GitHub)](https://github.com/ivpn/desktop-app)
- [New IVPN Apps for macOS and Windows](https://www.ivpn.net/blog/new-ivpn-apps-for-macos-and-windows/)
- [Tailscale Windowed macOS UI](https://tailscale.com/blog/windowed-macos-ui-beta)
- [Tailscale: Escaping the Notch](https://tailscale.com/blog/macos-notch-escape)
- [WireGuard macOS App Abandoned (HN)](https://news.ycombinator.com/item?id=43369111)
- [TunnlTo Desktop App (GitHub)](https://github.com/TunnlTo/desktop-app)
- [WG Tunnel (GitHub)](https://github.com/wgtunnel/wgtunnel)
- [WireGuard G2 Reviews](https://www.g2.com/products/wireguard/reviews)
- [WireGuard App Store](https://apps.apple.com/us/app/wireguard/id1451685025)
- [Mullvad VPN Review 2026 (CyberInsider)](https://cyberinsider.com/vpn/reviews/mullvad-vpn/)
- [IVPN for Windows](https://www.ivpn.net/en/apps-windows/)
