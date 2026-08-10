# Linux verification plan

Target baseline: Debian 13 / Raspberry Pi OS, ARM64, Wayland (`labwc`) and
WayVNC. CI baseline: Ubuntu latest, AMD64.

## Automated gate

- Clean frontend install and production build (`npm ci`, `npm run build`).
- Go unit tests and vet after `frontend/dist` exists.
- Race tests on Linux AMD64 CI. Raspberry Pi's 39-bit ARM64 VMA layout is not
  supported by Go's race runtime, so `-race` cannot run on this device.
- Native Wails production build and `ldd` missing-library check.
- DEB generation, metadata inspection, desktop-file validation, and simulated
  APT installation.
- Repeat the native build on ARM64 hardware before a release.

## GUI and desktop integration

- Launch under X11/Xvfb for a crash smoke test.
- Launch in a real Wayland session and verify initial window, resizing,
  minimising, close-to-tray, tray menu actions, theme, scaling, and dialogs.
- On Raspberry Pi's detached/headless labwc output, also test through XWayland
  (`GDK_BACKEND=x11`). Native Wayland WebKitGTK rendering is corrupted on that
  virtual output even with the original dependency set, while XWayland renders
  correctly. This is a test-host compositor limitation, not a frontend result.
- On the Pi, verified the real Linux tray click path (not only its menu): native
  close hides the window without terminating the process, and a left click on
  the tray icon restores a decorated window.
- Confirm the PolicyKit prompt appears, cancellation is handled, successful
  authentication starts the helper, and closing the last GUI causes the idle
  helper to exit.
- Verify XDG autostart creation/removal and launch after a fresh login.
- Install the DEB, check application-menu/icon/tray integration, then purge it
  and confirm no package-owned files remain.

## Linux-only network behaviour

### Raspberry Pi smoke-test result (2026-08-04)

- Imported and connected a disposable WireGuard tunnel through the real helper.
- Confirmed the `wg` interface was up with MTU 1420 and the configured IPv4
  route was installed.
- Disconnected and deleted the tunnel, then confirmed both the interface and
  route were removed.
- Confirmed routine RTNETLINK traffic no longer produces false primary-network
  changes; reconnect decisions now compare the actual default route snapshot.
- This local peer intentionally had no server, so handshake, payload, DNS and
  kill-switch verification still require a real test endpoint.

Run these with a local console or a second management path. A full-tunnel or
kill-switch defect can sever the SSH/VNC session used to test it.

- Helper Unix socket: directory ownership/mode, peer UID rejection, stale
  socket recovery, GUI reconnect, helper version replacement.
- TUN: create/configure/remove the interface and recover after forced helper
  termination.
- Routing: IPv4/IPv6 split tunnel, dual-stack full tunnel, endpoint bypass,
  custom `Table`/`FwMark`, repeated connect/disconnect, and no leaked routes or
  policy rules.
- DNS: test systemd-resolved, resolvconf, and plain `/etc/resolv.conf` paths;
  verify restoration after disconnect, helper crash, and reboot.
- Firewall: kill switch and DNS leak protection using nftables; verify LAN and
  endpoint exceptions and cleanup after every failure path.
- Network changes: NetworkManager Wi-Fi SSID events, gateway MAC matching,
  Ethernet/Wi-Fi handover, DHCP/default-route change, offline/online recovery.
- Power: logind suspend/resume reconnect and fallback polling on systems
  without logind.

## Cross-OS comparison points

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| Elevation/helper | PolicyKit + Unix socket/peer UID | launchd helper | UAC + named pipe |
| Tunnel/routes | TUN + `ip` policy routing | utun + route socket | Wintun/IP Helper APIs |
| DNS | resolved/resolvconf/resolv.conf | networksetup | Windows IP APIs |
| Kill switch | nftables | pf | Windows firewall/WFP path |
| Wi-Fi identity | NetworkManager + `/proc` ARP | CoreWLAN | WLAN/IP Helper APIs |
| Sleep/network events | logind + netlink | IOKit/SystemConfiguration | Windows notifications |
| Autostart | XDG desktop entry | LaunchAgent | registry Run key |
| Desktop shell | GTK/WebKitGTK + AppIndicator | AppKit/WebKit | WebView2/tray |

For every platform-sensitive test, compare the observable contract rather
than the implementation: identical tunnel status, route/DNS cleanup, reconnect
timing, error text, persisted settings, and tray/window state.
