# Manual Test Checklist

Things that can't be reasonably automated and must be verified by hand
before considering the related feature done. Items here are added when
shipped without end-to-end verification — clear them out as you walk
through each one.

The [2026-10-21 execution report](analysis/macos-native-verification-20261015.md#full-application-verification--2026-10-21)
records current macOS results and remaining hardware limits. Older combined
platform checkboxes below are not a claim that those completed macOS cases
still lack evidence; they also include Windows and unavailable hardware.

## Phase 4 — Automation rules (helper-side, issue #12)

Rule evaluation lives in `internal/helper/wifi_rules.go`
(`reevaluateAutomation`); the rule model + engine live in
`internal/wifi/automation.go` (`Evaluate`); rule data lives in
`Settings.Automation` (`internal/storage/settings.go`). Legacy
`Settings.WifiRules` is migrated once on first read. The helper evaluates
rules itself. Verify with the window open and after closing it to the tray.
Explicit Quit (Cmd+Q) now shuts down the helper and its tunnels; it is not a
background-automation mode. Manual Connect/Disconnect overrides rule actions
until the override is cleared; check `ctl automation` for that latch.

Rules can be authored in the GUI (tunnel detail → **Automation**) or from
the CLI (`wireguide ctl automation add/rm/rules`). The read-only preview
`wireguide ctl automation` prints the current network context (SSID,
gateway MAC, physical IPs) and each tunnel's decision — use it to check
expectations without reading logs.

Semantics reminder: rules are evaluated top to bottom, first matching
concrete condition wins (a `none_match`/`else` rule is the fallback);
order = priority, and a rule can connect OR disconnect regardless of how
the tunnel was brought up.

### Connect on a network (SSID)
- [ ] Add `connect` when `ssid:<current-wifi>` for a tunnel with no manual
      Off override; rejoin/stay on that SSID. **Expected**: helper log
      `automation: rule connect ... reason=ssid-change`, tunnel up within
      ~6s. Confirm with `ctl automation` (decision=connect).
- [ ] Repeat after closing the window to the tray, with the app still
      running. The rule must still fire; `ctl status` confirms.

### Disconnect on a specific network (gateway MAC)
- [ ] On the target network, capture its gateway MAC (`ctl automation`
      shows `gateway-mac=`), add `disconnect` when `mac:<that-MAC>`.
- [ ] Clear any manual On override; **Expected**: within a few seconds the
      route-change trigger fires `automation: rule disconnect
      reason=network-change` and the tunnel goes down. Verify the MAC
      match is separator/case-insensitive (dash/upper-case forms match).

### Subnet condition + Ethernet
- [ ] Add `disconnect` when `subnet:<your-current-CIDR>` for a connected
      tunnel without a manual On override (Ethernet needs no SSID).
      **Expected**: it disconnects. On macOS this fires via the route
      monitor instantly; on Windows/Linux within the 30s poll.

### Priority / conflict
- [ ] Add two rules that both match now with opposite actions (e.g.
      `disconnect ssid:X` and `connect else`, or two matching concrete
      conditions). **Expected**: the top rule wins. Reorder (GUI drag, or
      `rm` + `add`) and confirm the result flips.

### Rule edits without restart
- [ ] Edit rules (GUI or `ctl automation add`) while connected to a
      network. **Expected**: the change takes effect on the next trigger
      (SSID change / route change / 30s poll) — the helper rereads
      config.json each evaluation, no restart.

### Negative cases
- [ ] A tunnel with NO rules is never auto-touched (connect it manually;
      it stays up across network changes).
- [ ] A malformed MAC/CIDR rule never matches (and the GUI flags it red);
      it doesn't crash or affect other rules.
- [ ] Wi-Fi off / on Ethernet with only SSID rules — those rules simply
      don't match (SSID is empty); nothing happens.

## Endpoint loop protection (issue #49, macOS and Windows)

These checks remain pending. Loopback integration tests exercise the real
WireGuard engine and UDP transport, but do not exercise a remote VPN peer,
native Windows interface binding, or physical network changes.

- [ ] With a real peer, verify split tunnel, IPv4 full tunnel and dual-stack
      full tunnel. Sustain a fast one-way upload; the watchdog must not
      disconnect merely because receive traffic is low.
- [ ] Switch Wi-Fi/Ethernet and disable/re-enable the physical connection.
      Verify recovery, the endpoint's physical forwarding path, and absence
      of recursive outer traffic. Include an IPv4-only underlay.
- [ ] On macOS, remove an owned endpoint bypass while keeping the same
      gateway. Verify safe route repair; if repair fails, outer sends must
      remain blocked until forwarding is verified or the tunnel is stopped.
- [ ] On Windows, change the listen port while connected. Verify native
      socket interface binding survives socket recreation. Disconnect under
      sustained upload and confirm shutdown completes.
- [ ] With two tunnels and DNS protection/kill switch enabled, stop one via
      the watchdog. Verify the other tunnel's traffic and DNS still work,
      while the stopped tunnel's permits and DNS rules are removed.
- [ ] After a forced disconnect, exercise network rules, sleep/wake and a
      helper restart. The stopped tunnel must stay blocked from automatic
      reconnect; a successful manual connect must clear the block.
- [ ] Disconnect the last tunnel and exit the helper. Verify system DNS,
      endpoint routes and firewall rules are restored to their prior state.

## macOS menu bar (issues #45 and #46)

The standalone Cocoa fixture passes on macOS 26.3.1: persistent menu,
action dispatch, template image, badge click passthrough, disabled emphasis
and cleanup. These target scenarios still need hardware verification:

- [ ] On macOS 27, open the menu with left/right click and keyboard; repeat
      after selecting a tunnel and after dismissing the menu.
- [ ] On two displays with different light/dark wallpapers, change the
      focused display. Compare glyph contrast and inactive emphasis with
      Apple's menu-bar icons in both connected and disconnected states.
- [ ] Verify the green connected badge, absence of a persistent background
      box, and VoiceOver's connection-state announcement.

## macOS native networking follow-up (2026-10-15)

[Execution report](analysis/macos-native-verification-20261015.md) records
passed native split-route IPv4/IPv6 traffic, macOS resolver dispatch, DNS/KS
packet enforcement, PF repair/coexistence, system launchd crash restoration
and product cleanup. Forced-disconnect tests inject the event and validate
real teardown/block persistence; genuine recursive-route detection and remote
full-tunnel tests above remain unchecked. Actual sleep/wake was deferred by
the user. The test runner is `scripts/macos_native_live_test.py`.
