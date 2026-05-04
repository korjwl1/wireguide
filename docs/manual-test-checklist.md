# Manual Test Checklist

Things that can't be reasonably automated and must be verified by hand
before considering the related feature done. Items here are added when
shipped without end-to-end verification — clear them out as you walk
through each one.

## Phase 4 — Wi-Fi auto-connect rules (helper-side)

Implementation lives in `internal/helper/wifi_rules_darwin.go`; rule
data lives in `Settings.WifiRules` (`internal/storage/settings.go`).
The helper evaluates rules itself, so these tests verify behavior
**both with the GUI running and after Cmd+Q'ing the GUI**.

### Setup
- [ ] Settings → Wi-Fi 규칙 master toggle ON
- [ ] In a tunnel's detail panel, open "자동 연결" modal and add the
      current Wi-Fi SSID
- [ ] (Optional) Add a different SSID to the same tunnel, and a third
      SSID to a different tunnel

### Per-tunnel auto-connect (fires on join)
- [ ] Disconnect tunnel manually. Switch Wi-Fi to a SSID listed for
      that tunnel. **Expected**: helper log shows
      `wifi rule: matched SSID, connecting` and the tunnel comes up
      within ~6s. UI reflects connected state.
- [ ] Repeat with the GUI completely quit (Cmd+Q, confirm process is
      gone via `pgrep -f WireGuide.app`). The auto-connect must still
      fire — only the helper log will show it; relaunch the GUI to see
      the connected state.

### Trusted-SSID disconnect
- [ ] Add the current SSID to Settings → Wi-Fi 규칙 → 신뢰하는 네트워크.
- [ ] Connect any tunnel.
- [ ] Switch to a different SSID, then back to the trusted one.
      **Expected**: log shows `wifi rule: trusted SSID, disconnecting
      all`; all tunnels go down.

### Auto-disconnect on leaving auto-connect zone
- [ ] Connect to an auto-connect SSID — tunnel comes up automatically.
- [ ] Switch to a SSID that has no rule (and is not trusted).
      **Expected**: log shows
      `wifi rule: SSID no longer in auto-connect list, disconnecting`;
      that tunnel goes down. Manually-connected tunnels (started via
      the Connect button rather than a rule) **must not** be touched.

### Rule edits without restart
- [ ] While on Wi-Fi network A (no rule), open the modal, add A as an
      auto-connect SSID, close the modal.
- [ ] Move off A and back to A. **Expected**: the new rule fires —
      helper rereads settings.json on every SSID change, no restart
      required.

### Multi-tunnel disambiguation
- [ ] Add the same SSID to two tunnels' auto-connect lists.
- [ ] Join the SSID. **Expected**: only the lexicographically-first
      tunnel is auto-connected (matches `Action()`'s sort order in
      `internal/wifi/rules.go`).

### Negative cases
- [ ] Master toggle OFF — switching SSIDs does nothing.
- [ ] Wi-Fi off (no SSID) — nothing happens (network change detector
      handles real reconnect concerns separately).
