# Issue #42: reconnect on ping failure

Request: https://github.com/korjwl1/wireguide/issues/42

Tunnel details now contain an optional ping health panel. The feature defaults
to disabled. Configure up to five unicast IPv4/IPv6 addresses covered by that
tunnel's AllowedIPs. Hostnames, loopback, multicast and link-local targets are
rejected. Choose targets that answer ICMP through the VPN.

The default interval is 30 seconds and the failure threshold is three rounds.
The interval range is 10–300 seconds; the threshold range is 1–10. Targets run
concurrently with a three-second deadline. Any matching echo reply makes the
round successful and resets consecutive failures. All targets must fail for
the configured number of rounds before requesting reconnection of that tunnel.

The helper owns the loop, including when the GUI closes. It binds raw ICMP
sockets to the tunnel interface and source address; an unavailable interface
does not fall back to the default network. macOS uses IP_BOUND_IF, Linux uses
SO_BINDTODEVICE, and Windows uses IP_UNICAST_IF/IPV6_UNICAST_IF (with separate
IPv6 adapter index resolution). Reply address, type, identifier, sequence and
random payload must match. No hostname resolution is needed.

Monitoring has an initial interval of grace and a 60-second reconnect cooldown
that survives a new connection session. The helper checks eligibility every
five seconds, so intervals are approximate; several slow tunnels can delay a
round further. Existing reconnect backoff is preserved. Session identity and
settings are rechecked after probing under the connection-action lock so a
stale result cannot initiate a reconnect after a manual disconnect or rename.
The existing handshake-age setting remains independent.

Review follow-up: each ping-triggered retry now retains a predicate over the
settings that caused it. The helper sweeps invalid retries on its five-second
health tick even while a tunnel is disconnected, and the monitor rechecks the
predicate before teardown and before reconnecting. Disabling, changing targets,
renaming or deleting the profile expires the old retry. Wake/network/handshake
retries do not have this predicate and are left intact. An operation already
executing when settings change is subject to its existing cancellation limits;
this cannot undo a disconnect that has already happened.

The follow-up tests drive real settings persistence into the helper predicate
and monitor with a fake tunnel manager. All four changes above prevent both
disconnect and reconnect; bypassing the predicate reproduces all four failures.
Additional tests cover failed-attempt backoff, preservation of another retry
reason, and firewall restoration when settings change during teardown. These
tests and helper/reconnect/app race checks passed on macOS arm64.

Settings live in the tunnel metadata sidecar. Updating them preserves notes
and unrelated settings; rename/delete follow the existing sidecar lifecycle.
WireGuard configuration exports do not contain these application settings.

## Verification on 2026-09-10

- `go test ./... -count=1`: passed on macOS arm64.
- `go vet ./...`: passed (local SDK/linker compatibility warnings remain).
- Race tests for healthcheck, app and reconnect: passed.
- Tests cover target validation, AllowedIPs, saved settings and rename/delete,
  consecutive failures, recovery, configuration/session reset, cooldown,
  probe cancellation, reply matching and preservation/cancellation of active retries.
- `TestNativeBoundICMP` with `WIREGUIDE_TEST_ICMP=1`, elevated on this Mac:
  IPv4 and IPv6 echo over loopback passed; missing interface correctly failed.
- `task package` produced and signed a macOS app. The packaged app was launched
  and its installed helper reported ready.
- Windows amd64 cross-build passed for healthcheck/helper/app/gui/network.
- Linux amd64 cross-build passed for healthcheck/network/reconnect. Building
  the Linux helper/app from this Mac with CGO disabled is blocked by Wails'
  GTK-dependent application package; this is not a Linux runtime pass.

Follow-up [macOS execution checks](issue-42-macos-live-verification.md) now cover
actual utun/WireGuard traffic, controlled ping outages, GUI cancellation,
settings persistence, DNS/firewall restoration and native network/power events.
Native Windows/Linux tests and remote-WAN/full-tunnel checks remain separate.

## Native release checks

1. Save settings on two disposable tunnel profiles; switch profiles and restart
   the app. Verify each profile retains its own values and disabled is default.
2. Connect a controlled test VPN with a reachable target. Confirm a healthy
   target prevents reconnect, including when another target fails.
3. Drop ICMP responses at the test peer, preserving the WireGuard handshake.
   Confirm threshold-based reconnect of that tunnel only, then restore replies.
4. Keep all targets blocked across reconnect: confirm grace/cooldown and existing
   retry backoff, without a tight disconnect loop.
5. Disconnect manually, disable monitoring, edit targets, rename/delete the
   profile and stop the helper during an in-flight probe. Confirm no stale retry.
6. Repeat with IPv4/IPv6, split routes, kill switch, multiple tunnels, sleep/wake
   and network changes on native macOS, Windows and Linux.
