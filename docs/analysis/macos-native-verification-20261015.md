# macOS native verification — 2026-10-15

## Scope and result

**Passed on this Mac:** the native checks below, including real utun packet
traffic, macOS resolver dispatch, PF enforcement, and system launchd crash
recovery. This advances the previous review's target-machine evidence; it
does not close all remaining platform and release checks.

Host: macOS 26.3.1 (25D2128), arm64, Ethernet primary interface.
Production source: `6f8bd4e` (production code identical to the reviewed and
three-OS CI-tested `48b5c92`). The new native test fixture compiles these
production packages directly into its test executable.

Final privileged run: `TestMacOSLiveProductionNetworking`, **PASS, 12.76 s**;
independent recovery/check runner exit **0**. Private local evidence directory:
`macos-live-evidence-20261015-verified` under the session's SSD scratch
folder. It contains the binary hash, native test/child/recovery logs and
before/after network snapshots. Private snapshots are not committed.

The installed app/helper remain v0.5.1 and were not replaced. The test uses
a separate root-owned temporary binary and uniquely named **system-domain**
launchd job. Its helper fixture calls production RPC handlers, tunnel manager,
network adapters, PF backend, desired-state restore and reconciliation loop.
It does not run the full GUI or invoke `helper.Run`'s installation/bootstrap
entry point. The remote peers are controlled userspace WireGuard responders;
the client uses real macOS utun interfaces and kernel routes.

## Native networking results

| Scenario | Observed result |
|---|---|
| Actual client tunnel traffic | Both utun clients returned IPv4 and IPv6 ICMP replies through real encrypted WireGuard UDP. Outer transport is IPv4 loopback; IPv6 is the tunnel payload. |
| Supplemental DNS | Real scutil resolver installed; `dscacheutil` resolved a unique matching name to the controlled peer's answer. Original default DNS remained separate while only the split resolver was active. |
| DNS diagnostics | Split-only, global-only and mixed checks read real `scutil --dns` and produced no false leak/error for the matching configuration. |
| DNS protection packets | Both configured resolvers answered through their tunnels. A reachable, unconfigured resolver on the same controlled VPN subnet answered before protection and was blocked after On. |
| Kill-switch enforcement | A fresh TCP connection to `1.1.1.1:80` succeeded before On, failed with KS On and succeeded after product Off. Both protected tunnels retained IPv4/IPv6 and DNS traffic. |
| External PF stop | With PF initially disabled and sole token ownership verified, actual `pfctl -d` invalidated the test's reference. The production five-second reconciliation loop re-enabled PF, and tunnel/DNS packets worked afterward. |
| Cached reconnect | Production reconnect replaced a client's transport and rebuilt protection; the sibling remained usable. The event was explicitly invoked; physical roaming was not performed. |
| Actual helper crash | Sent SIGKILL to the live helper. System launchd respawned it; production crash journals and same-boot desired state restored both clients and protected packet traffic. |
| Watchdog teardown and durable block | Injected a forced-disconnect event into the production handler. Real OS teardown preserved the sibling's packets/DNS. A second SIGKILL/respawn restored only the sibling; manual Connect cleared the blocked client's durable veto. This verifies event handling, not detection of a genuine recursive endpoint route. |
| PF coexistence | Took a second real PF enable reference. WireGuide's normal Off kept PF enabled for that owner. Explicitly releasing the second owner completed cleanup. |
| Product cleanup | Normal Off/disconnect removed both WireGuide anchors and restored the exact `scutil --dns` snapshot, per-service DNS/search preferences and original default gateway/interface before emergency recovery ran. PF enabled status also matched the original before fallback. |
| launchd lifetime | No child ran before socket demand. Clean helper Shutdown exited without automatic respawn; the temporary job was then removed. |

After the independent cleanup completed, DNS, interface-list and default-route
snapshots matched the initial snapshots **byte for byte**. PF was disabled
before and after; its elapsed-time counters naturally differ. Both test
subnets again used the normal physical default route. The installed helper
job remained stopped with its original run count. Test namespaces, rules and
resolvers were removed; generated profiles were kept outside user storage.

## Additional native desktop and launchd checks

With the explicit native opt-ins enabled under race testing:

- `TestNativeSocketActivation`: actual per-user launchd socket adoption,
  two activations and socket survival after clean exit — PASS.
- `TestLaunchdDemandLifecycle`: generated production plist's demand/crash/
  clean-exit behavior — PASS.
- `TestNativeDisabledStateParsing`: actual disabled-job state — PASS.
- `TestNativeStatusItemMenuLifecycle`: real Cocoa status item/menu, actions,
  image/badge handling and cleanup — PASS.

Ordinary helper/launchd/elevate/GUI race suites and helper vet also passed.
Opt-in privileged tests skip during ordinary CI. The new native fixture is
compiled separately and explicitly authorized before touching the network.

## Repeat the networking test

Close WireGuide and ensure no VPN is active. Native administrator
authentication is required. The runner refuses an active installed helper or
existing WireGuide PF rules and snapshots service DNS/search preferences.
It stages inputs on the internal disk because macOS authorization processes
can be denied external-volume access by TCC.

```sh
go test -c -o /tmp/wireguide-macos-live.test ./internal/helper
python3 scripts/macos_native_live_test.py /tmp/wireguide-macos-live.test /tmp/wireguide-native-evidence
```

The root supervisor bounds the test independently, removes its own launchd
job, runs production crash cleanup and restores differing service preferences.
PF releases target recorded tokens; emergency cleanup never globally stops PF.
A deliberate global PF stop occurs only in the test scenario after confirming
PF was initially disabled and the test is its sole reference holder. The
normal On/Off packet tests can briefly interrupt other network traffic.

Two initial driver failures occurred before packet verification: a missing
temporary store directory and assuming single-tunnel status had a nested
`tunnels` array. Both were corrected; snapshots confirmed cleanup. An earlier
authorization attempt hit external-volume TCC protection and performed no
network mutation. These were fixture/setup failures, not passing product
checks or application defects.

## Still open

- **Actual sleep/wake:** explicitly deferred by the user in this session.
- Remote WAN peers, full-tunnel default routes, endpoint-bypass repair/failure,
  real routing-loop detection, physical Wi-Fi/Ethernet changes and IPv6 outer
  transport. Controlled split routes do not establish those behaviors.
- Current full GUI installation/upgrade and interactive error/retry flows.
  The Cocoa fixture and system launchd helper fixture cover narrower paths.
- Native Windows WFP/crash recovery and remaining Linux resolver behavior.
- The lower-priority findings retained in
  [review disposition](claude-review-disposition.md).

No main merge or original PR closure is part of this verification.
