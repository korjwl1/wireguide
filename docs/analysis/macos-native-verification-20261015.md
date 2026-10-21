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

## Retest after the code-quality audit

After administrator authorization, the executable was rebuilt from
`fc70480c12133e650c4eaf0171091a6b11a58fd3` using Go 1.26.9 and the macOS
12.0 CGo deployment settings. This includes the audit's canonical DNS
checkpoint changes, atomic storage, IPC lifecycle and package refactoring;
its final functional source is `ef31b4f`.

`TestMacOSLiveProductionNetworking` **passed in 12.14 s**. The independent
runner exited **0**, and `TestMacOSLiveEmergencyCleanup` also passed. All
networking scenarios in the table above ran again. The test asserted exact
per-service DNS/search restoration before emergency cleanup. The runner's
DNS, default-route and interface-list snapshots matched byte for byte, and
PF was disabled before and after. The temporary system launchd job was
absent afterward, no test helper process remained, and the installed helper
was still stopped with run count 1. A subsequent public HTTPS check returned
HTTP 200. No installed app/helper was replaced.

Private evidence: `macos-audit-evidence-20261015` under the session's SSD
scratch folder. Executable SHA-256:
`fed0ef54c7add22b76596b7e6ce7515ea8dfeeb67338a7feeb689331ce081723`.
The earlier canceled authorization request produced no test results; this
was a separate completed run with a freshly rebuilt executable.

This fixture uses one global DNS tunnel and one split DNS tunnel. The
two-global-tunnel original-baseline case has engine-level regression tests,
not a two-global-tunnel native packet test. Actual sleep/wake remains
deferred, and the other scope limits below still apply.

## Latest logic retest and PF token reuse defect

The six desktop checks were rerun from `86a06fa` under `-race` with native
opt-ins: DNS checkpoint-before-write (0.23 s), Apple sample/Go stack capture
(2.09 s), Cocoa status-item lifecycle (1.93 s), socket activation (5.49 s),
disabled-state parsing (0.01 s), and generated launchd lifecycle (6.59 s).
All passed. Hang capture tests the capture mechanism, not a real main-queue
deadlock. The original root networking matrix also passed in 11.89 s.

An additional real PF stop/start scenario then exposed an ownership defect:
after `pfctl -d`, a second owner received **the same numeric token** as the
invalidated WireGuide reference. The production loop accepted the number as
proof of ownership, and the second owner's release could stop our protection.
The narrow earlier stop/repair and coexistence cases did not detect this.

[Apple's xnu implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf_ioctl.c)
generates a token by hashing the allocated reference object's address and
frees all reference objects on DIOCSTOP. Immediate reuse is therefore possible;
the observed native log confirms it occurred on this Mac.

`f634db7` records the issuing `pfctl -E` process PID with the token and boot
UUID, and compares both PID and token in the kernel reference listing.
Reconciliation and normal/crash release use the same ownership check. Query
failure retains the journal; another owner's reused token is neither adopted
nor released. Old journals without an issuing PID cannot prove ownership and
are retired without releasing that reference. This conservative migration can
leave an old reference enabled; it does not globally stop another firewall.
The independent test supervisor uses the same identity rule for cleanup.

Focused counterexamples failed before the change for both ownership repair
and live/crash release, then passed after it. The fixed native PF scenario
also passed with an actually reused numeric token (different issuing PIDs).
That run subsequently failed in the new two-global-DNS fixture because it
mistook a connecting tunnel for a connected one; no full-run success is
claimed for it. The fixture now waits for connected state and a real interface.

The final expanded native run, whose production and test source was committed
in `f634db7`, **passed in 24.08 s**. It includes the complete original matrix,
other-owner PF restart/reacquisition, retained packet enforcement after that
owner exits, and two global-DNS tunnels across actual SIGKILL/launchd recovery.
Disconnecting the first global tunnel preserves its sibling's IPv4/IPv6 and
DNS; disconnecting the last restores exact original service DNS/search values.

Independent recovery also passed (0.02 s), runner exit 0. DNS, default-route
and interface snapshots matched byte for byte; PF returned to its initial
disabled state. No native test helper or system job remained. The installed
helper was still stopped, run count 1, and public HTTPS returned 200.

Private evidence: `macos-expanded-native-final-20261015` in SSD scratch.
Executable SHA-256:
`355842b62e0b18f705d07c64c9c17cb24abbaf9ed6d48e2e32b24fabecbc882e`.
The complete repository race suite and vet passed. An earlier full-suite run
concurrent with privileged networking hit a five-second synthetic-scutil
timeout; the fresh complete run after networking cleanup passed.

## Still open

- **Actual sleep/wake:** explicitly deferred by the user in this session.
- Remote WAN peers, full-tunnel default routes, endpoint-bypass repair/failure,
  real routing-loop detection, physical Wi-Fi/Ethernet changes and IPv6 outer
  transport. Controlled split routes do not establish those behaviors.
- Current interactive cancellation, slow authorization, failed Retry and
  BTM approval flows. A subsequent [full GUI follow-up](macos-single-instance.md)
  verified successful cold upgrade, matching installed helper, app-copy
  reservation and hidden/minimised window restoration on the current code.
- Native Windows WFP/crash recovery and remaining Linux resolver behavior.
- The lower-priority findings retained in
  [review disposition](claude-review-disposition.md).

No main merge or original PR closure is part of this verification.

## Full application verification — 2026-10-21

Host: macOS 26.4.1 (25E253), arm64, Wi-Fi, one display. Local branch
`test/macos-verify-20261021` combines main `d5a629b`, PR #55 `9c18a10`
and PR #56 `91a7692` at merge `7c64ba3`, plus the two fixes below.
Remote refs/tags were fetched; no remote branch or PR was changed.
Sleep/wake was explicitly excluded. This section supersedes the older
"Still open" entries only for the scenarios actually recorded here.

Private evidence lives in the mode-0700 local directory
`/private/tmp/wireguide-macos-verify-20261021-dokzvpbp`. It includes original
app/user/helper backups, packet-test logs and before/after OS snapshots.
Profiles, keys, network identifiers and private snapshots are not committed.
The installed old app was stopped before testing. Production builds use
the macOS 12.0 deployment target and ad-hoc signed app bundles.

### Defects found and corrected

- Connecting replaced the padded native Dock icon with an edge-to-edge
  shared PNG, making the artwork grow. The macOS bridge now draws the badge
  over the original AppKit icon and restores the default icon on disconnect.
  The strengthened native test checks logical size, rendered pixels outside
  the badge, green pixels and exact reset across 25 connect/disconnect cycles.
- A real direct update replaced the bundle but hung during application quit.
  Captured native samples and Go stacks showed Wails alpha.74 holding the
  window-map read lock while waiting synchronously for AppKit; native cleanup
  needed the same map's write lock. The custom transport keeps HTTP bindings
  and queues event delivery on the GUI thread after taking a window snapshot
  without retaining that lock. It ignores events before runtime readiness and
  after shutdown. Regression tests cover lock release and both lifecycle
  boundaries. The repeated direct update exited and automatically opened the
  downloaded official app successfully.

### Completed checks

| Scenario | Result and evidence |
|---|---|
| Privileged native networking | `TestMacOSLiveProductionNetworking` passed in 33.98 s; runner exit 0. Real utun IPv4/IPv6 payloads, split/global/mixed DNS, resolver dispatch, DNS protection, KS packets, external PF stop/repair, second-owner token coexistence, cached reconnect, SIGKILL/launchd recovery, durable forced-stop veto, two global-DNS tunnels and sibling preservation. Exact network restoration and emergency cleanup passed. `native-evidence/result.json`. |
| Remote IPv4 full tunnel | Real WAN handshake, counters, utun default forwarding and HTTPS 200. Configured DNS allowed, reachable alternate resolver blocked with protection and restored by Off. Sustained upload for 35 s at 512 KiB/s caused no false watchdog stop; disconnect completed in 0.938 s. Zero-tunnel KS blocked physical traffic, Off restored it. `runtime-remote-results.json`. |
| Rules and CLI lifecycle | Import, rename, active delete, live edits, first-match precedence, else, subnet/not-subnet, MAC normalization/not-MAC, GUI-reported actual SSID and manual overrides passed. Manual Off persisted through a 36 s observation; manual On prevailed over a disconnect rule. Active CLI delete disconnected and removed the disposable tunnel in 0.915 s. `runtime-automation-results.json`. |
| Physical outage | Wi-Fi disabled for 5 s and restored; the remote VPN recovered HTTPS in 19.94 s including the outage. `wifi-only-results.json`. |
| Endpoint bypass | With the monitor armed, deleting the owned host route produced a repaired STATIC physical bypass and working WAN traffic. `bypass-steady-results.json`. An earlier combined early route deletion/outage test instead detected recursive forwarding, stopped safely and required manual recovery; it is not counted as automatic outage recovery. `network-transition-results.json` records that initial failure. |
| Full GUI lifecycle | Minimized and hidden windows restored through another launch/app copy with the same GUI PID. GUI active-tunnel delete showed the disconnect-first warning and retained the connection. Idle operation exceeded 437 s without helper respawn/elevation loops. Window restoration and idle JSON evidence are retained. |
| Full GUI helper crash | SIGKILL during a real WAN connection with DNS protection and KS recovered traffic in 5.027 s, preserving the GUI PID and requiring no further elevation. An explicitly unloaded helper produced reopen guidance without repeated authorization. `gui-helper-crash-result.private.json`. |
| Explicit quit | Native Cmd+Q exited the GUI while connected with protection enabled; DNS/default routing returned to the stopped state. `native-quit-result.private.json`. Closing the window remains distinct from explicit Quit. |
| Authorization cancel/retry | The user canceled the actual administrator prompt; error -128 produced a Retry/Quit dialog. Clicking Retry and approving the next prompt reached the working GUI. Exactly two authorization attempts, one canceled, occurred. `authorization-cancel-success.json`, native dialog snapshot and `gui-auth-ready.log`. Earlier accidentally approved attempts are not counted as cancellation checks. |
| Direct signed update | A production-code fixture reporting 0.5.1 verified/downloaded the official 0.5.2 release, replaced the app, exited and automatically opened the new GUI. This passed after the shutdown fix; the original failing sample is retained. `direct-update-fixed-result.json`. |
| Homebrew update | The equivalent in-app Homebrew flow updated the receipt/app to 0.5.2, exited the old GUI and opened the official new app. The temporarily hidden receipt used to select the direct-update path was restored. `brew-update-result.json`. |
| Native desktop tests | Dock icon geometry/reset, Cocoa status item/menu lifecycle, hang capture, disabled launchd-state parsing, demand lifecycle, socket activation and DNS checkpoint-before-write opt-ins passed. These fixtures do not establish every hardware/UI scenario below. |
| Automated checks after fixes | Complete `go test -race -count=1 ./...` with native icon/tray opt-ins and `go vet ./...` passed. Frontend 15 tests and build passed. Production update tests passed. Windows GUI test binary cross-compilation passed; no post-fix Windows runtime result is claimed. |

### Remaining environment limits

Other macOS versions and unavailable display arrangements are context limits,
not additional release gates for the user's current-Mac verification scope.
Display selection/appearance logic was not changed in this branch; menu glyph
alpha/outline rendering was changed and tested on the available display.

- Sleep/wake remains intentionally excluded.
- No Ethernet uplink or second physical network was available: Wi-Fi/Ethernet
  roaming, a changed gateway and duplicate-subnet routers remain unverified.
- The WAN peer/underlay was IPv4. Native tunnel IPv6 payloads passed, but
  IPv6 outer transport and remote dual-stack full-tunnel WAN were unavailable.
- macOS 27, multiple displays with different wallpapers and spoken VoiceOver
  output were unavailable. Native menu/badge tests and AX connection-state
  attributes do not replace those checks.
- Actual BTM denial/approval, deliberately long authorization, and a second
  failed Retry were not reproduced. Cancellation followed by successful
  Retry and repair after job removal were exercised.
- This run does not establish new Windows or Linux runtime coverage, nor
  exhaustive visual review of every locale/theme/window size.

The Homebrew receipt remains at 0.5.2. The local patched 0.5.2 app is restored
after update/cancellation fixtures; user tunnel configuration and settings
are preserved byte for byte. Final stopped-state checks confirmed PF disabled,
both WireGuide anchors empty, exact per-service DNS/search preferences,
matching signed app/helper binaries and no temporary system launchd jobs.
No updater swap staging directory remained. The original VPN was then
reconnected with the patched app: connected state, real handshake/counters
and public HTTPS 200 were confirmed, with one GUI process. Evidence:
`final-cleanup-check.json`, `final-restored-result.json` and the private final
status snapshot. No release, push or PR merge is part of this run.

## BTM implementation comparison — 2026-10-21

Following the user's request, background approval handling was compared with
open-source implementations instead of changing this Mac's approval settings.
This is source/native API verification, not a claim that the actual System
Settings denial/reapproval UI was exercised.

- [Mullvad's legacy daemon status query](https://github.com/mullvad/mullvadvpn-app/blob/209b0d6a65b04130868be6bc955b16a91619ee7c/mullvad-daemon/src/macos_launch_daemon.rs)
  calls `SMAppService.statusForLegacyPlist(at:)` on macOS 13+, maps
  `requiresApproval` to not authorized, and distinguishes missing/unknown
  status. Its package installer still installs a conventional LaunchDaemon;
  querying this API does not require migrating service registration.
- [Pearcleaner's helper manager](https://github.com/alienator88/Pearcleaner/blob/7724df7111bff82ae243301cf701992ef05ecf19/Pearcleaner/Logic/HelperToolManager.swift)
  uses modern `SMAppService.daemon`, directs approval-required users to Login
  Items settings, and also checks actual helper responsiveness. Its
  registration/reinstallation policy is different from WireGuide's legacy
  install and is not copied wholesale.
- [Apple's legacy status API](https://developer.apple.com/documentation/servicemanagement/smappservice/statusforlegacyplist(at:))
  is specifically intended to detect user-disabled legacy helpers. The SDK
  header recommends checking at launch and after connection errors. The
  `launchctl print-disabled` override list alone is not equivalent to this
  approval status.

The comparison found one omission: WireGuide checked launchd disable
overrides but did not query the legacy BTM approval API. A read-only native
bridge now checks it before install/repair and after repair failures.
`requiresApproval` uses the existing disabled-service error, Open Settings
action and explicit Retry flow, avoiding unnecessary authorization/reinstall.
Missing, unregistered or unknown API states do not assert user denial; the
existing launchctl checks/readiness/one-repair policy still apply. macOS 12
and non-CGo builds retain the launchctl fallback. No BTM reset, automatic
enable, service registration migration or dependency was added.

The native child test first queried the actual framework (this Mac reported
Enabled), then replaced the query method only inside that disposable process
to verify requiresApproval, enabled, missing, unregistered and unknown return
values. It checks the exact plist URL and rejects empty paths without querying
the framework. It never changes the system approval database. Run with
`WIREGUIDE_TEST_BTM=1 go test ./internal/elevate -run TestNativeBackgroundApproval -v`.

The elevate/GUI race suites including this probe, their vet checks and a full
production build passed; the non-CGo macOS elevate test binary also
cross-compiled. This source-only follow-up did not replace the running app;
the original VPN connection stayed active through the review. Private
sources/test evidence and the production executable are under
`/private/tmp/wireguide-btm-review-20261021`.

## Sleep/wake follow-up and combined DNS protection defect — 2026-10-21

The user subsequently authorized real sleep/wake testing on the same macOS
26.4.1 arm64 Mac. The current signed app/helper includes the BTM follow-up.
Private evidence, original configuration/app backups and the supervised test
scripts are in `/private/tmp/wireguide-macos-sleep-20261021-pz7q8zcd`.
One-time wake events use a unique verification owner and are canceled
individually; permanent power-management settings are not changed.

The first completed plain-connection cycle recorded actual system Sleep/Wake,
an approximately 63-second scheduler gap, IOKit notification and automatic
reconnection. Completion plus eight seconds of stable HTTPS took 19.11 s
after the supervising process resumed. GUI/helper PIDs stayed unchanged.
An earlier driver advanced after transient post-wake traffic before the
scheduled reconnect finished; its next setting transition was not a valid
steady-state check. A separate protected attempt immediately returned from
DarkWake on HID input and is not counted as a completed sleep test.

A later actual protected sleep cycle recovered VPN traffic but exposed a
DNS enforcement defect. This was reproduced independently while awake:
DNS-only protection blocked the reachable alternate resolver, but enabling
the kill switch allowed it. The main PF anchor put `pass quick on utunX all`
before its DNS sub-anchor, so the terminal permit bypassed the DNS policy.
The loaded DNS rule text and enabled flags could therefore look correct
while packets escaped the intended resolver restriction. This observation
does not establish cleartext DNS escaping the encrypted tunnel; it establishes
that an unconfigured resolver was reachable through the VPN despite protection.

The DNS sub-anchor now runs before tunnel-wide permits. Endpoint transport,
DHCP/loopback exceptions and the final physical-network blockade remain in
place. The ordering regression test failed before the fix and passes after
it. The native packet matrix now checks the unconfigured but reachable
resolver with both protections active, after PF repair, cached reconnect and
actual SIGKILL recovery; the older matrix checked that negative case only
before enabling the kill switch.

Firewall/helper/reconnect race tests and vet passed, and the corrected
production bundle was built, signed and installed with a matching helper.
The expanded privileged packet matrix passed in **34.71 s**, independent
runner exit **0**, with exact DNS/service/interface restoration and PF
ownership cleanup. Evidence: `pf-fix-native-verified/native-test.log` and
`result.json`. Awake WAN verification also confirmed that the corrected
combined protections allow the configured resolver and block the alternate.
The setup attempts denied Documents-folder access or started before the
installed helper finished exiting did not run the native matrix and are
not counted as product failures or successful test runs.

### Completed sleep/wake results

All three scenarios below completed with real macOS Sleep/FullWake records
and IOKit notifications. The plain run used the BTM-follow-up build; the
protected and manual-Off runs used the corrected PF build, committed as
`5467e6c`. The plain path's protections were Off and its code was unchanged
by that PF correction.

| Scenario | OS evidence and observed result |
|---|---|
| Connected, original protection settings Off | 65 s of actual Sleep. VPN reconnected automatically; completion plus 8 s of stable HTTPS took 19.11 s after the supervisor resumed. GUI/helper PIDs unchanged. |
| Connected, DNS protection and KS On | 65 s of actual Sleep, then FullWake. Automatic VPN recovery plus 8 s stable HTTPS was confirmed 25.54 s after the recorded FullWake. Configured DNS answered; reachable unconfigured DNS remained blocked; the KS and DNS anchors were restored. Same GUI/helper, no wake-time elevation or hang report. |
| Manually disconnected, KS still On | Entered DarkWake, then 51 s of actual Sleep; scheduled wake went through DarkWake to FullWake. The tunnel stayed disconnected for the full 35 s observation, and a fresh physical-network HTTP connection remained blocked. Same GUI/helper and IOKit notification. |

An intermediate driver rejected a valid maintenance-wake cycle because it
required a continuous 20-second process scheduling gap. The power log showed
actual Sleep, DarkWake, further Sleep and scheduled FullWake. The corrected
driver waits through the scheduled wake and checks the actual Sleep and
FullWake records, rather than treating a maintenance wake as a failed sleep
test. This changes the fixture's power-state detection, not product behavior.
The final protected run independently obtained an uninterrupted 65 s Sleep;
the manual-Off run verified the maintenance-wake path as well.

Final combined evidence: **25 checks passed**, `results.json`; all original
settings/profile/power-settings comparisons passed, `restoration.json`.
The original VPN is reconnected with a fresh handshake and HTTPS 200.
WireGuide PF anchors are empty with the original protections Off, temporary
wake events are absent, signed app/helper hashes match, and one GUI remains.
After these cycles, native accessibility actions opened and closed Settings
successfully (`gui-after-wake-result.json`), confirming interactive UI response.
The latest BTM and PF fixes are installed in the running app/helper.

This completes the requested short sleep/wake scenarios on this Mac. It
does not establish overnight standby/hibernation, physical lid-close
behavior or the historical macOS 27 hang's exact cause.
