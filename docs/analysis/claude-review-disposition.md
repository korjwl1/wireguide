# Disposition of Claude's integration review

Source: [independent review of 68fdca0](claude-integration-review-20261015.md).
The old three-OS CI result did not establish feature completeness. The initial
review and backend proposal were read and checked before incorporation; Codex
also identified and requested correction of a new Windows transaction flaw in
the first backend proposal. The revised implementation commits KS activation
and DNS narrowing together, with failure leaving previous tracked state intact.

## High and Medium

| ID | Correction / evidence |
|---|---|
| H-1 | PF running-state query even with a cached lease; invalid-token release; periodic enforcement repair. PF kernel model tests simulate external disable, dead-token recovery, query failure and other owners. No live host PF was changed. |
| H-2 | Both timer arming and fire-time checks include cached wanted transports and pending restore. `TestWantedTransportBackoffKeepsHelperAlive`, `TestIdleTimerRechecksNewWantedTransport`. |
| H-3 | Saved DNS intent is restored before monitor/background workers start, without installing rules before a protected tunnel exists. `TestStartupRestoresDNSIntentBeforeHeadlessConnect`. |
| M-1 | `Manager.ConnectedInterfaces` reads lifecycle/engine state without UAPI telemetry. All firewall decisions and restore-active checks use that snapshot; stats remain separate. `TestFirewallSnapshotSurvivesUnavailableTelemetry`. |
| M-2 | Legacy reconnect iteration holds connectMu in a function with deferred unlock. `TestLegacyReconnectPanicReleasesConnectLock`, plus existing monitor panic/resume tests. |
| M-3 | Signal grace reserves its final third for bounded parallel firewall/DNS fallback, published before startup recovery. `TestSignalDeadlineAttemptsFallback`, plus native signal subprocess tests. Fallback is best-effort and cannot guarantee that a hung OS call completes; journals remain required. |
| M-4 | Kill-switch mode omits unpinned DNS permits while retaining the wanted permit model for KS Off. macOS renderer/toggle tests; Windows narrows DNS in the SAME KS transaction, tested with mocked native WFP APIs. |
| M-5 | Additive IPC 1.3 `wanted_tunnels`; CLI status/disconnect/stop treat pending/backoff as work while ctl start still requires a GUI. `TestPendingIntentCountsAsWorkButNotAsGUI`, `TestStopCancelsHeadlessPendingRestoreOverIPC`, helper Ping test. |
| M-6 | One macOS resolver snapshot; only default blocks enter global probes, only global servers own default-resolver expectations. Split domains retain separate ownership. Leak and incomplete-check results both render. Mixed DNS regression tests cover shared LAN/supplemental IP and simultaneous leak/error. |
| M-7 | Settled positive gateway/MAC/subnet evidence can establish a move even with an unknown SSID, including Windows wired probe shape. `TestReview52_WindowsWiredLatchNeverClears` now expects the network-B rule to act. |
| M-8 | Missing ARP/SSID is not positive change evidence. IPv4 network overlap survives IPv6 churn; positive MAC/SSID/underlay change still releases the latch. Subnet-churn and gateway disappearance/recovery tests. |
| M-9 | Removed false "existing native uninstall" claim. README provides explicit shutdown + manual helper removal and verified Homebrew zap instructions. Automatic self-deletion remains excluded; a native GUI/CLI uninstall feature is not claimed. |
| M-10 | WFP begin/body/delete/commit failures preserve DNS IDs, active flags and old model; only a successful commit changes them. Already-absent filter IDs are idempotent. Transaction seam tests and Windows DNS filter tests cover retry and abort. |

## Low

| ID | Correction / policy |
|---|---|
| L-1 | PF main-rule marker recognizes a filter `anchor` line, not scrub/nat/rdr prefixes. Query failure remains an explicit retryable error. |
| L-2 | Recovery of automatically owned intent also checks LAN overlap; manual On still keeps its explicit route policy. |
| L-3 | Validator checks combined match/search count and platform command byte budget; overlong DNS configuration fails before network changes. |
| L-4 | Save an inert private `config.json.automation-v2-backup` that old rewrites and unrelated post-upgrade saves cannot erase. Never auto-execute backup rules; explicit recovery is documented. Storage downgrade-roundtrip tests. |
| L-5 | Leak and incomplete split verification are retained and both shown in CLI/GUI. |
| L-6 | Legacy retries that no longer perform teardown do not suspend the firewall again. |
| L-7 | Windows emits an explicit warning when global search domains cannot be applied. |
| L-8 | Windows validates split-DNS capability before engine creation or network changes. Portable import remains available; en/ko/ja detail text states platform support. |
| L-9 | Same-boot desired recovery is intentionally independent of new automation's GUI-seen gate. DESIGN now states both policies explicitly. |
| L-10 | Failed supplemental cleanup retains its journal and retries with bounded exponential backoff; interface reuse still requires successful cleanup immediately. |

## Follow-up review of f0ead69

The [second independent review](claude-followup-review-20261015.md) reproduced
five remaining Medium findings. The earlier table describes the initial
corrections and must be read together with these additional corrections.

| ID | Additional correction / regression evidence |
|---|---|
| N-1 | Interface changes alone do not release manual Off. Known latch evidence remains fixed; missing ARP cannot import another router's MAC. Unknown latches may adopt their first known network once. `manual_latch_scenarios_test.go` covers docking, A→B→A, another VPN owning the default route, and retained Windows wired-change detection. Indistinguishable networks conservatively retain Off. |
| N-2 | Loaded user DNS settings and live DNS/KS intent take priority over an older crash journal. A recovered full tunnel preserves DNS Off; a new full-tunnel connect retains the previous automatic-protection policy. `recovery_intent_regression_test.go` covers config Off, a live update after the journal snapshot, KS Off, and recovery versus new-connect behavior. |
| N-3 | An occupied idle timer resets for a future check. Connect rollback, pending withdrawal and missing-config drop start an idle window. Startup restore owns a lifetime lease through pending registration. Tests prove both survival during work and actual server shutdown after work is withdrawn. |
| N-4 | A pending-only named disconnect succeeds; unknown tunnels still error. CLI text and JSON include waiting tunnels alongside active ones. The old disconnect test now asserts its error instead of discarding it; `TestStatusShowsPendingAlongsideActive` uses real IPC. |
| N-5 | All macOS global DNS checks share the same default-resolver selector, with scoped flags recognized. Global-only and mixed tests use identical resolver fixtures and probe sets, and both retain real default-leak detection. |

Baseline copies reproduced the DNS/KS override, idle-lifetime and CLI failures;
the corrected integrated tests are rerun before commit. The first review and
follow-up review remain historical records, not claims about the final head.

### Remaining follow-up findings

The second review also records lower-priority and inherited limitations. They
are not represented as fixed by the N-1–N-5 changes:

- LAN overlap skips lack a dedicated event; auto ownership is not persisted
  across helper restart (N-6).
- Windows platform rejection can occur after temporary KS suspension (P-1).
- Signal fallback is best-effort; its normal cleanup budget may expire (P-2).
- Scoped resolver badges, IPv6 zone parsing and Linux systemd-resolved stub
  attribution still need diagnostic improvements (D-1/D-2).
- Backup error/replacement behavior and GUI visibility remain limited (L4-x).
- PF live token membership, repair backoff and the periodic wiring test gap
  remain B-6/B-7/B-5/B-1; a cached lease with PF running is not independently
  proven to be a live reference.
- Windows pinned DNS permits do not constrain LUID (B-8), and existing tunnel
  permit/endpoint filter removal paths may forget failed deletes (B-9).
- Old IPC 1.2 clients cannot observe new headless pending intent (C-1).

P-3's startup restore lifetime gap is covered by the added restore lease and
`TestRecovery_StartupRestoreOwnsLifetimeBeforePendingRegistration`. Native
packet-path and OS lifecycle validation below remains separate from CI.

## Final targeted review of 6dcc6d5

The [targeted review](claude-final-review-20261015.md) reproduced two
regressions in the N corrections and one remaining settings contract gap.
They were corrected with the reproductions moved into repository tests:

| ID | Correction / evidence |
|---|---|
| F-1 | A default DNS false no longer sets the automatic-DNS Off latch. Explicit Off is stored separately as `dns_auto_off` in the crash journal. Live updates and new full connects veto stale replay; a new full connect also persists clearing that latch. Tests cover Windows auto protection, journal Off, live On, and new-connect versus snapshotted Off. |
| F-2 | A completely empty unknown manual latch adopts its first settled positive evidence even when SSID never becomes available. Later MAC/subnet moves release it. Tests cover offline Windows wired and permission-denied Wi-Fi; partial known evidence remains conservative for A→B→A. |
| F-3 | Only firewall keys actually present in a readable config are authoritative. Missing files or missing keys retain journal fallback. Config KS On is enforced before restore connect; config KS Off vetoes journal On. `firewall_settings_recovery_test.go` covers all directions. |
| D3 | Only appended pending rows say waiting to reconnect; active transitions say connecting. The real IPC status test covers text and JSON with an active transition and a pending sibling. |

The earlier CI success at 6dcc6d5 did not cover these scenarios. Its report
and findings remain preserved as historical evidence, not a final pass claim.

## Verification limits

Local full race suite, vet and frontend build are rerun on the integrated
changes, followed by native three-OS CI. Tests through an OS execution seam
prove transition/error handling, not actual packet paths. Real sleep/wake,
PF coexistence/token outputs, mixed DNS packets, systemd-resolved and Windows
WFP kernel failure injection remain target-machine verification. The same-
user socket activation capability is an accepted design tradeoff; deleting
only the app does not uninstall the helper. GUI single-instance reservation
does not prove asynchronous helper teardown has finished.

No original PR is closed and no main merge is performed by this follow-up.
