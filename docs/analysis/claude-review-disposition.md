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
