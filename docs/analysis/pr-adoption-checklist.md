# PR #50–#53 adoption checklist

Checked on 2026-10-15 against the PR descriptions, feature-only diffs, general
comments, reviews, inline comments, and the detailed #48/#49 issue comments.
Source heads: #50 `c06c0fe`, #51 `37e63bb`, #52 `0bb2fb7`, #53 `f1de66f`.

This records behavior, its implementation and verification, plus explicit
policy changes. Main has not received these branch changes and the original
PRs remain open. #47 RPM packaging is outside this integration.

## #50 — firewall follows connected tunnels (issue #48)

| Requested behavior | Implementation and evidence |
|---|---|
| Helper owns wanted DNS / kill-switch settings; ignore legacy client DNS list | `helper/dns_protection.go`, `kill_switch.go`, `handlers.go`; handler, desired-state and DNS intent failure tests |
| Reconcile manual connect, all disconnect paths including partial failure, automation, watchdog, restore, resume | Shared post-connect / teardown / disconnect reconciliation; `dns_protection_test.go`, `forced_disconnect_test.go`, `desired_state_test.go`; periodic live-set tests |
| Retry failed applies with backoff; skip healthy unchanged state | Separate DNS / KS journals; periodic `dnsReconcileLoop` calls both; failure, backoff, healthy-rule and lost-backend-state tests |
| Reconnect suspension, zero-tunnel blockade and every exit including panic | Successful suspend depth; final-owner resume; suspend rollback; monitor deferred resume and retry-slot cleanup; nested, explicit On/Off, failed apply/connect/suspend and panic regression tests |
| Per-resolver tunnel or physical permit; loopback exemption; ignore search domains | `helper/dns_policy.go`, `firewall/dns_rules.go`; longest-prefix, cross-tunnel, physical, Table=off, loopback and search-domain tests |
| Split / DNS-less tunnels do not trigger global DNS block; no protected tunnel means no block | `dnsProtectionNeeded`; split-only and empty-set tests |
| PF reference ownership, boot UUID, startup anchor sweep, preserve existing main rules | `pf_lease_darwin.go`, `DarwinFirewall.RecoverFromCrash`; PF lease/startup/recovery tests |
| PF ordered updates and rollback; avoid stale cached DNS on KS toggles | Serialized backend operations, prepare DNS sub-anchor before KS parent, commit model only on success, activation rollback; PF fault-injection tests |
| Linux DNS table replacement, all permits, stale cleanup, deletion failures | Atomic DNS table replacement and startup sweep; Linux rule tests and isolated nft integration from the earlier #48 work |
| Bounded graceful SIGTERM / SIGINT | `helper/signals.go`; registered before initialization, three-second cleanup deadline; subprocess signal tests |

Newly restored behavior: nested suspension, KS wanted/apply retry, panic-safe
resume, DNS requested intent after failure. Also corrected failed-suspend
transport teardown, stale permit tracking, partial permit failure dropping the
blockade, and cached DNS state masking a missing backend policy.

## #51 — split DNS

| Requested behavior | Implementation and evidence |
|---|---|
| `~domain` routes DNS; plain domains also search; no `~` retains global mode | `domain/dns.go`, config parser/validator and editor; domain and config tests |
| macOS supplemental dynamic-store keys without global networksetup/snapshot | `network/splitdns_darwin.go`; validated/bounded script golden tests; split-connect tests |
| Remove keys on disconnect/rollback/shutdown; sweep at startup/recovery | Split cleanup queue and retained journal, including interface reuse guard; `tunnel/split_dns_test.go` |
| Linux resolved DNS/domain/default-route no; revert partial setup | `splitdns_resolvectl.go`, Linux SetDNS; command and failure rollback tests |
| Validate malformed entries, server requirement and 32-domain cap | `config/validator_dns_test.go` |
| Journal DNS mode: only global DNS restores/resets system DNS | `tunnel/recovery.go`; DNS mode recovery tests including DNS-less tunnels |
| Split-aware and mixed diagnostics; detail panels and editor highlighting | `diag/dnsleak_split.go`, app/CLI calls, TunnelDetail, wireguard-lang; per-domain ownership and mixed-global-failure tests; frontend build |

Diagnostics now return an error on failed enumeration, zero resolvers or no
responding server. A mixed check cannot erase the global-check failure.
Configuration verification for supplemental resolvers is not a packet trace.

## #52 — automation and reconnect

| Requested behavior | Implementation and evidence |
|---|---|
| Negated SSID/subnet/MAC conditions in config, editor, CLI and en/ko/ja | `wifi/automation.go`, JSON storage, AutomationEditor, `ctl automation add`; evaluation, JSON and CLI tests |
| Unknown input / offline / settle holds; known empty SSID on wired uplink | Network context and EvaluateDetailed; negation tables; Windows interface detection limit below |
| Primary-interface settle fingerprint; preview peeks without resetting | `wifi/settle.go`, `helper/automation_state.go`; fake-clock, primary-only and preview-drift tests |
| Manual connect/disconnect wins until settled network identity changes | Per-tunnel latch shared by GUI/tray/CLI handlers; network identity includes SSID, iface, gateway MAC and subnet; latch/rename/offline/same-SSID tests |
| Saving rules reevaluates; held rules reevaluate after settling | Rules file watcher and settle timer; watcher and timer tests |
| ErrAlreadyConnected / ErrNotConnected tolerance, all-tunnel teardown once, only down tunnels reconnect, end when no intent remains | Helper/monitor reconnect paths; reconnect and automation-state tests; pending desired restore remains eligible |
| Wait for default route before wake/roam teardown | `prepareReconnect` wired through monitor preflight; ordering, cancellation and route-probe tests |
| Detect LAN overlap for rule-driven automatic connection | `network/lan_overlap.go`, automationConnect; prefix and automatic-connect guard tests |

## #53 — launchd socket activation (issues #41/#44)

| Requested behavior | Implementation and evidence |
|---|---|
| launchd owns private socket; RunAtLoad false; no helper until demand | Generated plist Sockets.Listeners, UID ownership/mode; plist tests and real per-user demand fixture |
| Adopt launchd FD, keep launchd socket on exit, legacy fallback | `launchd.Listeners`, helper acquireListener, IPC transport; descriptor/fallback tests and real activation fixture |
| Dormant automation until GUI seen; short GUI-less grace; active/pending wanted tunnel keeps helper alive | Helper startup gate, grace timer, desired-state integration; activation and recovery tests |
| Up-to-date install avoids authorization; repair missing/broken job; graceful legacy upgrade | Elevation and GUI lifecycle paths; slow activation/no-spawn, readiness/cancellation, legacy shutdown and repair tests |
| Quit stops recovery before shutdown so helper is not reactivated | GUI quit/recovery lifecycle; cancellation/quit tests |
| IPC 1.2 GUI presence; transient CLI start/stop/status semantics | `gui_attached` metadata, transient transport, CLI lifecycle; IPC and CLI tests |
| Owner-only RPC | Socket permissions plus existing peer UID checks; private transport and plist tests |

## Deliberate changes / exclusions

These are implemented policies, not pending ports. The earlier review contains
reproductions and compatibility reasons.

| Original behavior | Adopted policy and reason |
|---|---|
| #50 unified firewall reconciler | Retain separate OS backends and DNS lock; add full KS wanted/retry reconciliation and shared reconnect ownership. Preserves existing Windows filters and #44/#49 lifecycle. |
| #50 treat `/1` pairs like `/0` for automatic firewall policy | `/1` participates in resolver routing; retain existing `/0` auto-enable policy, matching the documented WireGuard routing distinction. |
| #51 warn and connect when split DNS is unsupported | Explicit DNS failure fails Connect, preserving the existing DNS contract. Windows split DNS remains unsupported. Linux requires working resolved integration. |
| #52 same-SSID identity, old-binary negation inversion | Include underlying network identity; store negated rule lists separately so older versions cannot execute their positive inverses. |
| #52 suppress repair for manual On / rule-owned tunnels | Preserve transport repair for wanted On; manual Off and durable watchdog blocks veto restoration. Avoids stranded active-looking tunnels after wake. |
| #52 silently omit LAN-overlapping routes and skip cached reconnects | Keep explicit manual configuration and recovery intent intact. Only rule-driven automatic connect is skipped for overlap. |
| #53 delete helper automatically after two missing-app checks | Exclude orphan self-uninstall and bundle flag: a short app update or unavailable volume must not erase the recovery executable or journals. Existing explicit uninstall remains. |
| Original release fragments | Release notes/version remain a separate main/release step; no release was cut. |

## Verification and limits

Fresh local verification during this correction:

- Full macOS `go test -race -count=1 ./...` and `go vet ./...`.
- After the final suspend-path correction: helper/reconnect/diag race suites.
- `npm run build`.
- `WIREGUIDE_TEST_LAUNCHD=1 go test -race -count=1 -run '^(TestNativeSocketActivation|TestLaunchdDemandLifecycle)$' ./internal/launchd ./internal/elevate`:
  real temporary user jobs, no root daemon or VPN configuration changes.
- The earlier six failing adversarial cases now pass; added coverage includes
  panic cleanup, failed suspension, requested DNS intent, all live KS permits,
  partial OS failure and explicit On/Off while suspended.

Native Windows/Linux verification is tracked by the branch's CI run. Existing
runtime limits remain: Windows wired/IPv6-only automation context, real
sleep/wake, PF coexistence and real mixed DNS routing require target-machine
execution. Unit tests and CI do not establish that every possible environment
is defect-free.
