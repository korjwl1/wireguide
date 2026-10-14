# Review of split DNS, automation and launchd activation

Review date: 2026-10-14. Current branch: `fix/issue-49-watchdog-teardown`
at `6bd54cd`. The three proposals fit useful parts of WireGuide's purpose,
but none should be merged unchanged. All include PR #50, whose implementation
differs from the DNS/firewall work already on this branch.

## Decision summary

| Proposal | Product fit | Adoption decision |
|---|---|---|
| [PR #51](https://github.com/korjwl1/wireguide/pull/51), split DNS | Useful for work VPNs; config-driven and mostly invisible to everyday users | Port after defining protection scope and unsupported-platform behavior. Extract DNS recovery and JSON field fixes separately. |
| [PR #52](https://github.com/korjwl1/wireguide/pull/52), automation | Negated conditions and stable network evaluation extend the existing automation model | Split reconnect fixes from new policy. Correct manual override identity and preserve transport recovery before adopting latches. |
| [PR #53](https://github.com/korjwl1/wireguide/pull/53), socket activation | Strong fit for on-demand privilege separation and fewer repeated prompts | Adopt activation through the current helper lifecycle. Redesign automatic self-uninstall and preserve desired-state recovery. |

The README's criteria are the basis: a small UI, safe failure behavior,
privilege separation and automatic recovery. A password prompt on every cold
start is an implementation choice, not a product identity requirement.
Socket activation can retain one authorized installation, an unprivileged GUI,
an idle root helper that exits, and local owner-only RPC access. Apple's
[launchd guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
describes that on-demand lifecycle.

## Versions and merge conflicts

The review uses these immutable heads:

| PR | Head | Feature-only delta from PR #50 | Conflicted files against current HEAD |
|---|---|---|---:|
| #51 | `37e63bb2050da057a1014b3c23d7873fc54b5e6f` | 34 files | 8 |
| #52 | `0bb2fb78a1b733ae6d7b07b5abd4ce0de97c6cb6` | 37 files | 7 |
| #53 | `f1de66f286ba7c06752e3139cd0213e15ffe19f8` | 40 files | 11 |

Shared base: PR #50 at `c06c0fe7730eac1f424f2f7794f2e543de7fb8be`,
based on main `8ecdfd41e8852a1e6a81d3396aa1aa75bcd53d3b`.
PR descriptions, general comments, reviews and inline comments were refreshed;
the three PRs have no comments or submitted reviews at these heads.

`git merge-tree --write-tree --name-only HEAD refs/review/pr-N` found:

- #51: `firewall/darwin.go`, `firewall/linux.go`, `helper/handlers.go`,
  `helper/helper.go`, `helper/wifi_rules.go`, `network/interface.go`,
  `reconnect/monitor.go`, `reconnect/monitor_test.go` under `internal/`.
- #52: the same set except `network/interface.go`.
- #53: the #52 set plus `elevate/spawn_darwin_test.go`,
  `gui/helper_lifecycle.go`, and root `main.go`.

Feature-only patches also fail `git apply --check`: #51 conflicts with the
network interface definitions; #52 depends on the unimported
`firewall_reconcile.go` and overlaps helper/reconnect code; #53 overlaps
helper startup, elevation, GUI lifecycle and the helper entry point.

Pairwise merges of the proposed heads produce no textual conflicts for
#51+#52 or #52+#53, and only a changelog conflict for #51+#53. This does not
establish behavioral compatibility with each other or this branch.

## PR 51 findings

### P1 Mixed global and split DNS can block a configured resolver

In [desiredDNSPermits](https://github.com/bitworks-io/wireguide/blob/37e63bb2050da057a1014b3c23d7873fc54b5e6f/internal/helper/firewall_reconcile.go#L57),
a split-DNS resolver outside its own tunnel's AllowedIPs gets no permit when
another tunnel activates the global DNS block. Reproduction: a global-DNS
tunnel uses `9.9.9.9`; another tunnel uses `1.1.1.1, ~corp.example` with only
`172.16.0.0/12` routed. The permit list contains `9.9.9.9` and omits `1.1.1.1`.
That address is consequently caught by the port-53 drop rule.

The problem is inherited from the shared #50 permit calculation and becomes
relevant to #51's supported split-DNS configuration. Retain our cross-tunnel
longest-prefix calculation when porting, including physical resolver permits.
Also make split-only protection explicit: our current wanted-state logic
would block ordinary system resolvers unless it is adapted for domain routing.

### P1 Unsupported split DNS is reported as a connected tunnel

[connectPhases](https://github.com/bitworks-io/wireguide/blob/37e63bb2050da057a1014b3c23d7873fc54b5e6f/internal/tunnel/connect_phases.go#L257)
ignores `ErrSplitDNSUnsupported`. Windows always returns that sentinel; Linux
does so when resolvectl is missing, and also for operational failures during
setup. Only log warnings expose the lost DNS behavior. The existing
`TestSplitUnsupportedIsNonFatal` explicitly expects success.

This changes the existing contract that explicitly configured DNS failures
fail Connect. A nontechnical user can see Connected while internal names fail
or use the system resolver. Require supported-platform validation, or an
explicit degraded state with a user-visible decision. An execution failure
must be distinguished from a genuinely unsupported backend.

### P2 Split DNS diagnostics can report an incorrect configuration as safe

[ExpectedDNSForTunnels and evaluateSplitDNS](https://github.com/bitworks-io/wireguide/blob/37e63bb2050da057a1014b3c23d7873fc54b5e6f/internal/diag/dnsleak_split.go#L61)
flatten domain-to-server ownership into a union. With A's server `10.1.0.53`
for `a.example` and B's `10.2.0.53` for `b.example`, the check passes when
both domains use B's server. Preserve each tunnel's domain/server mapping.

On Linux and Windows, `runSplitDNSCheck` returns `SplitMode=true`,
`Leaked=false` and no error without checking the resolver. The GUI renders
that result with its safe style; the CLI prints OK. Return an explicit
unverified/unsupported result, and distinguish resolver configuration checks
from an actual DNS leakage test.

### P1 Failed supplemental resolver removal is forgotten

Darwin `RestoreDNS` logs a `removeSplitDNS` failure and returns success when
`dnsActive` is false, which is the normal split-DNS state. The disconnect and
rollback paths also log removal failures and clear the tunnel journal anyway.
An injected dynamic-store error reproduces the false-success return without
touching the host DNS. Stale supplemental resolvers can remain pointed at a
dead tunnel until a later helper startup sweeps them. Return cleanup errors
and retain a retryable per-tunnel cleanup record until the keys are gone.

### Parts to keep and integration requirements

- The DNS mode in the recovery journal prevents DNS-less tunnels from
  resetting user-configured DNS after a crash. That correction is independent
  of split DNS and applies to a real gap in the current recovery path.
- Lower-case JSON field access in TunnelDetail fixes existing `Peers` /
  `AllowedIPs` / `Interface.DNS` access against lower-case serialized fields.
- The macOS script builder validates tokens, bounds input lines and reads back
  the dynamic-store key. It is a useful starting point; key existence alone
  does not prove the system resolver is using it.
- Keep global DNS snapshots, per-tunnel supplemental resolvers, firewall
  permits and diagnostic expectations as distinct state. Exercise both
  connect orders, both disconnect orders, reconnect and crash restore.
- Linux routing-only domains fit the
  [systemd-resolved routing model](https://github.com/systemd/systemd/blob/main/man/systemd-resolved.service.xml).
  The feature requires a working resolved integration; a resolv.conf fallback
  cannot preserve domain routing. Windows needs a deliberate support policy.

## PR 52 findings

### P1 Manual intent and automation ownership suppress transport repair

[legacyTeardownWith](https://github.com/bitworks-io/wireguide/blob/0bb2fb78a1b733ae6d7b07b5abd4ce0de97c6cb6/internal/helper/helper.go#L730)
skips every latched or rule-governed connected tunnel. The subsequent legacy
reconnect also skips connected tunnels; automation does nothing for an
already-active connect rule, and skips manual latches outright.

A manual Connect records a latch even though the requested intent is On.
If that tunnel needs transport recreation after wake, this policy removes its
repair path. A test confirms that the teardown callback is never invoked for
this case. This demonstrates the policy difference, not a reproduced physical
sleep failure on every network. Separate desired On/Off from transport health:
manual Off must stay down, while manual On can still recover.

### P2 A network change with the same SSID never releases the manual override

[networkIdentity](https://github.com/bitworks-io/wireguide/blob/0bb2fb78a1b733ae6d7b07b5abd4ce0de97c6cb6/internal/helper/automation_state.go#L126)
uses only the SSID whenever it is nonempty. A different gateway MAC and subnet
under `SharedSSID` restart settling but leave the identity unchanged. The
manual override stays in effect indefinitely, including against gateway-MAC
and subnet automation rules. A deterministic clock/probe test reproduces it.
Use a stable network identity that includes the fields relevant to the rules,
while excluding transient IP/privacy-address churn.

### P2 LAN overlap silently changes the imported route configuration

[Darwin AddRoutes](https://github.com/bitworks-io/wireguide/blob/0bb2fb78a1b733ae6d7b07b5abd4ce0de97c6cb6/internal/network/darwin.go#L182)
omits a configured route when it contains a local physical address. Connect
can still succeed with fewer routes than the imported config requested.
Automation/reconnect instead skip the entire tunnel. Linux and Windows do
not have the same route omission behavior.

LAN conflict detection is useful, but changing routes silently conflicts with
predictable config import. Report the conflict clearly and define a consistent
policy for manual Connect, automation and recovery, including multi-peer
tunnels where other prefixes are usable.

### P2 Negated rules can invert after downgrade

The new `negate` boolean is ignored by existing binaries, leaving the same
known condition type and action. An intended "connect when not at the office"
rule becomes "connect at the office" after downgrade. The PR acknowledges
this in documentation, but a documentation warning cannot preserve the saved
rule's meaning. Prefer a representation that old binaries reject or treat as
unknown, plus an explicit migration/downgrade policy.

### Parts to keep and integration requirements

- Treating ErrNotConnected as an already-completed teardown prevents a failed
  reconnect from getting stuck before Connect on the next attempt.
- ErrAlreadyConnected tolerance and all-tunnel teardown overlap fixes already
  present here. Preserve our session checks and successful survivors.
- Rules-change reevaluation, unknown-input holds and a settle timer fit the
  existing automation model. Keep the editor optional and show a useful reason
  when a manual override or unknown network is holding a rule.
- Preserve #49's durable watchdog block separately from a temporary manual
  override. Network changes must never clear the watchdog block.
- Preserve #44's `pendingDesired` and same-boot crash restore. The proposal's
  empty-cache cancellation must not cancel a still-wanted pending restore.
- Windows leaves the primary interface unknown and treats an empty SSID as
  undecidable; IPv6-only/default-route detection also needs execution coverage.
  Do not promise identical negated-SSID behavior on Ethernet across platforms.

## PR 53 findings

### P1 Network recovery failure cannot veto destructive self-uninstall

[handleOrphanedInstall](https://github.com/bitworks-io/wireguide/blob/f1de66f286ba7c06752e3139cd0213e15ffe19f8/internal/helper/orphan.go#L95)
calls a `func()` recovery callback and then removes the daemon plist, executable
and socket. The callback exposes no success/error result; its production
recovery operations log failures and continue. A mock failure therefore cannot
stop removal. Persistent PF/DNS state could be left with its repair binary
deleted. Preserve the install and journal when recovery fails, and surface an
error through the lifecycle API.

### P2 A temporary app replacement can be mistaken for uninstall

The app is considered removed after two failed existence checks two seconds
apart. A synthetic three-second app replacement triggers self-uninstall before
the replacement appears. The same risk applies to a temporarily unavailable
app volume and Homebrew paths that resolve through versioned directories.
This is a decision-logic reproduction, not a destructive system-install test.
Use explicit uninstall handling or durable evidence of removal; a two-second
absence is insufficient authority to remove the installed helper.

### Parts to keep and integration requirements

- Launchd owns the listening socket; adopting its descriptor and keeping
  `SetUnlinkOnClose(false)` is the correct ownership model.
- Owner/mode restrictions and peer-credential checks retain local privilege
  separation. Socket activation permits any process under the installing UID
  to start the helper without another prompt; that change should be explicit.
  A non-transient connection is a lifecycle signal, not GUI authentication.
- GUI-attached status, transient CLI probes and cancellation before Quit are
  needed because a successful connect can now start an otherwise idle helper.
- Port into the current startup path without dropping `--restore-desired`,
  watchdog blocks, bounded IPC writes, signal handling, native tray lifecycle
  or hang diagnostics. Prefer an options struct over incompatible additions
  to Run's positional arguments.
- Update the actual current recovery-journal path in packaging; this branch
  uses `pf-was-enabled` JSON, while the proposed uninstall adds `pf-token`.
- Verify migration from the legacy socket, plist replacement, owner UID,
  reboot, idle exit, crash restore, update and uninstall as one lifecycle.

## Verification and limits

Each original PR head passed its related package race tests on macOS 26.3.1:

| PR | Packages |
|---|---|
| #51 | config, domain, network, tunnel, diag, helper, firewall |
| #52 | wifi, helper, network, reconnect, ipc |
| #53 | launchd, elevate, gui, helper, ipc, cli |

The changed core packages also cross-build for Windows amd64 and Linux arm64.
These are package builds, not full Linux desktop builds or native Windows tests.

The new review cases below fail against the corresponding PR heads. They are
counterexamples to the stated behavior or to WireGuide's current contract;
they are not tests added to the current runtime branch:

| PR | Case | Observed result |
|---|---|---|
| #51 | Mixed split physical resolver | Resolver absent from permits |
| #51 | Per-domain diagnostic ownership | Wrong tunnel's DNS accepted |
| #51 | Supplemental resolver removal fails | RestoreDNS still reports success |
| #52 | Same SSID, different gateway/subnet | Manual override retained |
| #52 | Manual On during wake recovery | Transport teardown callback skipped |
| #53 | Recovery failure during self-uninstall | Removal cannot be vetoed |
| #53 | Three-second temporary app swap | Self-uninstall selected after two seconds |

Reproducible test patches: [#51](pr-51-review-cases.patch),
[#52](pr-52-review-cases.patch), [#53](pr-53-review-cases.patch).
In a separate checkout at each pinned PR head, apply its patch and run
`go test -race -run '^TestReview' ./internal/helper`; include
`./internal/diag ./internal/network` for #51. These tests deliberately fail
until the reviewed behavior is corrected.

PR #53's real per-user launchd socket fixture passed with a race-enabled test
executable under `/tmp`: it stayed idle before contact, started for a connect,
started again after clean exit, and retained the launchd-owned socket. The
first execution from the external SSD build directory timed out; relocating
the same fixture isolated that execution-path limitation. No system-domain
helper was replaced, and root-owned socket permissions were not exercised.

Native supplemental DNS routing, systemd-resolved integration, Windows DNS,
physical sleep/roaming and destructive uninstall remain target-machine gates.
The original review only supplied documentation and repro patches. Integration
status is recorded below; local code changes do not install the system helper.

## Suggested integration sequence

1. Extract #51's DNS-less recovery correction and JSON field fixes, and the
   remaining #52 retry/rules-change fixes into focused issue-linked commits.
2. Add #53's socket adoption and installation migration while retaining the
   current recovery and shutdown paths. Keep automatic self-uninstall out
   until its failure and update semantics are corrected.
3. Add split DNS with per-domain diagnostics and explicit platform support;
   keep current global DNS behavior for configs without routing domains.
4. Add negated automation and manual overrides after fixing identity,
   downgrade handling and the distinction between user intent and repair.

## Integration following adversarial reassessment

All three features are suitable for integration with the corrections above.
The wake counterexample establishes a change to recovery policy, not a measured
physical sleep failure. Manual On must still allow transport repair.

### Split DNS (#51)

Integrated with per-domain resolver ownership, explicit unsupported-platform
errors, mixed-tunnel firewall permits, and retained/retried cleanup journals.
Split-only connections preserve ordinary system DNS. Diagnostics distinguish
configuration checks from packet leak tests and report unavailable verification.
Fresh race tests passed for helper, network, tunnel and diagnostics; vet, frontend
build and Windows core build passed. Linux arm64 resolvectl command/rollback
fixtures passed in an isolated container. Native resolver routing still needs
target-machine validation.

### Automation (#52)

Integrated negated predicates, settle tracking, rule-edit detection, preview
provenance and session manual overrides. Identity includes the gateway and
subnets even with an unchanged SSID. Entire lists containing negation use a
separate JSON map so old engines cannot run inverse conditions or fallbacks.
Manual On continues to permit transport recovery, while manual Off vetoes it.
Wake retries do not bounce siblings already restored after the initial teardown.
Automatic connects skip LAN conflicts; manual routes are never silently removed.
Fresh helper, reconnect, wifi, storage and network race tests passed, including
the corrected counterexamples. Frontend build, vet and Windows core build passed.
Physical roaming and sleep remain target-machine checks.

### Socket activation (#53)

Integrated launchd descriptor adoption, private socket ownership, installation
and legacy socket migration, longer activation contact budgets, CLI GUI-presence
checks, dormant automation before GUI attachment and cancellation at quit.
The existing bounded signals, IPC write cancellation, durable watchdog blocks,
macOS native tray and desired-state recovery remain in place. Automatic orphan
self-uninstall is excluded: transient app replacement must not erase the only
recovery binary. Explicit uninstall metadata includes the new socket and actual
PF journal path.

Fresh full-repository race tests and vet passed. Windows amd64 and Linux arm64
core builds passed. Real per-user launchd fixtures passed for generated plist
demand/crash behavior and descriptor adoption across clean exits. No system
helper was replaced. Root-owned system-domain migration, reboot and target
network coexistence remain native release gates.
