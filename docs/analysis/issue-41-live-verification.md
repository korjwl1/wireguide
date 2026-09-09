# Issue #41: execution verification on macOS Tahoe

Host: macOS 26.3.1, arm64. Tests started 2026-09-08.
Evidence directory: `/tmp/wireguide-issue41-live` (private local logs and snapshots).

## Continue testing on another Mac (#41)

Branch: `analysis/issue-41-macos-helper-loop`. This is a candidate fix for
[#41](https://github.com/korjwl1/wireguide/issues/41), not a confirmed resolution
of the reporter's exact failure. The private `/tmp` evidence directory is local
to the first Mac and is not included in Git; the observations below summarize
it. Build a fresh bundle on the target Mac.

With Go, Node/npm, Task, Xcode command-line tools, and the project's Wails CLI
installed, fetch this branch in a clean checkout and run:

```sh
git fetch origin
git switch analysis/issue-41-macos-helper-loop
git pull --ff-only
go test ./... -count=1
go vet ./...
WIREGUIDE_TEST_LAUNCHD=1 go test -race ./internal/elevate ./internal/gui ./internal/ipc -count=1
task package SIGN_PUBKEY=ea2dda6d25dbcbbb9a4b16077c7138fa343a0775a3e718a333c0fbae31bded36
codesign --verify --deep --strict --verbose=2 bin/wireguide.app
open bin/wireguide.app
```

The key above is the public update-verification key from the release workflow.
The native launchd tests use temporary user-domain fixtures and require a
logged-in macOS session. Close any older WireGuide GUI before launching the
candidate so observations belong to this build.

Priorities for the next live run:

1. Approve installation, confirm the GUI renders and `bin/wireguide.app/Contents/MacOS/wireguide ctl status --json`
   responds. Compare the app binary and `/Library/PrivilegedHelperTools/com.wireguide.helper`
   using `shasum -a 256` to confirm which helper was installed.
2. With no active VPN, exercise helper crash recovery and a persistent helper
   outage. A crash restarted by launchd should reconnect. A persistent outage
   should show one error banner after detection plus ten seconds, without
   repeated administrator prompts. Quit and reopen to retry setup explicitly.
3. Check cold start, cancellation, and slow password entry. Cancel must not
   trigger an automatic full repair. Time in the authorization dialog must not
   consume the subsequent readiness budget.
4. Check an explicitly disabled helper: setup should offer Open Settings and
   Retry/Quit without requesting authorization or silently enabling the job.
   Other bootstrap failures must retain their actual error and launchd state.
5. Check both fast-start failure cases: failed kickstart, and successful
   kickstart with no compatible RPC response. Either should attempt one full
   repair, then return the error if that fails.

Record macOS/build versions, the exact dialog error, helper state from
`launchctl print system/com.wireguide.helper`, and relevant lines from
`/var/log/wireguide-helper.log`. Preserve existing tunnel configurations and
record whether any VPN was active during the test. Avoid treating an ordinary
cold-start authorization request as reproduction of the failed Retry loop.

## Follow-up repairs (2026-09-08)

Re-reading the issue, including recurrence after a clean reinstall, identified
four further defects. This branch contains corrections for those paths:

1. **Repeated interactive runtime recovery.** On macOS, the health monitor
   now calls a passive RPC reconnect function. It cannot authorize an install
   or shut down a mismatched helper. After a ten-second outage following
   detection, one persistent error asks the user to reopen the app for setup.
   Passive recovery continues so launchd crash restarts still reconnect.
2. **Socket reachability mistaken for health.** Startup now requires compatible
   Ping RPC responses. Connection and handshake honor context deadlines;
   installer probes are transient and do not acquire a GUI control lease.
   Accept-and-close and accept-without-response fixtures are both rejected.
3. **Disabled state survives reinstall.** Before authorization, the installer
   checks the exact helper label in launchctl's disabled-state output. The
   actual Tahoe output uses `disabled/enabled`; both that form and `true/false`
   are covered. A native disabled user-domain fixture verifies the parser.
   The native failure dialog offers Open Settings and explicit Retry/Quit.
   Neither file replacement nor generic error 5 is treated as proof of BTM
   corruption. The app does not silently re-enable disabled services.
4. **Successful kickstart without RPC response.** Both failed kickstart and
   failed readiness now lead to at most one full repair. Failed full repair,
   canceled authorization, disabled state, or shutdown returns control to the
   user. Readiness gets 30 seconds after each authorization completes.

Regression tests cover these paths, including accepting a recovered helper
without shutting down an old one. The earlier evidence files
`socket-without-rpc-review.log` and `disabled-job-review.json` document the
pre-fix findings. The new results are in `repair-race.log`,
`repair-all-tests.log`, and `repair-vet.log`.

Starting a stopped helper still requires administrator authorization under the
GUI-bound lifetime design. This change addresses failed/repeated recovery, not
v0.4.2's once-per-install authorization behavior. Arbitrary corrupted user
configuration and the external reporter's specific BTM state have not been
reproduced; there is no claim that every possible cause of #41 is eliminated.

## Follow-up execution

The repaired app builds and passes strict signature verification. All Go tests,
vet, focused race tests (including real launchd lifecycle and disabled-state
fixtures), and Windows IPC/GUI compilation pass. The disabled dialog's
Open Settings → Retry flow passes with stubbed UI commands.

The new app was launched at 21:43:59 on 2026-09-08. The last recorded run
stopped at native administrator authentication. Installation and post-install GUI recovery for
this additional repair are **not yet verified**. Earlier passing live runs in
the matrix below used the `c26cceb5…` candidate; they must not be presented as
execution evidence for the new passive-recovery code. The planned remaining
check is to shut down the idle helper while leaving the GUI open, observe a
persistent error without repeated authorization, then reopen and recover.
Evidence: `repair-gui.log`.

## Acceptance criteria

| Scenario | What must be observed | Status |
| --- | --- | --- |
| Upgrade an existing stopped helper | Real authorization/install completes; GUI renders; installed hash matches built app; RPC works | Passed on initial candidate; helper hash matches, runs=1 |
| Startup under launchd | No process before explicit demand; one startup per install; abnormal exit restarts; clean exit stays stopped | Passed with actual generated plist; old behavior fails regression test |
| Stopped helper, identical binary and plist | Kickstart path; helper files keep their hashes and modification times | Passed; hashes and nanosecond modification times unchanged |
| GUI restart while helper survives | Same helper PID; no install/authorization path; GUI reconnects | Passed, PID 57947 reused |
| Normal GUI quit | GUI and helper exit; RPC/socket no longer available | Passed via ctl stop |
| Slow authorization | Installer takes over 35 seconds; approval leads directly to GUI, no expired-context retry | Passed with actual authorization subprocess paused for 48.9 seconds, then resumed; GUI ready after 53.4 seconds total |
| Authorization cancellation | Cancel yields readable Retry/Quit; Quit exits; Retry can recover | Passed: native Cancel shows error -128; Quit exits; Retry recovery tested below |
| Failed setup and recovery | Real install failure appears in dialog; correcting the failure allows recovery | Passed: temporarily missing disposable app source caused cp failure; restored source + native Retry installed helper and opened GUI |
| Stability after startup | Helper remains responsive past health-monitor intervals; no repeated password dialogs or replacement | Passed: root helper killed once, automatically restarted; GUI recovered; RPC responsive for the next 60 seconds |
| Existing settings and network | Tunnel configurations preserved; no tunnel connected by test; default route unchanged | Passed: config.json values and tunnel file contents unchanged; default route unchanged; no active tunnel |

## Defect found through execution

The first installation produced `runs = 2` and `last terminating signal = 15`
in launchd. `KeepAlive.SuccessfulExit=false` causes an initial launch even
with `RunAtLoad=false`; the subsequent `kickstart -k` kills that new process.
A harmless user-domain launchd probe reproduced the implicit initial launch.

Correction: `KeepAlive.AfterInitialDemand=true` gates crash supervision until
explicit demand, and installation uses `kickstart` without `-k`. A second
real launchd probe stayed stopped after bootstrap, then restarted after exit 1
and stayed stopped after exit 0. The generated production plist has a native
integration test enabled by `WIREGUIDE_TEST_LAUNCHD=1`.

The tests deliberately distinguish actual launchd/GUI behavior from shell
stubs. A scripted fixture does not establish BTM approval behavior for a
blocked third-party helper on another machine.

## Recorded observations

- Initial upgrade: old helper SHA-256 `52363dd5…` replaced by initial candidate
  `f789d3ed…`; GUI rendered and RPC responded. `runs=2` plus terminating signal
  15 exposed the redundant startup/kill cycle.
- Initial verified candidate SHA-256 `c26cceb5…`: installed helper and app binary match.
  Generated plist includes AfterInitialDemand. A fresh install has `runs=1`
  and no forced termination of a just-started helper.
- GUI-only termination/relaunch reused helper PID 57947 without spawning or
  authorization. Normal `ctl stop` terminated GUI and helper.
- Native password cancellation produced `사용자가 취소함. (-128)` in the actual
  Retry/Quit dialog; clicking Quit left no GUI process.
- The native password prompt for the missing-source test remained pending
  for about 57 seconds. Approval reported the intended `cp: ... No such file
  or directory`, not an expired setup context. The reporter screenshot in
  this session is this deliberately induced failure, not an unexplained
  failure of the final build.
- Restoring the disposable source and clicking Retry produced a live helper
  and rendered GUI. The disposable app was subsequently stopped and removed.
  The real final build was launched and reinstalled its matching helper.
- Final cold restart preserved both helper/plist hashes and modification
  times. This checks the real fast path, not just a generated command string.

## Actual helper crash recovery

With no active tunnels, SIGKILL was sent to the installed helper PID 92975
through a native administrator authorization. launchd started PID 94465.
The GUI logged `helper disconnected` followed by `connected to existing
helper` and `helper recovered` at 21:23:28, with no new spawn request.
The immediate RPC probe failed during the restart; all probes from 5.1 to
60.4 seconds succeeded with the same PID and no active tunnels.

## Checks and limits

`go test ./... -count=1` and `go vet ./...` pass. The explicitly enabled
native launchd integration test also passes under `-race` together with the
GUI lifecycle tests. Removing AfterInitialDemand makes the native regression
test fail because the helper launches before demand. The production source
was restored before the final passing run.

The installer-delay success test used SIGSTOP/SIGCONT on the actual
osascript child, not a person waiting in a password field. Native Cancel and
native Retry were exercised separately. A disabled/stale BTM approval state
on the external reporter's machine has not been reproduced. No reboot or
real VPN connection was performed in this review.

The test bundle and temporary launchd jobs are removed. The normal build at
`bin/wireguide.app` is left running with its matching installed helper; the
older app in `/Applications` was not overwritten. Local logs and private
backups remain under the evidence directory for review.

[Apple's AfterInitialDemand key](https://developer.apple.com/documentation/xpc/launch_jobkey_keepalive_afterinitialdemand)
is the policy used here; actual behavior was checked on this Mac rather than
inferred from RunAtLoad alone.
