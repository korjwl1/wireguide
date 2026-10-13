# Issue #44: sleep/wake disconnect, tunnel loss after helper restart

Report: [#44 "Hard hang after sleep/wake"](https://github.com/korjwl1/wireguide/issues/44)
(v0.5.2, macOS 27 Golden Gate / macOS 26, Apple M3).
Branch: `fix/issue-44-tunnel-restore`. Analysis date: 2026-09-21.

## Reported symptoms

1. **P1 — wake disconnect**: every lid-open leaves the VPN disconnected;
   manual reconnect required. Expected: a tunnel connected before sleep is
   re-established on wake.
2. **P2 — hard hang**: after travelling, opening the Mac left the GUI
   unresponsive (beachball ~2 min), force-quit produced an Apple crash
   report. Logs were wiped with the app.
3. **P3 — lost logs** (consequence of P2).

Diagnostic questions were posted on the issue (status after wake, admin
dialog at wake, macOS 26 vs 27, health-check setting, and the crash report's
Thread 0 backtrace). Answers pending at the time of this writing.

## What 0.5.2 already covered

- Wake- and network-change-triggered reconnect is **built in and default-on**
  since v0.1.x (`7a750b8`); it is not part of the opt-in per-tunnel ping
  health checks that 0.5.2 added under #42.
- The trigger path: sleep detector (IOKit + wall-clock fallback, works for
  root LaunchDaemons) → `Monitor.triggerLoop` → all-tunnels
  Disconnect/reconnect from the helper's in-memory `activeCfgs` cache.
- 0.5.2 additionally serialized monitor start/stop (`28dcf0f`), cancelled
  stale retries, and added unresponsive-helper detection.

## Root cause found by code review (P1): helper restart loses everything

The tunnel device (utun/wintun + wireguard-go) lives **inside the helper
process**. If the helper dies — crash during sleep, `kill -9`, upgrade
`ForceShutdown` — every tunnel dies with it. After launchd restarts the
helper, **no recovery source could bring the tunnels back**:

| source | state after helper restart |
|---|---|
| `activeCfgs` (in-memory config cache) | empty — only populated by Connect |
| crash journal (`internal/tunnel/recovery.go`) | restores *system* state only (DNS, firewall, routes) — never re-establishes tunnels |
| wake/network triggers (`Monitor.triggerLoop`) | guard requires `IsConnected() \|\| ActiveTunnel() != ""` → skipped, manager is empty |
| GUI health monitor (`helper_lifecycle.go`) | reconnects the IPC socket silently; never re-issues Connects |

Net effect: "woke up, app shows disconnected, manual reconnect" — exactly the
report. Wi-Fi automation users were the accidental exception (an SSID report
after helper restart re-fires rules). This also contradicts
`docs/analysis/issue-41-live-verification.md`, whose checklist asserts "a
crash restarted by launchd should reconnect" — with current code that
expectation was false; the second-Mac verification would have caught it.

Why the maintainer's machine never showed it: the crash-restore path only
matters when the helper dies while the GUI keeps running (sleep being the
amplifier). Ordinary dev/test sessions don't hit that combination.

## The fix on this branch

New persisted intent file `<dataDir>/desired-tunnels.json`
(`internal/helper/desired_state.go`):

- **Written on user-intent transitions only**: successful Connect
  (`doConnectHeld`), Disconnect, rename. Failed connects need no write
  (activeCfgs rolls back to what the file already records). The monitor's
  teardown-before-reconnect deliberately does not touch it — a tunnel
  mid-reconnect is still wanted.
- **Cleared on clean shutdown** (`cleanup()`): Quit / `ctl stop` leave
  nothing to restore.
- **Restored once at helper startup** (`restoreDesiredTunnels` via `goSafe`,
  async so the IPC listener is never delayed): each listed tunnel is reloaded
  from the user's tunnel store and reconnected, with the same
  `applyPostConnectFirewall` follow-up a manual connect gets.
- **Reboot-aware**: if the file's mtime predates the current boot
  (`kern.boottime` / `/proc/uptime` / `GetTickCount64`, 2 s slack), the
  tunnels died with a previous power cycle — clear instead of restore. After
  a reboot the user's expectation is "off".
- **Failure-tolerant**: a restore connect that fails (no network yet right
  after a crash-restart) goes into `pendingDesired`, which every later write
  still includes, so an unrelated connect/disconnect can't drop it. Retry:
  - `Monitor.shouldTriggerReconnect` now also fires wake/network triggers
    when the desired-state file is non-empty even with nothing active
    (`SetDesiredActiveFn`, wired in `Run`). With nothing up, the monitor
    skips the pre-reconnect `Disconnect()` (which would fail with
    not-connected and back off forever) and the firewall suspend (whose
    resume can't re-enable a no-tunnel kill switch).
  - `reconnectFn` connects pending tunnels through `doConnectHeld` +
    post-connect firewall, re-checking under `connectMu` that the user
    hasn't disconnected them meanwhile.
  - A Disconnect (named or all) withdraws pending entries; rename re-keys
    them. `cleanup()` clears the file under `desiredMu`, and writes after
    shutdown begins are skipped, so a connect finishing during Quit can't
    resurrect the file.
  - A helper with a pending restore does not idle-exit (`armShutdownTimer`
    treats it like an active tunnel), or cleanup would clear the file and
    nothing would retry until the GUI next started the helper.
- **Firewall intent restored with the tunnels**: kill switch and DNS
  protection live only in helper memory (the GUI re-sends them after its own
  connects via `applyFirewallSettings`), and crash recovery removes the pf
  rules. The file records both flags (using the pre-suspend values while a
  reconnect has the firewall suspended). Restore re-installs the kill switch
  BEFORE reconnecting — a restore that fails keeps the blockade instead of
  leaking — and DNS protection after each connect, then broadcasts
  `EventAutoConnect` so a running GUI refreshes and re-applies its settings.
- **Automation rules win**: restore holds `reevalMu` (order
  reevalMu → connectMu, same as automation) and skips tunnels whose rule says
  off on the current network; pending retries check the same, and a rule
  pass that says off withdraws a pending entry. Unknown SSID gives no
  verdict, matching the startup rule pass.

### Pre-existing bugs fixed alongside

- Wake with several tunnels up: the all-tunnels path called
  `manager.Disconnect()`, which drops only the first tunnel, so reconnecting
  all of them hit `ErrAlreadyConnected` and the retry looped. It now
  disconnects every connected tunnel, and `reconnectFn` treats
  `ErrAlreadyConnected` as success.
- `resumeFirewall` re-enabled the kill switch for one interface only, so
  after a wake other tunnels were fenced out; with no tunnel back up it
  logged and left the kill switch off. It now rebuilds from all active
  tunnels via `enableKillSwitchForActiveTunnels`, which installs the base
  blockade when none are up. A later attempt then finds nothing up and skips
  the suspend, so `reconnectFn` connects cached tunnels through
  `doConnectHeld` whenever the blockade is up — a bare connect under it
  would fail (DNS/UDP blocked) or come up with the interface never
  permitted.

### Exit-path semantics

| how the previous helper ended | restore? | why |
|---|---|---|
| crash / `kill -9` mid-session | yes | same boot, file fresh |
| crash while machine asleep | yes | launchd restarts mid-sleep, or the wake trigger acts on the file |
| upgrade `ForceShutdown` (no teardown) | macOS only | tunnel continuity across app updates; Windows/Linux relaunch is a fresh start |
| clean Quit / `ctl stop` | no | cleanup cleared the file |
| reboot / power loss | no | file predates current boot |
| Windows logoff / Fast Startup shutdown | no | helper (a plain elevated process, not a service) dies with the session; the next GUI launch is a fresh start |

Restart source differs by platform: on macOS launchd restarts a crashed
helper (`KeepAlive`), so restore runs on startup subject to the boot-time
check. On Windows/Linux nothing restarts the helper but the GUI's background
recovery, which passes `--restore-desired`; any other start clears the file.
Boot time alone can't gate Windows: a Fast Startup shutdown keeps it.
On Windows/Linux an in-app update is also a fresh start, so tunnels don't
carry across it there (unchanged from before this branch).

## Not addressed here

Follow-up (2026-10-13): RPC deadlines previously bounded only response
waiting. A blocked request write or a wait behind another writer could
outlive the context indefinitely. Tests using a real stalled net.Pipe
reproduced both failures. Request writes now use context-aware serialization,
write deadlines and cancellation; a partial-frame failure closes the stream
instead of reusing corrupted framing. This removes a concrete recovery/Quit
hang path, but does not establish the cause of the reporter's native GUI hang.

- **P2 (the hang)**: static review found no main-thread blocker (event
  bridge, SSID reporter and tray paths all run off the main thread; helper
  busy-ness delays GUI RPCs at 10 s per call but does not beachball). The
  crash report's Thread 0 backtrace is required; requested on the issue.
- Whether the reporter's helper actually died during sleep (vs. the trigger
  failing to fire on macOS 27) — the diagnostic questions separate the two;
  the fix covers the first, the answers will confirm.

## Verification checklist (macOS, per the live-verification convention)

Build a fresh signed bundle on the target Mac (same prerequisites as the
issue-41 doc), then, with the GUI running and a tunnel connected:

1. **Crash-restore**: `sudo kill -9 <helper pid>` → helper restarts (launchd,
   ≤5 s throttle) → the tunnel should come back by itself within seconds and
   the GUI show connected again, no admin prompt, no manual reconnect.
   Check `/var/log/wireguide-helper.log` for `desired-state restore complete`.
2. **Boot boundary**: crash the helper as above, then reboot BEFORE it can be
   restarted (or backdate the file: `sudo touch -t` on
   `/var/lib/wireguide/desired-tunnels.json` — actual path is the helper's
   `--data-dir`). After reboot + app launch the tunnels must stay down.
3. **Clean quit leaves nothing**: connect a tunnel, tray Quit, reopen → no
   auto-reconnect (unchanged behavior), `desired-tunnels.json` absent.
4. **Wake retry after failed restore**: crash the helper with Wi-Fi off;
   once it restarts the restore fails; enable Wi-Fi (network-change trigger)
   → tunnel comes back without manual action.
5. **Upgrade continuity**: connect a tunnel, run an in-app update through
   the ForceShutdown path → after relaunch the tunnel should return.
6. Regression pass: connect/disconnect cycles, multi-tunnel restore,
   rename/delete of a listed tunnel (entry dropped, not resurrected).

Record macOS version, `launchctl print system/com.wireguide.helper` after
each crash-restart, and the helper log tail.
