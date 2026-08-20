# Issue #41 — macOS: admin-permission prompt loop after updating to v0.5.x

Root-cause analysis. No macOS hardware was available for live reproduction;
every claim below is either (a) verified directly in this repository's code /
git history, or (b) sourced from external documentation and marked as such.
Confidence levels are stated explicitly.

## Reported symptom

- Reporter: simonefil, macOS Tahoe (26.x), upgraded v0.4.2 → v0.5.0/v0.5.1
  (Homebrew cask).
- On launch, the dialog *"WireGuide needs its helper service to manage VPN
  connections. Please grant administrator access when prompted [Quit] [Retry]"*
  appears; Retry fails; the dialog loops indefinitely.
- v0.4.2 did not exhibit this.
- Reporter's manual fix that worked: full uninstall (`brew uninstall --zap`),
  `launchctl bootout system/com.wireguide.helper`, delete
  `/Library/LaunchDaemons/com.wireguide.helper.plist`,
  `/Library/PrivilegedHelperTools/com.wireguide.helper`,
  `/var/log/wireguide-helper.log`, `/var/run/wireguide`,
  `~/Library/Application Support/WireGuide`, then fresh install of the SAME
  v0.5.x version → works.

The "same version works after a scorched-earth reinstall" detail is the key
constraint: the v0.5.x binary itself runs fine on Tahoe. The failure lives in
**state left behind by the previous install**, not in the new code's ability to
run.

## Verified code facts

### 1. The dialog loop is the GUI's 3-attempt retry funnel

`internal/gui/gui.go:99-120`: `ensureHelper` gets 3 attempts × 30 s each; any
failure shows `askHelperRetry` (`internal/gui/retry_prompt_darwin.go`) — the
exact dialog text from the issue. After 3 failures the app exits; relaunching
repeats it. Any *persistent* failure inside `ensureHelper` therefore presents
exactly as "dialog appears in loop".

Two failure funnels exist inside `ensureHelper` → `elevate.SpawnHelper`
(`internal/elevate/spawn_darwin.go`):

- **F-A** — the root install script (osascript `do shell script … with
  administrator privileges`) exits non-zero → `"daemon install failed"`.
  The script is `cp` binary + `cp` plist + `launchctl bootout` + wait ≤2 s +
  `launchctl bootstrap` + `launchctl kickstart -k`.
- **F-B** — script succeeds but the helper socket
  (`/var/run/wireguide/wireguide.sock`) never accepts within 6 s →
  `"daemon installed but socket not live after 6s"` (helper blocked from
  launching, or crash-looping).

Both funnels produce the identical user-visible loop. The GUI currently
surfaces **neither** the script's stderr nor launchctl's error code anywhere
the user can see.

### 2. v0.5.0 reinstalls the daemon (with password) on every cold launch — by design

Behavioral diff v0.4.2 → v0.5.0, verified via `git show v0.4.2:…` vs HEAD:

| | v0.4.2 | v0.5.x |
|---|---|---|
| plist `RunAtLoad` | `true` | `false` (commit 25b827b) |
| Helper lifetime | persistent from boot | exits ~10 s after GUI quits (`shutdownGrace`, `internal/helper/helper.go:108`); GUI quit also sends `MethodShutdown` explicitly (`gui.go:280`) |
| Install script runs | once, at first install | **every cold app launch** (socket dead → `SpawnHelper` goes straight to `installAndLoadDaemon`; there is no lighter "already installed, just kickstart" path) |
| Admin password prompts | once ever | **every cold launch** |
| Script ending | `bootstrap` | `bootstrap && kickstart -k` |

So in v0.5.x every single app launch (without a live tunnel keeping the helper
alive) rewrites the daemon binary + plist, boots the job out, re-bootstraps and
re-kickstarts it — under a fresh admin prompt each time. The `SpawnHelper` doc
comment (spawn_darwin.go:26-30) confirms this is the intended trade. This alone
explains the *"asks for admin permissions in loop"* framing of the title even
before any hard failure: v0.4.2 users were trained to expect exactly one
password prompt per machine, ever.

### 3. macOS artifacts are ad-hoc signed

`build/darwin/Taskfile.yml:166`: `codesign --force --deep --sign -` — ad-hoc
signature. `SIGNING-POLICY.md:15-16` confirms macOS is out of scope of the
SignPath (Windows-only) signing. An ad-hoc signature carries **no Developer ID
and no stable signing identity**; its identity is the binary's cdhash, which
changes with every release build.

### 4. Ruled out by code inspection

- **Stale socket file** — `ipc.Listen` unconditionally removes the old socket
  before binding (`internal/ipc/transport_unix.go:92`). Not the cause.
- **Socket path change between versions** — `DefaultSocketPath` identical in
  v0.4.2 and v0.5.x (`/var/run/wireguide/wireguide.sock`). Not the cause.
- **Old helper can't be told to die** — v0.4.2 already had
  `Helper.Shutdown` / `Helper.ForceShutdown` handlers and reported
  `AppVersion` in Ping (verified via `git show v0.4.2:internal/helper/handlers.go`),
  so the upgrade path's shutdown-then-reinstall sequence works against a
  v0.4.2 helper. Clean shutdown exits 0; the old plist's
  `KeepAlive={SuccessfulExit:false}` does not restart it. Not the cause.
- **bootout/bootstrap race** ("service already loaded") — possible on a slow
  teardown (the wait loop caps at 2 s and old-helper cleanup can take seconds
  per tunnel: `helper.go` cleanup comment), but it is transient; the next
  Retry would succeed. Cannot explain a *persistent* loop. Contributing noise
  at most.
- **Crash-recovery state from v0.4.2 crashing the new helper** — recovery
  state lives in the system `DataDir` `/Library/Application Support/WireGuide`
  (`internal/storage/paths.go:49`). The reporter's fix deleted only the
  *user-level* `~/Library/Application Support/WireGuide`; the system-level dir
  was (as far as the comment shows) never touched, yet the reinstall fixed the
  problem. Also `RecoverFromCrash` tolerates unknown/missing state files.
  Unlikely (low confidence in ruling out completely — `brew --zap` may remove
  more than listed, and we never saw `/var/log/wireguide-helper.log`).

## Primary root cause (high confidence): Tahoe BTM blocks the updated ad-hoc-signed daemon

macOS **Background Task Management (BTM)** — the subsystem behind System
Settings → General → Login Items & Extensions → "Allow in the Background" —
registers every LaunchDaemon under `/Library/LaunchDaemons/` and gates whether
launchd may run it:

- Since macOS 14.6.1, BTM gates LaunchDaemons whose executable does **not
  carry an Apple Developer signature**; such items are classified "Unknown
  Developer" and can be recorded with disposition `disallowed`
  ([mgaebler.me analysis of the identical Nix breakage on Tahoe](https://mgaebler.me/en/blog/nix-macos-tahoe-btm-blocks-launchdaemons/)).
- BTM records store the item's identity derived from its code signature. A
  **Developer ID**-signed daemon keeps a stable identity across updates (team
  ID + anchor); an **ad-hoc** binary has only its cdhash — *every release is a
  different identity*. Replacing the binary in place therefore invalidates the
  stored record instead of matching it. The long-known "Perpetual Background
  Items Added" notification problem for unsigned tools is the same mechanism
  ([Apple Communities](https://discussions.apple.com/thread/254341579)).
- macOS 26 Tahoe tightened enforcement further and added a user-facing flow to
  **deny** a background daemon, and BTM UI/DB state is known to drift after an
  OS upgrade until toggled off/on or reset
  ([Eclectic Light on managing background items](https://eclecticlight.co/2025/12/03/manage-login-and-background-items/),
  [sfltool notes](https://ss64.com/mac/sfltool.html)).

### Failure chain

1. v0.4.2 installed the daemon once; BTM recorded
   `com.wireguide.helper` keyed to the v0.4.2 ad-hoc cdhash (and/or the user
   upgraded macOS to Tahoe, migrating the BTM DB).
2. Upgrade to v0.5.x replaces `/Library/PrivilegedHelperTools/com.wireguide.helper`
   with a binary whose ad-hoc identity does not match the stored record.
3. On Tahoe, BTM refuses the mismatched/unknown-developer item: either
   `launchctl bootstrap`/`kickstart` fails inside the install script (funnel
   F-A, typically `Bootstrap failed: 5: Input/output error`) or launchd
   registers the job but never starts it (funnel F-B, "socket not live").
4. Every Retry — and every app relaunch — re-runs the same install script
   against the same poisoned BTM record, failing identically → infinite
   prompt loop. v0.5.0's reinstall-on-every-launch design (fact 2) turns what
   would have been a one-time upgrade hiccup into a loop.
5. The reporter's fix deleted the plist + binary (BTM drops/resets the record
   once its backing files are gone) and reinstalled fresh → new BTM
   registration with the new binary's identity → allowed → works. This is
   precisely the observed "same version works after full purge".

Why v0.4.2 never showed it: (a) its daemon was installed exactly once, so the
binary under the BTM record never changed; (b) pre-Tahoe enforcement was
laxer; (c) with `RunAtLoad=true` the helper was already running at GUI launch,
so the install path was almost never re-entered.

**Confidence: high** for the mechanism class (BTM + unstable ad-hoc identity +
Tahoe enforcement), **medium** on which exact funnel (F-A vs F-B) fires for
this reporter — distinguishing them requires the data below.

## Confirmation data to request from the reporter

Requesting these on the issue would turn the remaining uncertainty into fact
(all read-only):

```sh
sudo sfltool dumpbtm | grep -B4 -A12 -i wireguide     # BTM disposition for the helper
sudo launchctl print system/com.wireguide.helper       # job state / last exit reason
tail -50 /var/log/wireguide-helper.log                 # did the helper ever start?
log show --last 1h --predicate 'process == "backgroundtaskmanagementd" OR eventMessage CONTAINS "wireguide"' --info
```

Plus: System Settings → General → Login Items & Extensions → whether a
WireGuide / "Unknown Developer" entry exists and its toggle state.

## Recommended fixes

Ordered short-term → long-term:

1. **Surface the real error (trivial, do first).** Capture the install
   script's stderr + exit status and the `launchctl` error text, log them, and
   show them in the retry dialog. Today the user loops blind, and we diagnose
   blind. Also detect the BTM case explicitly: if `launchctl print` shows the
   job loaded-but-not-running (or bootstrap returns error 5/119), replace the
   generic Retry dialog with instructions to enable WireGuide under System
   Settings → Login Items & Extensions, or to remove
   plist+binary and retry (self-heal, see 3).
2. **Stop reinstalling when nothing changed.** If the installed daemon binary
   already hashes identical to the running app's binary AND the on-disk plist
   matches, skip the `cp`s and run only `launchctl kickstart -k` (still one
   admin prompt, but no binary churn → the BTM record stays stable and no
   re-registration storm / "Background Items Added" spam).
3. **On version change, purge-then-install instead of overwrite-in-place.**
   `bootout` + `rm` plist + `rm` binary, then install fresh — replicating the
   reporter's manual fix inside the script, which resets the BTM record
   instead of invalidating it. Low cost, directly targets the observed
   recovery path.
4. **Real fix: stable signing identity.** Ad-hoc signing is fundamentally
   incompatible with BTM across updates. Options: Apple Developer ID
   signing + notarization for the helper (and ideally migrate installation to
   `SMAppService.daemon(plistName:)`, Apple's supported mechanism, which also
   removes the osascript/authopen dance). Requires a paid Apple Developer
   account — a project decision, but every update-time BTM breakage traces
   back to this.
5. **Reconsider the every-cold-launch password prompt** (v0.5.0 regression in
   UX even when nothing fails). E.g. keep `RunAtLoad=false` but let the plist
   stay bootstrapped and use `launchctl kickstart` via a small
   SMJobBless/SMAppService-authorized path, or gate the helper's self-exit on
   an opt-in "harden lifetime" setting. Issue #41's title is as much about
   the prompt frequency as about the failure.

## Implemented on this branch

Recommendations 1-3 are implemented in this branch (recommendation 4,
Developer ID signing, is a project/funding decision; 5 is a product decision —
both left open):

- **Purge-then-install** (`internal/elevate/spawn_darwin.go`): the install
  script now runs `bootout` → wait (5 s) → `rm -f` binary+plist → fresh copy →
  `bootstrap` → `kickstart -k`. Replicates the reporter's working manual fix;
  resets the BTM record instead of invalidating it. Bootout moved ahead of the
  copy so a running helper's binary is never overwritten in place.
- **Kickstart-only fast path**: when the installed binary (SHA-256) and plist
  are byte-identical to the current build, the admin script is just
  `launchctl kickstart -k …`, escalating to the full purge+install inside the
  same admin session on failure. No BTM re-registration churn on routine cold
  launches.
- **Error surfacing**: the osascript install's combined output (which carries
  launchctl's error text) now rides along in the returned error; the
  "socket not live" failure names the helper log and the Login Items &
  Extensions pane; `askHelperRetry` on macOS and Windows shows the error
  detail in the retry dialog instead of looping blind.
- Tests: `TestInstallScriptPurgesBeforeCopy` pins bootout < purge < copy
  ordering; `TestKickstartOnlyPathEscalates` pins the same-session
  escalation; existing kickstart/RunAtLoad pins still hold.

Not verified on real macOS hardware (authored on Windows; `internal/elevate`
cross-compiles and vets clean for darwin). Needs a Tahoe machine — ideally the
reporter's — to confirm before release.

## Sources

- https://mgaebler.me/en/blog/nix-macos-tahoe-btm-blocks-launchdaemons/
- https://eclecticlight.co/2025/12/03/manage-login-and-background-items/
- https://discussions.apple.com/thread/254341579
- https://developer.apple.com/forums/thread/748205
- https://ss64.com/mac/sfltool.html
- https://theevilbit.github.io/posts/smappservice/
