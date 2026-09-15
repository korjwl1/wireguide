# Issue #41 — macOS helper authorization retry loop

## Status after the 2026-09-08 review

The branch contains a candidate fix. The reporter's persistent failure has
not been reproduced, and its root cause remains unconfirmed. Local test and
build results are recorded separately below; they do not prove that an
upgrade on an affected machine will recover.

The original analysis claimed that an ad-hoc signature change necessarily
invalidates a Background Task Management (BTM) record, and deleting the
binary and plist resets approval. Neither claim was established by the
reporter's logs or an experiment. Treat BTM as a hypothesis, not a diagnosis.
The manual reinstall also changed several other files, so it cannot isolate
which state caused the failure. A second reporter said the problem returned
after reinstalling.

## Reported behavior

- Upgrading v0.4.2 to v0.5.0/v0.5.1 on macOS Tahoe leads to repeated helper
  authorization and Retry/Quit dialogs.
- One reporter recovered after unloading the helper, deleting its binary and
  plist, removing runtime and user configuration files, and reinstalling.
- Another reporter reported recurrence and requested an update on September 8.
- Issue: https://github.com/korjwl1/wireguide/issues/41

## Confirmed code behavior

1. The GUI retries helper setup up to three times. Before this branch, the
   retry dialog omitted the underlying error, hiding distinct failure modes.
2. v0.5.x used `RunAtLoad=false` with `KeepAlive.SuccessfulExit=false`.
   Real launchd testing showed that SuccessfulExit still triggers an initial
   launch. The corrected plist adds `AfterInitialDemand=true`. The helper
   stops after the GUI exits when no tunnels keep it alive. Starting a stopped helper currently requires
   administrator authorization. This branch does not remove that requirement.
3. The old install flow copied files before unloading the previous daemon.
   The branch unloads the old job first and replaces its files afterwards.
4. The original branch polled teardown for five seconds, but then proceeded
   to delete and copy files even if the old job was still registered.
5. A semicolon after the optional quarantine-removal command broke the
   preceding failure chain: a failed purge could still lead to bootstrap and
   a success exit status; a failed binary copy still ran later commands.
6. The GUI's 30-second context began before macOS authorization. The password
   dialog ignored that deadline, but post-install readiness did not: answering
   slowly could therefore produce a retry after a successful install.

## Changes retained and corrections made

- An identical installed binary (SHA-256) and plist use `launchctl kickstart`.
  The fast path omits `-k` to avoid killing a helper that started concurrently.
  A failed kickstart or a process that never answers RPC gets one full
  installation attempt, which may require another authorization. Cancellation
  or an explicitly disabled service stops automatic fallback. `ForceReinstall` explicitly bypasses the fast path.
- Full installation unloads the existing job, waits up to five seconds, then
  removes and replaces the binary and plist, bootstraps, and kickstarts.
  A teardown timeout now aborts before modifying files. This is an installation
  strategy, not a guarantee of BTM approval or automatic approval reset.
- Purge/copy/ownership/permission/bootstrap failures stop the install chain.
  Only the optional quarantine-attribute removal is allowed to fail.
- A unique private temporary directory holds each install's plist, preventing
  concurrent attempts from sharing a predictable temporary filename.
- The GUI starts its 30-second readiness budget after SpawnHelper returns.
  macOS checks compatible RPC responses for up to 30 seconds after each
  authorized start, using transient IPC connections that do not acquire a GUI
  lease. A merely reachable socket is no longer treated as a healthy helper.
  Recovery still respects explicit shutdown cancellation. Linux and Windows
  return from spawning asynchronously, so their readiness budget still bounds
  waiting for the elevated process.
- Installer stderr is surfaced in the retry dialog. Error truncation preserves
  complete Unicode characters. The authorization explanation now acknowledges
  that starting a stopped helper can require a prompt even without an update.

- Runtime macOS recovery only reconnects to a compatible helper restarted by
  launchd. It never installs or shuts down a helper. An outage lasting ten
  seconds after detection shows one persistent error telling the user to quit
  and reopen the app for interactive setup; recovery clears the error.
- An exact disabled entry for `com.wireguide.helper` in `launchctl
  print-disabled system` blocks installation before authorization. Both
  `true/false` and Tahoe's `disabled/enabled` output are recognized. The native
  dialog offers Open Settings and explicit Retry/Quit. No service is silently
  enabled and no BTM records are reset. Other bootstrap failures include a
  concise launchd state summary and the helper log path.

## Verification approach

The installation tests execute the generated shell with stubbed commands;
no system service or VPN configuration is changed. They cover successful
installation, fast startup, purge/copy/bootstrap failures, missing
quarantine attributes, and teardown timeout. The old code failed the purge,
copy, and teardown cases before correction.

GUI lifecycle tests use a private local IPC server and simulated authorization
longer than the readiness budget. They cover successful connection after slow
authorization, readiness timeout, shutdown cancellation during authorization,
passive reconnection, and rejecting old helpers without terminating them.
Repair orchestration tests cover both command and RPC readiness failures, a
single full repair, cancellation, and disabled-service handling. Native launchd
fixtures verify demand/crash/clean-exit policy and parse the actual disabled
state output on this Mac.

## Local results (2026-09-08)

Host: macOS Tahoe 26.3.1, Apple Silicon arm64; Go 1.25.12;
Wails v3.0.0-alpha.74; Node 22.14.0.

- `go test ./... -count=1`: passed (15 packages with tests).
- `go vet ./...`: passed.
- `go test -race ./internal/elevate ./internal/gui -count=1`: passed.
- Slow-authorization test with its timeout deliberately moved back before
  authorization: failed with `context deadline exceeded`, as expected. The
  production source was restored and the corrected test passed with `-race`.
- `task package SIGN_PUBKEY=<release workflow public key>`: passed, producing
  `bin/wireguide.app`. The public verification key matches the release workflow;
  no private signing key is needed for this local build.
- `codesign --verify --deep --strict --verbose=2 bin/wireguide.app`: passed
  (ad-hoc signature). `file` confirms arm64; bundled Info.plist passes `plutil`.
- Built app binary `ctl help`: exited successfully.
- Build regenerated two event binding files to include the existing
  `update_progress` event.

Existing build warnings remain: Svelte accessibility diagnostics, duplicate
Objective-C linker flags, and macOS deployment-target warnings in test links.
`npm audit` reports a high-severity transitive `nanoid` advisory
[GHSA-2v37-7h3g-55p8](https://github.com/advisories/GHSA-2v37-7h3g-55p8).
Dependency updates are outside this helper review.

These were the initial build-only results. The subsequent live GUI/helper
review found an additional launchd lifecycle defect and corrected it. See
[execution verification](issue-41-live-verification.md) for the current matrix
and observed installation, restart, and authorization results.

## Remaining live verification

On an affected Tahoe machine, verify upgrade from v0.4.2/v0.5.1, a cold launch,
relaunch with a live helper, slow password entry, cancellation, and a disabled
background item. Capture the actual install error and helper startup logs.
A successful build or stubbed shell test does not exercise launchd/BTM policy.

Read-only diagnostic commands (run manually with authorization where needed):

```sh
sudo launchctl print system/com.wireguide.helper
sudo sfltool dumpbtm
sudo tail -50 /var/log/wireguide-helper.log
log show --last 1h --predicate 'process == "backgroundtaskmanagementd" OR eventMessage CONTAINS "wireguide"' --info
```

Inspect only the WireGuide records when sharing output; `dumpbtm` includes
unrelated applications. Do not reset the system-wide BTM database as a test.

## Primary references

- [Apple: Manage login items and background tasks](https://support.apple.com/en-au/guide/deployment/depdca572563/web)
  describes background-item management and diagnostics. It does not guarantee
  that removing helper files resets a user's approval decision.
- [Apple: Managing ongoing background processes](https://developer.apple.com/documentation/appkit/managing-ongoing-background-processes-in-your-mac)
  describes visibility and Service Management for persistent background work.
- Local macOS 26.3.1 `man launchctl`: `kickstart -k` kills a running instance;
  `disable` state persists across boots until enabled. These are separate from
  the unconfirmed signature/BTM hypothesis.
