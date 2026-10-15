# macOS GUI reservation and app-copy verification

## Observed failure

During native testing on 2026-10-15, both the temporary current app and the
old `/Applications/WireGuide.app` ran at once. Each GUI registered a Dock
entry and status item. Their different tray artwork came from different
versions. The old GUI also reinstalled its old shared helper. This was real
concurrent execution, not just a stale Dock icon.

The previous reservation in `guiinstance` applied only to Windows. macOS
returned an unconditional new instance before starting another helper/GUI.
Closing the window hides it to the tray; it does not terminate that instance.

## Fix (`aff22e9`, refs #30, #41, #44)

- Reserve the GUI before touching history, helper setup or the tray.
- Use a private fixed per-user directory under `/private/tmp`, an exclusive
  `flock` reservation and a Unix activation socket. Copies in different
  bundles and launches with different TMPDIR values share the same identity.
- Validate directory/lock owner, mode and type; refuse symlinked or linked
  lock files. Only the lock holder may remove a stale socket after a crash.
- Retain the lock through GUI shutdown and release it after the listener
  closes. Kernel file-descriptor cleanup releases it on SIGKILL as well.
- Reuse the existing bounded, buffered activation protocol. Extra launches
  exit after acknowledgement; the primary restores/shows/focuses its window
  only after the Wails runtime is ready.
- macOS window restoration now uses the shared minimise check before Show
  and Focus, retaining its existing Dock activation/retry behavior.
- A registered older app without an activation socket can be activated with
  [NSRunningApplication](https://developer.apple.com/documentation/appkit/nsrunningapplication).
  This fallback does not make old binaries cooperate with the new lock. An
  old binary launched *after* a new one can still create its old GUI and
  replace the helper. The installed app must also receive the update.

No plist multiple-user restriction was added. Apple's
[LSMultipleInstancesProhibited](https://developer.apple.com/documentation/bundleresources/information-property-list/lsmultipleinstancesprohibited)
has session-level policy implications and cannot replace the early process
reservation or protect direct executable launches.

## Verification on this Mac

macOS 26.3.1, arm64. The real production build corresponds to `aff22e9`;
source and update-key flags match the production build procedure. The local
bundle is ad-hoc signed, not a notarized release.

- Native socket/flock tests under race: activation/restart, eight concurrent
  callers reserving exactly one GUI, actual subprocess SIGKILL and stale
  socket recovery, legacy activation lock release, symlink refusal — PASS.
- Full repository `go test -race ./... -count=1` and `go vet ./...` — PASS.
- Production build and `codesign --verify --deep --strict` — PASS.
- Actual cold setup/upgrade installed the matching helper and rendered the
  Wails/Svelte window; native helper RPC returned an empty connected set.
- With the primary running, five additional processes from two bundle paths
  exited 0 and left one GUI. After updating the actual `/Applications` path,
  six additional processes from three paths also exited 0 and left one GUI.
- Minimised the actual installed window, relaunched the executable, and
  observed the same PID and full-size visible window, no longer minimised.
- Closed the window to the tray, launched another bundle copy, and observed
  the same PID/window restored. A fresh AppKit frontmost-app query confirmed
  that the existing WireGuide PID was active.
- Final observed GUI PID 60410, helper PID 60689; no tunnel was connected.
  Both installed executable hashes matched:
  `980764c9734cf986f9e572cd9e0f1b1a3eacd8081929c1bd7f3fce2e9439130a`.

The first concurrent full-app fixture wrongly assumed that the first Popen
would win the reservation. A child won instead and its subprocess timeout
terminated that legitimate primary. Subsequent full-app checks waited for
the primary reservation; the separate eight-caller native test verifies the
true simultaneous-start case without assuming which caller wins.

## Local installation and recovery

Initial GUI checks used empty test configuration and system-data directories.
Original directories were preserved and restored by rename, including the
saved profile, settings and history. Independent supervisors restored the
original helper/plist bytes. Their check for the old helper's stopped state
timed out during the legacy plist's bootstrap lifetime; the first restoration
was subsequently confirmed stopped. The later installed-app upgrade
intentionally replaced that restored old helper with the matching current one.
These supervisors did not finish with an all-success result.

After the user reproduced old-after-new coexistence, the actual Dock-targeted
`/Applications/WireGuide.app` was updated to the tested current build. Its
original bundle is retained outside `/Applications`, with a `.backup` suffix,
under the private test evidence directory. The original settings/profile were
restored before the final installed-app checks. They had no automatic connect
rules; no existing VPN profile was connected by this test.

Private evidence: `/private/tmp/wg-gui-native-5bce6aoi/evidence`.
The current installed GUI/helper remain running, with one GUI reservation.
The old app backup is deliberately not registered as a second `.app` install.

## Scope limits

This proves the current native reservation and normal window lifecycle on
this Mac. It does not change an already-distributed old binary. The legacy
AppKit fallback has a simulated activation test; the live checks above use
updated copies. Current cancellation, long authorization delay, failed
Retry/BTM approval flows remain separate from the successful cold upgrade.
No sleep/wake, physical network transition or notarized release install was
performed in this follow-up. No main merge or release publication occurred.
