# Windows GUI relaunch and duplicate tray icons

## Cause and scope

The GUI previously had no process reservation. Closing its window hides it,
so launching the executable again could leave two GUI processes attached to
one privileged helper, with one tray icon per GUI. Tray icon state changes
use `NIM_MODIFY`, not a new tray registration. A screenshot alone cannot
establish whether both icons were live or one was a stale shell icon.

This follows up Windows window restoration in issue #30. The GUI reservation
runs before history cleanup, helper connection, UAC and Wails initialization.
Helper mode and CLI commands retain their own entry paths.

## Implementation

A named pipe scoped to the token's user SID and desktop session is both the
exclusive reservation and activation endpoint. The existing pinned go-winio
implementation creates its first server handle with `FILE_CREATE`; another
listener cannot claim that name. No PID file, timeout-based lock stealing or
persistent mutex handle is needed. Windows releases the handles on process
exit, including a crash.

The second process verifies the pipe server's user/session and grants that
PID foreground permission with `AllowSetForegroundWindow`. It sends a bounded
activation request and exits after acknowledgement. Failure to contact a live
owner does not start another GUI. During shutdown the reservation remains
held until helper teardown and GUI background loops finish; a relaunch retries
until release, within a five-second contact budget.

Requests coalesce while UAC or the WebView is initializing. Delivery waits for
`WindowRuntimeReady`. Activation restores a minimized window, shows it and
requests focus; a normal or maximized window is not restored to a different
size. The same display path serves the tray's Show Window action. Linux's
existing decoration recovery remains in that shared display path. The process
reservation applies only to Windows.

The built-in Wails single-instance option was not used: its initialization
currently follows our helper setup, and its pinned Windows implementation
uses synchronous window messages before the application's message pump is
running. The activation pipe can accept requests while helper authorization
is pending.

## Verification

Shared race tests exercise startup buffering, repeated/concurrent activation,
failed contact, shutdown, silent clients and replacement after owner exit.
Window tests cover minimize restoration, normal/maximized state preservation,
readiness gating, shutdown cancellation and Linux decoration recovery.

Windows-only native tests exercise the exclusive pipe, activation from another
process, concurrent callers, restart after close, kernel cleanup after process
exit without Close, and relaunch during shutdown. These tests belong to the
existing Windows CI job; cross-compilation alone does not establish native
execution or foreground behavior on a user's desktop.

### Recorded results (2026-10-14)

The first [CI run 38534283629](https://github.com/korjwl1/wireguide/actions/runs/38534283629)
reported success, but its Windows log showed three failing Unix socket fixtures.
PowerShell returned the subsequent successful vet exit code, hiding the failed
`go test`. The fixture platform checks and Windows CI exit handling are corrected
in the follow-up commit (refs #25, #41). Results from that first run were:

- Windows: GUI and GUI-instance packages passed, including the five native
  reservation/process tests above. Full tests failed in CLI/helper Unix fixtures;
  the workflow's green status was not evidence of full test success.
- macOS: full repository race tests and vet.
- Linux: full repository race tests, vet, native build/link check and DEB packaging.
- Local macOS: focused GUI/instance race tests; a deliberate removal of the
  duplicate-launch guard made the counterexample fail, and restoring it passed.
- Local cross checks: Windows GUI/instance build and vet, native test executable
  compilation, and Linux arm64 instance package build.

Foreground permission is requested through the Windows API; desktop policy can
still deny focus. The native process tests do not create a Wails window or prove
foreground behavior under every desktop policy. The checks below remain the
release verification for visible, minimized and hidden installed-app windows.

Manual Windows release checks:

1. Launch the installed app, close to tray, then launch it again: one GUI and
   one helper remain, one tray icon is visible, and the original window opens.
2. Repeat with the window minimized, maximized and already visible; confirm
   restoration and focus without changing a maximized window's size.
3. Relaunch while the first launch awaits UAC; confirm one authorization flow
   and one GUI after authorization completes.
4. Quit and immediately relaunch; confirm the old helper teardown finishes
   before a replacement GUI starts.

An already-running v0.5.1 executable does not publish this new activation
endpoint. Exit that old version before testing a new standalone binary. The
existing NSIS upgrade path already terminates the old executable before
replacement. This change prevents duplicate live GUIs; it cannot remove a
shell icon left by a process that has already crashed.

## References

- [Microsoft foreground activation rules](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setforegroundwindow)
- [Microsoft named pipe instances](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-instances)
- Pinned go-winio v0.6.2 `pipe.go`: `ListenPipe`, `makeServerPipeHandle`.
- Pinned Wails v3.0.0-alpha.74 `single_instance_windows.go`,
  `systemtray_windows.go`, `webview_window_windows.go`.
