//go:build linux

package elevate

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
)

// SpawnHelper launches the helper with root privileges via pkexec (PolicyKit).
// Shows a native authentication dialog. ctx is accepted for cross-platform
// signature parity with the macOS variant; pkexec needs no plumbing because
// it backgrounds immediately on Start.
func SpawnHelper(ctx context.Context, args Args) error {
	_ = ctx
	if err := ValidateArgs(args); err != nil {
		return fmt.Errorf("invalid spawn args: %w", err)
	}
	if _, err := exec.LookPath("pkexec"); err != nil {
		return fmt.Errorf("pkexec not found: PolicyKit is required for privilege elevation — install the 'polkit' package: %w", err)
	}

	exe, err := SelfPath()
	if err != nil {
		return err
	}

	cmd := exec.Command("pkexec",
		exe,
		"--helper",
		fmt.Sprintf("--socket=%s", args.SocketPath),
		fmt.Sprintf("--uid=%d", args.SocketUID),
		fmt.Sprintf("--data-dir=%s", args.DataDir),
	)
	// Put the helper in its own process group so it survives Ctrl+C on the
	// parent terminal (macOS version uses `& disown` for the same purpose).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Reap pkexec when it exits — without a Wait every spawn attempt (three
	// per failed startup, plus one per health-monitor recovery) leaves a
	// zombie parented to the GUI for the life of the process. Note Start()
	// succeeding says nothing about authorization: pkexec exits non-zero
	// AFTER the user dismisses the polkit dialog, so callers must treat
	// readiness-poll timeout, not Start() error, as the failure signal.
	go func() { _ = cmd.Wait() }()
	return nil
}

// PlistNeedsReinstall is a no-op on Linux — there is no LaunchDaemon plist.
// The darwin variant returns true when the on-disk plist drifts from this
// build's expected content, forcing a reinstall via the version-mismatch path.
func PlistNeedsReinstall(args Args) bool {
	_ = args
	return false
}
