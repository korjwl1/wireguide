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
	return cmd.Start() // background
}
