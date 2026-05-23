//go:build windows

package elevate

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/korjwl1/wireguide/internal/sysexec"
)

// SpawnHelper launches the helper with admin privileges via PowerShell + UAC.
// ctx is accepted for parity with darwin; PowerShell's Start-Process detaches
// the elevated child immediately, leaving nothing for ctx to cancel.
func SpawnHelper(ctx context.Context, args Args) error {
	_ = ctx
	if err := ValidateArgs(args); err != nil {
		return fmt.Errorf("invalid spawn args: %w", err)
	}
	exe, err := SelfPath()
	if err != nil {
		return err
	}

	argList := fmt.Sprintf(
		`'--helper','--socket=%s','--data-dir=%s'`,
		psEscape(args.SocketPath), psEscape(args.DataDir),
	)
	ps := fmt.Sprintf(
		`Start-Process '%s' -ArgumentList %s -Verb RunAs -WindowStyle Hidden`,
		psEscape(exe), argList,
	)
	cmd := exec.Command("powershell", "-Command", ps)
	sysexec.Hide(cmd)
	return cmd.Start()
}

// psEscape escapes a string for use inside a PowerShell single-quoted string.
// Single quotes are doubled per PowerShell escaping rules.
func psEscape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// PlistNeedsReinstall is a no-op on Windows — there is no LaunchDaemon plist.
// The darwin variant returns true when the on-disk plist drifts from this
// build's expected content, forcing a reinstall via the version-mismatch path.
func PlistNeedsReinstall(args Args) bool {
	_ = args
	return false
}
