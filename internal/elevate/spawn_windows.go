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
// Wait for the authorization launcher, which detaches the elevated helper.
// The context bounds the UAC wait, without waiting for the helper lifetime.
func SpawnHelper(ctx context.Context, args Args) error {
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
	if args.SocketSID != "" {
		// ValidateArgs vetted the SID format; the helper scopes the pipe
		// ACL and peer checks to this SID instead of all interactive
		// users (issue #20).
		argList += fmt.Sprintf(`,'--owner-sid=%s'`, psEscape(args.SocketSID))
	}
	if args.RestoreDesired {
		argList += `,'--restore-desired'`
	}
	ps := fmt.Sprintf(
		`$ErrorActionPreference = 'Stop'; Start-Process '%s' -ArgumentList %s -Verb RunAs -WindowStyle Hidden`,
		psEscape(exe), argList,
	)
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	sysexec.Hide(cmd)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("helper authorization failed: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
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
