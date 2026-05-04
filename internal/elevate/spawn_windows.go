//go:build windows

package elevate

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// SpawnHelper launches the helper with admin privileges via PowerShell + UAC.
// ctx is accepted for parity with darwin; PowerShell's Start-Process detaches
// the elevated child immediately, leaving nothing for ctx to cancel.
func SpawnHelper(ctx context.Context, args Args) error {
	_ = ctx
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
	return exec.Command("powershell", "-Command", ps).Start()
}

// psEscape escapes a string for use inside a PowerShell single-quoted string.
// Single quotes are doubled per PowerShell escaping rules.
func psEscape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
