//go:build windows

package elevate

import (
	"fmt"
	"os/exec"
	"strings"
)

// SpawnHelper launches the helper with admin privileges via PowerShell + UAC.
// Returns an error if the user denies the UAC prompt or if the launch fails.
func SpawnHelper(args Args) error {
	exe, err := SelfPath()
	if err != nil {
		return err
	}

	argList := fmt.Sprintf(
		`'--helper','--socket=%s','--data-dir=%s'`,
		psEscape(args.SocketPath), psEscape(args.DataDir),
	)
	// Use -Wait so PowerShell blocks until Start-Process completes the UAC
	// dialog. If UAC is denied, Start-Process -Verb RunAs throws a
	// terminating error which makes PowerShell exit with a non-zero code.
	ps := fmt.Sprintf(
		`$ErrorActionPreference = 'Stop'; Start-Process '%s' -ArgumentList %s -Verb RunAs -WindowStyle Hidden`,
		psEscape(exe), argList,
	)
	out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(out))
		if outStr != "" {
			return fmt.Errorf("UAC elevation failed: %s: %w", outStr, err)
		}
		return fmt.Errorf("UAC elevation failed (user may have denied the prompt): %w", err)
	}
	return nil
}

// psEscape escapes a string for use inside a PowerShell single-quoted string.
// Single quotes are doubled per PowerShell escaping rules.
func psEscape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
