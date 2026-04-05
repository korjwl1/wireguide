//go:build windows

package elevate

import (
	"fmt"
	"os/exec"
)

// SpawnHelper launches the helper with admin privileges via PowerShell + UAC.
func SpawnHelper(args Args) error {
	exe, err := SelfPath()
	if err != nil {
		return err
	}

	argList := fmt.Sprintf(
		`'--helper','--socket=%s','--data-dir=%s'`,
		args.SocketPath, args.DataDir,
	)
	ps := fmt.Sprintf(
		`Start-Process '%s' -ArgumentList %s -Verb RunAs -WindowStyle Hidden`,
		exe, argList,
	)
	return exec.Command("powershell", "-Command", ps).Start()
}
