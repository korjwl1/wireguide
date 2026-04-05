//go:build linux

package elevate

import (
	"fmt"
	"os/exec"
)

// SpawnHelper launches the helper with root privileges via pkexec (PolicyKit).
// Shows a native authentication dialog.
func SpawnHelper(args Args) error {
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
	return cmd.Start() // background
}
