//go:build windows

package tunnel

import (
	"fmt"
	"os/exec"
)

// runScript executes a user-configured Pre/PostUp/Down hook command.
// Windows variant invokes cmd.exe /C so the user can write batch idioms.
func runScript(command string) error {
	cmd := exec.Command("cmd", "/C", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}
