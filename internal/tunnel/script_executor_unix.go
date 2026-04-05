//go:build darwin || linux

package tunnel

import (
	"fmt"
	"os/exec"
)

// runScript executes a user-configured Pre/PostUp/Down hook command.
// Unix variant uses `sh -c` so the user can write shell idioms in the .conf.
// The command string comes from a locally-stored config file — same trust
// level as the .conf itself — and the helper only runs these when the user
// explicitly approved via the ScriptWarning dialog.
func runScript(command string) error {
	cmd := exec.Command("sh", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}
