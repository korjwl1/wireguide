//go:build darwin || linux

package tunnel

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// runScript executes a user-configured Pre/PostUp/Down hook command.
// Unix variant uses `sh -c` so the user can write shell idioms in the .conf.
// The command string comes from a locally-stored config file — same trust
// level as the .conf itself — and the helper only runs these when the user
// explicitly approved via the ScriptWarning dialog.
//
// A 60-second timeout prevents a hung script from blocking tunnel
// connect/disconnect indefinitely.
func runScript(command, ifaceName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Env = append(os.Environ(),
		"WG_I="+ifaceName,
		"INTERFACE="+ifaceName,
		"WG_QUICK_USERSPACE_IMPLEMENTATION=wireguide",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}

// runScriptWithInterface replaces %i with the interface name (matching
// wg-quick behaviour) and sets WG_I in the environment, then executes.
func runScriptWithInterface(command, ifaceName string) error {
	expanded := strings.ReplaceAll(command, "%i", ifaceName)
	return runScript(expanded, ifaceName)
}
