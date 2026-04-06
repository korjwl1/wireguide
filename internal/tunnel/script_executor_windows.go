//go:build windows

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
// Windows variant invokes cmd.exe /C so the user can write batch idioms.
//
// A 60-second timeout prevents a hung script from blocking tunnel
// connect/disconnect indefinitely.
func runScript(command, ifaceName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cmd", "/C", command)
	cmd.Env = append(os.Environ(), "WG_I="+ifaceName)
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
