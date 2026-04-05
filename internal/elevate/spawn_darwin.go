//go:build darwin

package elevate

import (
	"fmt"
	"os/exec"
)

// SpawnHelper launches the helper binary with root privileges via osascript.
// Uses the native macOS authentication dialog (padlock), no terminal.
// The helper runs in the background; this call returns after the dialog is
// dismissed (or errors out).
func SpawnHelper(args Args) error {
	exe, err := SelfPath()
	if err != nil {
		return err
	}

	// Run the helper in the background via do shell script with privileges.
	// Using "& disown" to detach so osascript returns immediately.
	// Redirect output to log file for debugging.
	logPath := "/tmp/wireguide-helper.log"
	cmd := fmt.Sprintf(
		`'%s' --helper --socket='%s' --uid=%d --data-dir='%s' > '%s' 2>&1 & disown`,
		exe, args.SocketPath, args.SocketUID, args.DataDir, logPath,
	)
	script := fmt.Sprintf(
		`do shell script "%s" with administrator privileges with prompt "WireGuide needs administrator privileges to manage VPN tunnels."`,
		cmd,
	)

	return exec.Command("osascript", "-e", script).Run()
}
