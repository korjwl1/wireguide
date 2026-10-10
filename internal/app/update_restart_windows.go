//go:build windows

package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/korjwl1/wireguide/internal/sysexec"
)

// updateRestartScript waits (≤30 s) for this GUI to exit, then starts the
// installed wireguide.exe. Inputs come from environment variables, never
// from the script text, so a path containing quotes can't become code.
const updateRestartScript = `$p = [int]$env:WIREGUIDE_RESTART_PID; ` +
	`for ($i = 0; $i -lt 300 -and (Get-Process -Id $p -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 100 }; ` +
	`if (Get-Process -Id $p -ErrorAction SilentlyContinue) { exit 1 }; ` +
	`Start-Process -FilePath $env:WIREGUIDE_RESTART_APP`

// restartAfterUpdate quits the GUI and starts appPath once this process
// has exited. Only reached when the NSIS installer finished without
// terminating us (it normally taskkills wireguide.exe and the installer
// waiter relaunches the app itself).
func (s *TunnelService) restartAfterUpdate(appPath string) error {
	if s.app == nil {
		return fmt.Errorf("update installed, but application restart is unavailable")
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	cmd := exec.Command(filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", updateRestartScript)
	cmd.Env = append(os.Environ(),
		"WIREGUIDE_RESTART_PID="+strconv.Itoa(os.Getpid()),
		"WIREGUIDE_RESTART_APP="+appPath,
	)
	sysexec.Hide(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("update installed, but cannot schedule restart: %w", err)
	}
	_ = cmd.Process.Release()
	go func() {
		// Let the binding return before beginning the normal GUI shutdown.
		time.Sleep(100 * time.Millisecond)
		s.app.Quit()
	}()
	return nil
}
