package app

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// Wait for this GUI to finish shutdown before asking LaunchServices to open
// the installed app. Arguments are passed separately to preserve paths with
// spaces and avoid shell interpretation. Give up if shutdown never completes.
const updateRestartScript = `
attempt=0
while /bin/kill -0 "$1" 2>/dev/null; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 300 ] || exit 1
  /bin/sleep 0.1
done
exec "$3" "$2"
`

func (s *TunnelService) restartAfterUpdate() error {
	if s.app == nil {
		return fmt.Errorf("update installed, but application restart is unavailable")
	}
	cmd := exec.Command("/bin/sh", "-c", updateRestartScript, "wireguide-restart",
		strconv.Itoa(os.Getpid()), "/Applications/WireGuide.app", "/usr/bin/open")
	// The launcher must survive the GUI's termination, with no inherited
	// output pipes that could keep an update command waiting for EOF.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
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
