//go:build windows

package sysexec

import (
	"os/exec"
	"syscall"
)

// Win32 process creation flags:
//   - detachedProcess gives the child no inherited console, so it is not
//     killed when the launching console window closes.
//   - createNewProcessGroup keeps a Ctrl-C in the launching console from
//     being delivered to the child.
const (
	detachedProcess       uint32 = 0x00000008
	createNewProcessGroup uint32 = 0x00000200
)

// Detach configures cmd so the child survives this process exiting and is
// not tied to the launching console. Safe to call before any field on cmd
// has been set. Idempotent.
func Detach(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= detachedProcess | createNewProcessGroup
}
