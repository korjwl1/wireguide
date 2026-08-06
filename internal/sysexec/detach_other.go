//go:build !windows

package sysexec

import (
	"os/exec"
	"syscall"
)

// Detach configures cmd so the child survives this process exiting and does
// not share its controlling terminal. Setsid puts the child in a new session
// and process group, so a Ctrl-C in the launching shell (or the shell itself
// going away) doesn't take it down with it.
//
// Safe to call before any field on cmd has been set. Idempotent.
func Detach(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
}
