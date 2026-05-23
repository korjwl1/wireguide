//go:build windows

// Package sysexec adjusts exec.Cmd values for platform-specific spawn
// behaviour. Cross-platform callers Hide() unconditionally; non-Windows
// builds get a no-op.
package sysexec

import (
	"os/exec"
	"syscall"
)

// createNoWindow is the Win32 CREATE_NO_WINDOW process creation flag.
// It suppresses the conhost allocation that the loader would otherwise
// perform for a console-subsystem child of a windows-subsystem parent
// (the wireguide helper is built with -H windowsgui, so every netsh /
// route / powershell / reg invocation pops a brief conhost window
// without this flag — visible as a ~200ms flash during each Connect).
const createNoWindow uint32 = 0x08000000

// Hide configures cmd so that the spawned console child does not flash
// a console window. Safe to call before any field on cmd has been set.
// Idempotent.
func Hide(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= createNoWindow
}
