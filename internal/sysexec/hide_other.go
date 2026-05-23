//go:build !windows

package sysexec

import "os/exec"

// Hide is a no-op on non-Windows platforms — only Windows console
// children of a -H windowsgui parent need conhost suppression.
func Hide(cmd *exec.Cmd) {}
