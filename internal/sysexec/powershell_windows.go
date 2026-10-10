//go:build windows

package sysexec

import (
	"os"
	"path/filepath"
)

// PowerShellPath returns Windows PowerShell's absolute path. Callers pin
// it instead of a PATH lookup because the scripts they run launch the
// installed app or an elevated installer.
func PowerShellPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}
