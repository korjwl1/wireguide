package update

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Install runs the OS-specific installer for the downloaded update.
// The caller must pass the UpdateInfo whose HashVerified field was set by
// DownloadUpdate. Install refuses to proceed if the hash was not verified.
func Install(filePath string, info *UpdateInfo) error {
	if info == nil || !info.HashVerified {
		return fmt.Errorf("refusing to install: checksum was not verified")
	}
	switch runtime.GOOS {
	case "darwin":
		return installDarwin(filePath)
	case "linux":
		return installLinux(filePath)
	case "windows":
		return installWindows(filePath)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func installDarwin(path string) error {
	// If .dmg, mount and open
	if len(path) > 4 && path[len(path)-4:] == ".dmg" {
		return exec.Command("open", path).Run()
	}
	// If .zip, extract and replace
	return exec.Command("open", path).Run()
}

func installLinux(path string) error {
	// Try dpkg for .deb — use pkexec instead of sudo (works with GUI, no TTY needed)
	if len(path) > 4 && path[len(path)-4:] == ".deb" {
		return exec.Command("pkexec", "dpkg", "-i", path).Run()
	}
	// Try rpm for .rpm — use pkexec for the same reason
	if len(path) > 4 && path[len(path)-4:] == ".rpm" {
		return exec.Command("pkexec", "rpm", "-U", path).Run()
	}
	// AppImage — make executable and run
	if err := exec.Command("chmod", "+x", path).Run(); err != nil {
		return fmt.Errorf("chmod +x: %w", err)
	}
	cmd := exec.Command(path)
	if err := cmd.Start(); err != nil {
		return err
	}
	// Release the process so it doesn't become a zombie when the parent exits.
	return cmd.Process.Release()
}

func installWindows(path string) error {
	// Run .msi installer
	if len(path) > 4 && path[len(path)-4:] == ".msi" {
		return exec.Command("msiexec", "/i", path).Run()
	}
	// Run .exe installer
	cmd := exec.Command(path)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
