package update

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Install runs the OS-specific installer for the downloaded update.
func Install(filePath string) error {
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
	// Try dpkg for .deb
	if len(path) > 4 && path[len(path)-4:] == ".deb" {
		return exec.Command("sudo", "dpkg", "-i", path).Run()
	}
	// Try rpm for .rpm
	if len(path) > 4 && path[len(path)-4:] == ".rpm" {
		return exec.Command("sudo", "rpm", "-U", path).Run()
	}
	// AppImage — make executable and run
	exec.Command("chmod", "+x", path).Run()
	return exec.Command(path).Start()
}

func installWindows(path string) error {
	// Run .msi installer
	if len(path) > 4 && path[len(path)-4:] == ".msi" {
		return exec.Command("msiexec", "/i", path).Run()
	}
	// Run .exe installer
	return exec.Command(path).Start()
}
