//go:build windows

package update

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// The waiter script is exercised with Verb="" (no UAC) and cmd.exe as a
// stand-in installer; production passes Verb="RunAs" and the NSIS exe.

func cmdExe() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "cmd.exe")
}

// writeRelaunchMarkerApp creates a .cmd "app" that records it was started.
func writeRelaunchMarkerApp(t *testing.T) (app, marker string) {
	t.Helper()
	dir := t.TempDir()
	marker = filepath.Join(dir, "relaunched.txt")
	app = filepath.Join(dir, "fake-app.cmd")
	if err := os.WriteFile(app, []byte("@echo started> \"%~dp0relaunched.txt\"\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return app, marker
}

func TestInstallerWaiter_PropagatesInstallerExitCode_NoRelaunchWhileGUIAlive(t *testing.T) {
	app, marker := writeRelaunchMarkerApp(t)
	code, err := runInstallerWaiter(installerWaiterEnv{
		Installer: cmdExe(),
		Args:      "/c exit 3",
		App:       app,
		GUIPID:    os.Getpid(), // we're alive → must not relaunch
	})
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 {
		t.Errorf("waiter exit code = %d, want installer's 3", code)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Error("app relaunched although the GUI was still running")
	}
}

func TestInstallerWaiter_RelaunchesAfterGUIExit(t *testing.T) {
	// A PID that has already exited stands in for the GUI the NSIS
	// installer taskkilled.
	gone := exec.Command(cmdExe(), "/c", "exit 0")
	if err := gone.Run(); err != nil {
		t.Fatal(err)
	}
	app, marker := writeRelaunchMarkerApp(t)
	code, err := runInstallerWaiter(installerWaiterEnv{
		Installer: cmdExe(),
		Args:      "/c exit 0",
		App:       app,
		GUIPID:    gone.Process.Pid,
	})
	if err != nil || code != 0 {
		t.Fatalf("waiter = %d, %v; want 0, nil", code, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("app was not relaunched after the GUI exited")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestInstallerWaiter_LaunchFailure(t *testing.T) {
	code, err := runInstallerWaiter(installerWaiterEnv{
		Installer: filepath.Join(t.TempDir(), "missing-installer.exe"),
		Args:      "/S",
		App:       cmdExe(),
		GUIPID:    os.Getpid(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if code != waiterExitLaunchFail {
		t.Errorf("exit code = %d, want %d", code, waiterExitLaunchFail)
	}
}

// Paths with quotes/dollars travel via environment variables and must
// never be interpreted by PowerShell.
func TestInstallerWaiter_PathIsNotCode(t *testing.T) {
	dir := t.TempDir()
	injected := filepath.Join(dir, "injected")
	weird := filepath.Join(dir, "it's $(New-Item -Path '"+injected+"') x.exe")
	code, err := runInstallerWaiter(installerWaiterEnv{
		Installer: weird,
		Args:      "/S",
		App:       cmdExe(),
		GUIPID:    os.Getpid(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if code != waiterExitLaunchFail {
		t.Errorf("exit code = %d, want launch failure for a nonexistent path", code)
	}
	if _, err := os.Stat(injected); err == nil {
		t.Fatal("installer path was evaluated as PowerShell code")
	}
}

func TestOpenDenyWrite_BlocksWritersAndDelete(t *testing.T) {
	p := filepath.Join(t.TempDir(), "installer.exe")
	if err := os.WriteFile(p, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := openDenyWrite(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if w, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
		w.Close()
		t.Error("file opened for writing while the install lock was held")
	}
	if err := os.Rename(p, p+".swapped"); err == nil {
		t.Error("file renamed while the install lock was held")
	}
	r, err := os.Open(p)
	if err != nil {
		t.Errorf("readers must still be allowed (the loader needs it): %v", err)
	} else {
		r.Close()
	}
}

func TestInstallerProductVersion(t *testing.T) {
	v, err := installerProductVersion(cmdExe())
	if err != nil {
		t.Fatalf("reading cmd.exe version: %v", err)
	}
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(v) {
		t.Errorf("version %q is not MAJOR.MINOR.PATCH", v)
	}

	noRes := filepath.Join(t.TempDir(), "plain.exe")
	if err := os.WriteFile(noRes, []byte("not a PE file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := installerProductVersion(noRes); err == nil {
		t.Error("file without a version resource accepted")
	}
}

// A `go test` binary is neither named wireguide.exe nor next to an
// uninstall.exe, so it must be reported as unsupported (→ Releases page).
func TestWindowsInstallLayout_TestBinaryUnsupported(t *testing.T) {
	if err := platformSelfUpdateSupport(); !errors.Is(err, ErrSelfUpdateUnsupported) {
		t.Fatalf("err = %v, want ErrSelfUpdateUnsupported", err)
	}
}

func TestPlatformInstall_RejectsNonExe(t *testing.T) {
	info := &UpdateInfo{HashVerified: true, verifiedSHA256: "ab", Version: "99.0.0"}
	if _, err := platformInstall(context.Background(), filepath.Join(t.TempDir(), "x.zip"), info); err == nil {
		t.Fatal("non-.exe asset accepted as a Windows installer")
	}
}
