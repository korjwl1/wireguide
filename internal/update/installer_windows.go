//go:build windows

package update

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/korjwl1/wireguide/internal/sysexec"
)

// Windows releases ship WireGuide-windows-<arch>.exe, the NSIS installer
// from build/windows/nsis/project.nsi. It installs per-machine under
// Program Files (requestedExecutionLevel admin), taskkills every running
// wireguide.exe (GUI + elevated helper — Windows locks running images),
// and writes uninstall.exe next to the binary. Swapping files in Program
// Files ourselves would need the same elevation plus a way around the
// image lock, so the self-update strategy is simply: run the verified
// installer silently (/S) into the current install dir, then relaunch.

// Exit codes the waiter script uses for its own failures, chosen to not
// collide with NSIS's 0 (ok) / 1 (cancelled) / 2 (aborted).
const (
	waiterExitUACDeclined = 1223 // ERROR_CANCELLED: user said no to UAC
	waiterExitLaunchFail  = 1001 // Start-Process failed for another reason
)

// installerWaiterScript runs in a hidden, non-elevated PowerShell. All
// inputs arrive as environment variables — never interpolated into the
// script source — so a path containing quotes can't turn into code
// (same pattern as the PATH edit in project.nsi).
//
// Flow: elevate + start the installer (UAC prompt) → wait for it →
// if the installer killed the GUI (the normal case), relaunch the
// freshly installed wireguide.exe as the regular, non-elevated user →
// exit with the installer's code. The GUI blocks on this script, so a
// declined prompt or failed install surfaces back in the UI; on success
// the GUI is gone before the script ends and the relaunch takes over.
//
// WIREGUIDE_UPDATE_VERB is "RunAs" in production; tests leave it empty
// to exercise the script without a UAC prompt.
const installerWaiterScript = `
$ErrorActionPreference = 'Stop'
$a = @{ FilePath = $env:WIREGUIDE_UPDATE_INSTALLER; ArgumentList = $env:WIREGUIDE_UPDATE_ARGS; PassThru = $true }
if ($env:WIREGUIDE_UPDATE_VERB) { $a.Verb = $env:WIREGUIDE_UPDATE_VERB }
try {
  $p = Start-Process @a
} catch {
  $e = $_.Exception
  while ($e.InnerException) { $e = $e.InnerException }
  if ($e -is [System.ComponentModel.Win32Exception] -and $e.NativeErrorCode -eq 1223) { exit 1223 }
  exit 1001
}
$null = $p.Handle
$p.WaitForExit()
$code = $p.ExitCode
if ($null -eq $code) { $code = 0 }
if (-not (Get-Process -Id ([int]$env:WIREGUIDE_UPDATE_GUI_PID) -ErrorAction SilentlyContinue)) {
  try { Start-Process -FilePath $env:WIREGUIDE_UPDATE_APP } catch { }
}
exit $code
`

// windowsInstallLayout returns the running wireguide.exe and its
// directory if — and only if — it looks like an NSIS-managed install
// (uninstall.exe beside it). A portable copy, `go run`, or a dev build in
// bin/ has no uninstall.exe and is reported as unsupported.
func windowsInstallLayout() (exe, dir string, err error) {
	exe, err = os.Executable()
	if err != nil {
		return "", "", fmt.Errorf("%w: cannot locate running executable: %v", ErrSelfUpdateUnsupported, err)
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	dir = filepath.Dir(exe)
	// The installer's taskkill targets this exact image name; a renamed
	// binary would survive the install and keep the old files locked.
	if !strings.EqualFold(filepath.Base(exe), "wireguide.exe") {
		return "", "", fmt.Errorf("%w: running binary %q is not the installed wireguide.exe", ErrSelfUpdateUnsupported, filepath.Base(exe))
	}
	if st, serr := os.Stat(filepath.Join(dir, "uninstall.exe")); serr != nil || st.IsDir() {
		return "", "", fmt.Errorf("%w: %s is not an installer-managed WireGuide directory", ErrSelfUpdateUnsupported, dir)
	}
	return exe, dir, nil
}

func platformSelfUpdateSupport() error {
	_, _, err := windowsInstallLayout()
	return err
}

func platformInstall(ctx context.Context, path string, info *UpdateInfo) (*InstallResult, error) {
	if !strings.EqualFold(filepath.Ext(path), ".exe") {
		return nil, fmt.Errorf("refusing to install: expected the .exe installer, got %q", filepath.Base(path))
	}
	exe, dir, err := windowsInstallLayout()
	if err != nil {
		return nil, err
	}

	// Hold a share-deny-write handle on the installer from the re-hash
	// until it has run: the UAC prompt is an elevation boundary, and the
	// file sits in the user-writable temp dir, so without the lock
	// unprivileged malware could swap it between our check and the
	// elevated launch. Read/execute opens (the loader, NSIS reading its
	// own payload) are still allowed.
	f, err := openDenyWrite(path)
	if err != nil {
		return nil, fmt.Errorf("open update installer: %w", err)
	}
	defer f.Close()
	if err := rehashOpenFile(f, info.verifiedSHA256); err != nil {
		return nil, err
	}
	// The signed SHA256SUMS lists version-less asset names, so a
	// validly-signed installer from an OLDER release re-uploaded under a
	// new tag would verify. The installer's version resource (NSIS
	// VIProductVersion, bumped with every release) must match the tag.
	got, err := installerProductVersion(path)
	if err != nil {
		return nil, fmt.Errorf("read update installer version: %w", err)
	}
	if want := versionCore(info.Version); got != want {
		return nil, fmt.Errorf("refusing to install: installer is version %s, release tag says %s", got, want)
	}

	// /S = silent, /D = install dir (must be last and unquoted — NSIS
	// takes the rest of the command line verbatim, spaces included).
	code, err := runInstallerWaiter(ctx, installerWaiterEnv{
		Installer: path,
		Args:      "/S /D=" + dir,
		App:       exe,
		GUIPID:    os.Getpid(),
		Verb:      "RunAs",
	})
	if err != nil {
		return nil, err
	}
	switch code {
	case 0:
		// Normally unreachable: a successful install taskkills us before
		// the waiter exits. If we're still here the new files are in
		// place but we weren't restarted — let the caller do it.
		return &InstallResult{RelaunchPath: exe}, nil
	case waiterExitUACDeclined:
		return nil, fmt.Errorf("update cancelled: administrator permission was declined")
	case waiterExitLaunchFail:
		return nil, fmt.Errorf("could not start the update installer")
	default:
		return nil, fmt.Errorf("update installer exited with code %d", code)
	}
}

type installerWaiterEnv struct {
	Installer string
	Args      string
	App       string
	GUIPID    int
	Verb      string
}

// runInstallerWaiter runs installerWaiterScript and returns its exit
// code. err is non-nil only when PowerShell itself couldn't run.
func runInstallerWaiter(ctx context.Context, e installerWaiterEnv) (int, error) {
	cmd := exec.CommandContext(ctx, powershellPath(),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodePowerShell(installerWaiterScript))
	cmd.Env = append(os.Environ(),
		"WIREGUIDE_UPDATE_INSTALLER="+e.Installer,
		"WIREGUIDE_UPDATE_ARGS="+e.Args,
		"WIREGUIDE_UPDATE_APP="+e.App,
		"WIREGUIDE_UPDATE_GUI_PID="+strconv.Itoa(e.GUIPID),
		"WIREGUIDE_UPDATE_VERB="+e.Verb,
	)
	sysexec.Hide(cmd)
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return -1, fmt.Errorf("run update installer: %w", err)
	}
	return 0, nil
}

// encodePowerShell produces the base64(UTF-16LE) form -EncodedCommand
// expects, sidestepping Windows command-line quoting of the script.
func encodePowerShell(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[2*i] = byte(c)
		b[2*i+1] = byte(c >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// powershellPath pins Windows PowerShell by absolute path instead of a
// PATH lookup — this process is about to trigger an elevation prompt.
func powershellPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}

// installerProductVersion returns MAJOR.MINOR.PATCH from the PE version
// resource's fixed ProductVersion (the 4th, always-zero NSIS component is
// dropped).
func installerProductVersion(path string) (string, error) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil {
		return "", err
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return "", err
	}
	var fixed *windows.VS_FIXEDFILEINFO
	var fixedLen uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\`, unsafe.Pointer(&fixed), &fixedLen); err != nil {
		return "", err
	}
	if fixed == nil || fixedLen < uint32(unsafe.Sizeof(*fixed)) {
		return "", fmt.Errorf("no fixed version info")
	}
	return fmt.Sprintf("%d.%d.%d", fixed.ProductVersionMS>>16, fixed.ProductVersionMS&0xffff, fixed.ProductVersionLS>>16), nil
}

// openDenyWrite opens path for reading with FILE_SHARE_READ only, so no
// other process can open it for writing or delete/rename it while the
// returned file stays open.
func openDenyWrite(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}
