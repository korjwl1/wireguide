//go:build darwin

package update

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// macOS releases ship WireGuide-darwin-arm64.zip: an ad-hoc-signed
// wireguide.app archived with `ditto -c -k --keepParent`. Homebrew
// installs never get here (RunUpdate routes them to `brew upgrade`).
// For a direct-download install the strategy is a same-volume bundle
// swap with no privilege escalation:
//
//  1. extract the verified zip with ditto into a staging dir created
//     NEXT TO the running bundle (so the swap is a plain rename),
//  2. sanity-check the staged bundle (identifier, version, codesign),
//  3. rename current → backup, staged → current (rollback on failure),
//  4. the caller quits and reopens the bundle.
//
// The privileged helper is not touched: on next launch the GUI sees the
// helper's version mismatch and runs the existing reinstall prompt.
//
// The swap only needs write access to the bundle's parent directory —
// true for admin users in /Applications and for ~/Applications. When it
// isn't writable (standard user) or the app is translocated, the install
// is reported as unsupported and the caller opens the Releases page.

const darwinBundleID = "com.korjwl1.wireguide"

func runningAppBundle() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("%w: cannot locate running executable: %v", ErrSelfUpdateUnsupported, err)
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	if isTranslocated(exe) {
		return "", fmt.Errorf("%w: app is running from a translocated (quarantined) location — move it to Applications first", ErrSelfUpdateUnsupported)
	}
	bundle, err := appBundleFromExe(exe)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSelfUpdateUnsupported, err)
	}
	return bundle, nil
}

func platformSelfUpdateSupport() error {
	bundle, err := runningAppBundle()
	if err != nil {
		return err
	}
	// Writability probe: the swap renames inside the parent directory.
	probe, err := os.MkdirTemp(filepath.Dir(bundle), ".wireguide-update-probe-")
	if err != nil {
		return fmt.Errorf("%w: %s is not writable by this user", ErrSelfUpdateUnsupported, filepath.Dir(bundle))
	}
	_ = os.Remove(probe)
	// Moving a directory to another parent also rewrites its ".." entry,
	// which needs write access on the bundle itself — a root-owned bundle
	// under an admin-writable /Applications would otherwise pass the probe
	// above, download, and only then fail the swap.
	if err := unix.Access(bundle, unix.W_OK); err != nil {
		return fmt.Errorf("%w: %s is not writable by this user", ErrSelfUpdateUnsupported, bundle)
	}
	return nil
}

// platformCleanupPreviousUpdate removes the staging directories a bundle
// swap kept next to the app (the replaced bundle, which the old process
// was still running from) and any left by an interrupted update.
func platformCleanupPreviousUpdate() {
	bundle, err := runningAppBundle()
	if err != nil {
		return
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(bundle), ".wireguide-update-*"))
	for _, dir := range leftovers {
		if err := os.RemoveAll(dir); err != nil {
			slog.Warn("update: could not remove leftover update directory", "path", dir, "error", err)
		}
	}
}

func platformInstall(ctx context.Context, path string, info *UpdateInfo) (*InstallResult, error) {
	if !strings.EqualFold(filepath.Ext(path), ".zip") {
		return nil, fmt.Errorf("refusing to install: expected the .zip app archive, got %q", filepath.Base(path))
	}
	target, err := runningAppBundle()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open update archive: %w", err)
	}
	err = rehashOpenFile(f, info.verifiedSHA256)
	f.Close()
	if err != nil {
		return nil, err
	}

	staging, err := os.MkdirTemp(filepath.Dir(target), ".wireguide-update-")
	if err != nil {
		return nil, fmt.Errorf("create staging directory: %w", err)
	}
	keepStaging := false
	defer func() {
		if !keepStaging {
			_ = os.RemoveAll(staging)
		}
	}()

	extractDir := filepath.Join(staging, "new")
	if out, err := exec.CommandContext(ctx, "/usr/bin/ditto", "-x", "-k", path, extractDir).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("extract update archive: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	staged, err := findStagedBundle(extractDir)
	if err != nil {
		return nil, err
	}
	if err := checkStagedBundle(ctx, staged, info.Version); err != nil {
		return nil, err
	}
	// Our HTTP client never sets the quarantine xattr, but clear it
	// anyway (as the cask's postflight does) — the content has already
	// been authenticated by the signed SHA256SUMS.
	_ = exec.CommandContext(ctx, "/usr/bin/xattr", "-dr", "com.apple.quarantine", staged).Run()

	if err := swapBundle(staged, target, filepath.Join(staging, "previous.app")); err != nil {
		if _, statErr := os.Stat(target); statErr != nil {
			// Rollback failed — the only copy of the old app is in the
			// staging dir. Never delete it.
			keepStaging = true
		}
		return nil, err
	}
	// Keep previous.app: this process is still running from it until the
	// relaunch, and the quit path may read its Resources. The next startup
	// removes it (CleanupPreviousUpdate).
	keepStaging = true
	slog.Info("update: app bundle replaced", "bundle", target, "version", info.Version)
	return &InstallResult{RelaunchPath: target}, nil
}

// checkStagedBundle rejects an extracted bundle that isn't the WireGuide
// release we asked for. The bytes are already authenticated; this guards
// against a validly-signed but WRONG artifact (e.g. an older release's
// zip re-uploaded under a new tag, which the version-less SHA256SUMS
// signature alone can't distinguish) and against a broken extraction.
func checkStagedBundle(ctx context.Context, bundle, wantVersion string) error {
	exe := filepath.Join(bundle, "Contents", "MacOS", "wireguide")
	if st, err := os.Stat(exe); err != nil || st.IsDir() {
		return fmt.Errorf("update bundle has no Contents/MacOS/wireguide executable")
	}
	plist := filepath.Join(bundle, "Contents", "Info")
	if id := readPlistKey(ctx, plist, "CFBundleIdentifier"); id != darwinBundleID {
		return fmt.Errorf("update bundle identifier is %q, want %q", id, darwinBundleID)
	}
	if v := readPlistKey(ctx, plist, "CFBundleShortVersionString"); versionCore(v) != versionCore(wantVersion) {
		return fmt.Errorf("update bundle version is %q, want %q", v, wantVersion)
	}
	if out, err := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", bundle).CombinedOutput(); err != nil {
		return fmt.Errorf("update bundle code signature is invalid: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// readPlistKey reads a top-level string key with `defaults read`, which
// accepts an absolute plist path minus the ".plist" extension. "" on any
// failure — callers compare against an expected non-empty value.
func readPlistKey(ctx context.Context, plistNoExt, key string) string {
	out, err := exec.CommandContext(ctx, "/usr/bin/defaults", "read", plistNoExt, key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
