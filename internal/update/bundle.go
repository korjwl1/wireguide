package update

// OS-agnostic helpers for the macOS bundle-swap installer
// (installer_darwin.go). Kept free of build tags so the path and swap
// logic is unit-tested on every CI platform, not only on macOS runners.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// appBundleFromExe maps a running executable path like
// /Applications/WireGuide.app/Contents/MacOS/wireguide to its bundle
// root. Returns an error for binaries that don't live in a bundle
// (dev builds run from bin/, `go run`, the Homebrew CLI symlink once
// resolved — callers resolve symlinks first).
func appBundleFromExe(exe string) (string, error) {
	macOS := filepath.Dir(exe)
	contents := filepath.Dir(macOS)
	bundle := filepath.Dir(contents)
	if filepath.Base(macOS) != "MacOS" || filepath.Base(contents) != "Contents" ||
		!strings.EqualFold(filepath.Ext(bundle), ".app") {
		return "", fmt.Errorf("%q is not inside an .app bundle", exe)
	}
	return bundle, nil
}

// isTranslocated reports whether path is under Gatekeeper's App
// Translocation mount — a read-only randomized copy macOS runs a
// quarantined app from until the user moves it. Replacing it is
// pointless (the next launch translocates the original again).
func isTranslocated(path string) bool {
	return strings.Contains(path, "/AppTranslocation/")
}

// findStagedBundle returns the single top-level .app inside dir — the
// release zip is built with `ditto -c -k --keepParent wireguide.app`.
// Anything else (no bundle, several bundles) means the archive isn't what
// CI produces and is rejected. Dotfiles and __MACOSX resource-fork
// folders are ignored.
func findStagedBundle(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var found []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || name == "__MACOSX" {
			continue
		}
		if e.IsDir() && strings.EqualFold(filepath.Ext(name), ".app") {
			found = append(found, filepath.Join(dir, name))
		}
	}
	if len(found) != 1 {
		return "", fmt.Errorf("update archive must contain exactly one .app bundle, found %d", len(found))
	}
	return found[0], nil
}

// swapBundle atomically-as-possible replaces target with staged:
// target is renamed to backup, staged is renamed into place, and on
// failure the backup is renamed back. All three paths must be on the
// same filesystem (the caller stages next to target), so each step is a
// plain rename(2) — no half-copied bundle is ever visible at target.
// The running process keeps executing from the moved/unlinked old inode.
func swapBundle(staged, target, backup string) error {
	if _, err := os.Stat(staged); err != nil {
		return fmt.Errorf("staged bundle missing: %w", err)
	}
	if err := os.Rename(target, backup); err != nil {
		return fmt.Errorf("move current app aside: %w", err)
	}
	if err := os.Rename(staged, target); err != nil {
		if rerr := os.Rename(backup, target); rerr != nil {
			return fmt.Errorf("install new app: %w (rollback ALSO failed: %v — previous app is at %s)", err, rerr, backup)
		}
		return fmt.Errorf("install new app: %w (previous version restored)", err)
	}
	return nil
}
