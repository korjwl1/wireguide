package update

// Install is the last step of the in-app update chain (see Apply in
// apply.go): it takes a file DownloadUpdate has already verified and
// hands it to the platform installer. Per-platform strategies live in
// installer_windows.go / installer_darwin.go / installer_other.go.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ErrSelfUpdateUnsupported means this installation cannot replace itself
// (package-managed Linux install, portable/dev Windows binary, read-only
// or translocated macOS bundle, …). Callers should fall back to sending
// the user to the GitHub Releases page — it is never a verification
// failure, and nothing has been downloaded or executed when it is
// returned from SelfUpdateSupport.
var ErrSelfUpdateUnsupported = errors.New("self-update is not supported for this installation")

// Platform hooks, implemented per OS. Package-level vars only so tests
// can drive Apply end-to-end without touching the real installation.
var (
	selfUpdateSupport = platformSelfUpdateSupport
	installPlatform   = platformInstall
)

// InstallResult tells the caller what is left to do after Install.
type InstallResult struct {
	// RelaunchPath is what the caller should reopen after quitting the
	// running app: the swapped .app bundle on macOS, or wireguide.exe on
	// Windows when the installer finished without terminating us. Empty
	// when nothing is left to do.
	RelaunchPath string
}

// SelfUpdateSupport reports whether this installation can update itself
// in place. It returns nil when it can, or an error wrapping
// ErrSelfUpdateUnsupported with the reason. Cheap and side-effect free
// (beyond a writability probe on macOS) — Apply calls it BEFORE
// downloading so an unsupported install never pulls a 20 MB asset.
func SelfUpdateSupport() error {
	return selfUpdateSupport()
}

// Install runs the OS-specific installer for a downloaded update.
//
// The caller must pass the UpdateInfo that DownloadUpdate filled in.
// Install refuses to proceed unless that same process-local
// DownloadUpdate call verified the file (info.verifiedSHA256), and — in
// builds that require signed updates — unless the Ed25519 signature was
// verified too. The re-check matters because Install executes or swaps
// in the file: it must enforce the same policy as DownloadUpdate rather
// than trust that every (future) caller went through it, and the
// JSON-visible HashVerified/SignatureVerified flags alone could have been
// forged by whoever constructed the struct.
func Install(ctx context.Context, filePath string, info *UpdateInfo) (*InstallResult, error) {
	if err := checkInstallPolicy(info); err != nil {
		return nil, err
	}
	return installPlatform(ctx, filePath, info)
}

func checkInstallPolicy(info *UpdateInfo) error {
	if info == nil || !info.HashVerified || info.verifiedSHA256 == "" {
		return fmt.Errorf("refusing to install: checksum was not verified")
	}
	if requireSignedUpdates && !info.SignatureVerified {
		return fmt.Errorf("refusing to install: signature was not verified (this build requires signed updates)")
	}
	return nil
}

// versionCore normalises a release version to MAJOR.MINOR.PATCH for
// comparison with a platform version resource: build metadata and
// pre-release tails are dropped (same rules as isNewerVersion), missing
// components become 0 and leading zeros are removed. Unparseable input
// is returned stripped but otherwise as-is, so it simply fails to match.
func versionCore(v string) string {
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) > 3 {
		parts = parts[:3]
	}
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v
		}
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ".")
}

// rehashOpenFile re-reads f from the start and compares its SHA256 with
// the digest DownloadUpdate verified. Install calls it on the handle it
// is about to hand to the installer, so a file swapped in the temp dir
// between download and install is caught instead of executed.
func rehashOpenFile(f io.ReadSeeker, wantHex string) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("re-verify update file: %w", err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("re-verify update file: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, wantHex) {
		return fmt.Errorf("refusing to install: update file changed after verification (expected %s, got %s)", wantHex, got)
	}
	return nil
}
