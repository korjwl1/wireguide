package update

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DownloadUpdate downloads the release asset to a secure temp file and
// verifies the SHA256 checksum if available.
//
// CURRENTLY UNREFERENCED FROM PRODUCTION CODE — macOS uses Homebrew for
// updates (see internal/app/settings_ops.go → IsBrewInstall path) and
// Linux/Windows ship without auto-install plumbing yet. This function
// (and the rest of the verify* / install* family below) is kept on
// purpose for the day we add native Linux/Windows update flows; it is
// fully exercised by checker_test.go so it doesn't bit-rot. If you're
// auditing for dead code and considering deletion: confirm with the
// maintainer first.
func DownloadUpdate(info *UpdateInfo) (string, error) {
	if info.DownloadURL == "" {
		return "", fmt.Errorf("no download URL for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	// Defensive even though CheckForUpdate also rejects this — a
	// future caller might construct UpdateInfo by hand.
	if info.AssetSize <= 0 {
		return "", fmt.Errorf("refusing to download: invalid AssetSize %d", info.AssetSize)
	}

	if err := checkUpdateRawURL(info.DownloadURL); err != nil {
		return "", err
	}
	client := newUpdateClient(5 * time.Minute)
	resp, err := client.Get(info.DownloadURL)
	if err != nil {
		return "", fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	// Verify Content-Length matches the asset size reported by the
	// GitHub API. A mismatch may indicate a MITM or CDN substitution
	// attack. If the response omits Content-Length entirely (chunked
	// encoding from a transparent proxy), warn and rely on the
	// post-stream length+hash check instead of refusing.
	cl := resp.ContentLength
	if cl > 0 && info.AssetSize > 0 && cl != info.AssetSize {
		return "", fmt.Errorf("Content-Length %d does not match expected asset size %d — possible tampering", cl, info.AssetSize)
	}
	if cl <= 0 && info.AssetSize > 0 {
		slog.Warn("download response has no Content-Length; relying on post-stream length+hash verification",
			"expected_size", info.AssetSize, "url", info.DownloadURL)
	}

	// Limit download to expected size + 10% margin to prevent disk exhaustion.
	maxSize := int64(info.AssetSize) + int64(info.AssetSize)/10
	if maxSize < 100*1024*1024 {
		maxSize = 100 * 1024 * 1024 // minimum 100MB cap
	}
	limitedBody := io.LimitReader(resp.Body, maxSize)

	// Use os.CreateTemp to avoid predictable temp paths (symlink attacks).
	ext := filepath.Ext(info.AssetName)
	f, err := os.CreateTemp("", "wireguide-update-*"+ext)
	if err != nil {
		return "", err
	}
	destPath := f.Name()

	// Hash the content as we download it.
	hasher := sha256.New()
	writer := io.MultiWriter(f, hasher)
	written, err := io.Copy(writer, limitedBody)
	if err != nil {
		f.Close()
		os.Remove(destPath)
		return "", err
	}
	f.Close()

	// Reject files that are empty or unreasonably small for a packaged app.
	if written < minAssetSize {
		os.Remove(destPath)
		return "", fmt.Errorf("downloaded file is %d bytes, below minimum %d — refusing to install", written, minAssetSize)
	}

	// Verify the downloaded size matches the size the GitHub API reported.
	if info.AssetSize > 0 && written != info.AssetSize {
		os.Remove(destPath)
		return "", fmt.Errorf("downloaded %d bytes but expected %d — possible truncation or tampering", written, info.AssetSize)
	}

	// Determine the authoritative expected hash. When a signing key is
	// embedded, the hash MUST come from the signature-verified
	// SHA256SUMS fetched now: info.ExpectedHash was fetched
	// unauthenticated at check time, and check and download are separate
	// requests minutes-to-hours apart — a repo-write attacker (the exact
	// threat the Ed25519 layer exists for) could serve a tampered
	// SHA256SUMS at check time and restore the genuine signed pair at
	// download time. Verifying the signature over the fresh copy while
	// comparing the binary against the stale hash would pass both
	// checks; extract-then-verify must operate on one atomic blob.
	expectedHash := info.ExpectedHash
	signatureChecked := false
	if activePublicKey() != "" {
		sums, err := verifyChecksumSignature(info.ChecksumURL, client)
		if err != nil {
			os.Remove(destPath)
			return "", fmt.Errorf("signature verification: %w", err)
		}
		verifiedHash := parseExpectedHash(sums, info.AssetName)
		if verifiedHash == "" {
			os.Remove(destPath)
			return "", fmt.Errorf("asset %q not listed in the signed SHA256SUMS — refusing to install", info.AssetName)
		}
		if expectedHash != "" && !strings.EqualFold(expectedHash, verifiedHash) {
			// Not fatal — the signed hash is authoritative — but a
			// mismatch with the check-time fetch is worth a trace.
			slog.Warn("check-time checksum differs from signed SHA256SUMS; trusting the signed value",
				"asset", info.AssetName)
		}
		expectedHash = verifiedHash
		signatureChecked = true
	} else if requireSignedUpdates {
		// Release builds REFUSE to install without a signature. Defends
		// against a compromised GitHub repo write token swapping both
		// binary + SHA256SUMS at once. Dev builds can still proceed via
		// SHA256-only (the build tag flips this constant off).
		os.Remove(destPath)
		return "", fmt.Errorf("refusing to install update: no signing public key embedded in this build " +
			"(set update.expectedPublicKey before release, or disable signed-updates with the build tag)")
	} else {
		slog.Warn("signature verification skipped: no public key embedded; falling back to SHA256-only authentication " +
			"(dev build — release builds require a signed checksum)")
	}

	// Checksum verification is mandatory — refuse to install without it.
	if expectedHash == "" {
		os.Remove(destPath)
		return "", fmt.Errorf("refusing to install update: no checksum available for verification")
	}

	actual := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(actual, expectedHash) {
		os.Remove(destPath)
		return "", fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHash, actual)
	}
	info.HashVerified = true
	info.SignatureVerified = signatureChecked

	return destPath, nil
}
