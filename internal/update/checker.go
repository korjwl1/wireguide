// Package update checks for new releases and handles auto-update.
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	githubRepo     = "korjwl1/wireguide"
	apiEndpoint    = "https://api.github.com/repos/" + githubRepo + "/releases/latest"
	currentVersion = "0.3.1-dev6"

	// minAssetSize is the minimum acceptable size for a release asset.
	// A macOS .dmg/.zip containing WireGuide.app is always well over 1 MB;
	// anything smaller is almost certainly corrupted or a placeholder file
	// injected by an attacker.
	minAssetSize = 1 << 20 // 1 MB

	// expectedPublicKey is set at build time via:
	//   go build -ldflags="-X 'github.com/korjwl1/wireguide/internal/update.expectedPublicKey=<hex>'"
	//
	// Release builds set this to the hex-encoded Ed25519 public key whose
	// matching private key signs each release's SHA256SUMS file. The
	// signature lives next to SHA256SUMS as <SHA256SUMS>.sig (raw
	// 64-byte signature, no encoding).
	//
	// EMPTY in dev builds — falls back to checksum-only auth. To
	// REQUIRE the key at build time for release tags, the CI script
	// passes -ldflags + the requireSignedRelease build tag (see
	// require_signed_release.go). Without that tag, a missing key
	// degrades to SHA256-only; with the tag, a missing key causes
	// activePublicKey() to return "" and the install path refuses
	// to apply the update.
)

// expectedPublicKey is a `var` (not `const`) so `-ldflags -X` can inject
// it. The build-time constant idiom (`const expectedPublicKey = ""`) is
// what allowed every release to ship unsigned by default — the var form
// + ldflags is the standard Go pattern for build-time secrets.
var expectedPublicKey = ""

// CurrentVersion returns the hardcoded app version string.
func CurrentVersion() string { return currentVersion }

// IsDevBuild reports whether this binary was built from an in-progress
// development version. Mirrors wireguard-windows'
// `version.IsRunningOfficialVersion()` — periodic scheduler ticks check
// this and stay silent on dev builds so a developer iterating on the
// app doesn't burn the unauthenticated GitHub API rate budget on every
// `task build` cycle.
//
// We match an explicit allow-list of pre-release markers rather than
// "any hyphen". semver pre-release tags (-rc1, -beta, -alpha) and
// build metadata can both contain hyphens for legitimate official
// releases (`0.3.0-rc1` is shipped publicly), so a bare
// `strings.Contains(currentVersion, "-")` would incorrectly mute the
// scheduler on a real release-candidate build. Our convention (see
// `feedback_dev_build_workflow.md`) is to use `-devN` for in-progress
// builds; the other markers are listed defensively so that future
// release pipelines (rc/beta) keep the scheduler ON in production
// hands while still skipping local dev iteration.
func IsDevBuild() bool {
	lower := strings.ToLower(currentVersion)
	for _, marker := range devBuildMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// devBuildMarkers is the closed allow-list of substrings that flag a
// build as pre-release. Tested against the lower-cased version string.
// Keep this list short and surgical — adding "snapshot" or "ci" here
// would also catch any future stable version that incidentally
// contains those words.
var devBuildMarkers = []string{
	"-dev",  // our project convention: 0.2.1-dev1, 0.2.1-dev2, ...
	"-snap", // generic snapshot builds (CI artefacts, nightly)
	"-pre",  // pre-release marker some projects use
}

// CheckResult is the structured result of a single check, separating
// "no update / didn't change since last time" (Status304) from "new
// update found" (info != nil) from "look-up failed".
type CheckResult struct {
	// Info carries the asset metadata when a newer version is available.
	// Nil otherwise. Callers compare Info.Version with the persisted
	// LastSeenVersion to decide whether to (re-)notify the user.
	Info *UpdateInfo

	// NotModified is true when the server replied 304 — the cached
	// LastSeenVersion is still authoritative and no body was parsed.
	NotModified bool

	// ETag and LastModified are the response headers to persist for the
	// next conditional request. Empty if the server omitted them.
	ETag         string
	LastModified string
}

// CheckForUpdateConditional is the rate-limit-friendly variant of
// CheckForUpdate used by the periodic scheduler. It sends If-None-Match
// and If-Modified-Since headers built from the previous successful
// response so GitHub can answer 304 Not Modified without spending the
// caller's request budget against the public-IP rate-limit bucket.
//
// `prevETag` / `prevLastModified` come from the persisted StateStore;
// passing empty strings degrades to an unconditional fetch.
//
// ctx is propagated so app-shutdown cancellation (schedulerCancel in
// gui.Run) interrupts an in-flight HTTP call cleanly instead of waiting
// for the client-side timeout. Pass context.Background() if the caller
// doesn't have a context (e.g. test code).
func CheckForUpdateConditional(ctx context.Context, prevETag, prevLastModified string) (*CheckResult, error) {
	client := newUpdateClient(10 * time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiEndpoint, nil)
	if err != nil {
		return nil, err
	}
	if prevETag != "" {
		req.Header.Set("If-None-Match", prevETag)
	}
	if prevLastModified != "" {
		req.Header.Set("If-Modified-Since", prevLastModified)
	}
	// GitHub returns richer JSON when this Accept header is set; without
	// it some intermediaries strip the asset list.
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("checking updates: %w", err)
	}
	defer resp.Body.Close()

	res := &CheckResult{
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}

	if resp.StatusCode == http.StatusNotModified {
		res.NotModified = true
		return res, nil
	}
	if resp.StatusCode != http.StatusOK {
		// 403 here usually means rate-limit; surface a typed error so
		// the scheduler can extend its backoff.
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			return res, fmt.Errorf("github rate limit (HTTP %d)", resp.StatusCode)
		}
		return res, fmt.Errorf("github returned HTTP %d", resp.StatusCode)
	}

	info, err := parseReleaseBody(ctx, resp, client)
	if err != nil {
		return res, err
	}
	res.Info = info
	return res, nil
}

// parseReleaseBody extracts the UpdateInfo from a 200 OK response. Pulled
// out of CheckForUpdate so CheckForUpdateConditional and the legacy
// CheckForUpdate share the exact same parsing path. The ctx is threaded
// through to the optional SHA256SUMS sub-fetch so cancellation propagates.
func parseReleaseBody(ctx context.Context, resp *http.Response, client *http.Client) (*UpdateInfo, error) {
	var release Release
	limited := io.LimitReader(resp.Body, 10<<20)
	if err := json.NewDecoder(limited).Decode(&release); err != nil {
		return nil, err
	}

	latestVer := strings.TrimPrefix(release.TagName, "v")
	if !isNewerVersion(latestVer, currentVersion) {
		return &UpdateInfo{Available: false, CurrentVer: currentVersion, Version: latestVer}, nil
	}

	assetName := matchAsset(release.Assets)
	if assetName == "" {
		slog.Warn("update available but no matching asset for this platform",
			"version", latestVer, "os", runtime.GOOS, "arch", runtime.GOARCH)
		return &UpdateInfo{Available: false, CurrentVer: currentVersion, Version: latestVer}, nil
	}
	downloadURL := ""
	var assetSize int64
	checksumURL := ""
	for _, a := range release.Assets {
		if a.Name == assetName {
			downloadURL = a.BrowserDownloadURL
			assetSize = a.Size
		}
		if isCanonicalChecksumName(a.Name) && checksumURL == "" {
			checksumURL = a.BrowserDownloadURL
		}
	}

	if assetSize <= 0 {
		return nil, fmt.Errorf("refusing update %s: GitHub reports asset size 0 (failed upload or tampered release)", latestVer)
	}
	if assetSize < minAssetSize {
		return nil, fmt.Errorf("refusing update %s: asset size %d bytes is below minimum %d (likely corrupted or malicious)", latestVer, assetSize, minAssetSize)
	}

	var expectedHash string
	if checksumURL != "" && assetName != "" {
		expectedHash = fetchExpectedHash(ctx, checksumURL, assetName, client)
	}

	return &UpdateInfo{
		Available:    true,
		Version:      latestVer,
		CurrentVer:   currentVersion,
		ReleaseURL:   release.HTMLURL,
		DownloadURL:  downloadURL,
		ReleaseNotes: release.Body,
		AssetName:    assetName,
		AssetSize:    assetSize,
		ChecksumURL:  checksumURL,
		ExpectedHash: expectedHash,
	}, nil
}

// BrewUpgradeCommand returns the shell command a Homebrew user should
// run to upgrade WireGuide. Returned as a string (not executed) so the
// UI can show it next to a Copy button — the cross-platform-app
// convention is that the user runs the package-manager command, not the
// app itself. See research-update-patterns notes (Tailscale, OrbStack)
// for context.
func BrewUpgradeCommand() string {
	return "brew upgrade --cask wireguide"
}

// Release represents a GitHub release.
type Release struct {
	TagName     string  `json:"tag_name"`
	Name        string  `json:"name"`
	Body        string  `json:"body"`
	PublishedAt string  `json:"published_at"`
	HTMLURL     string  `json:"html_url"`
	Assets      []Asset `json:"assets"`
}

// Asset represents a downloadable file in a release.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// UpdateInfo contains information about an available update.
type UpdateInfo struct {
	Available    bool   `json:"available"`
	Version      string `json:"version"`
	CurrentVer   string `json:"current_version"`
	ReleaseURL   string `json:"release_url"`
	DownloadURL  string `json:"download_url"`
	ReleaseNotes string `json:"release_notes"`
	AssetName    string `json:"asset_name"`
	AssetSize    int64  `json:"asset_size"`
	ChecksumURL       string `json:"checksum_url,omitempty"`  // URL to SHA256SUMS file
	ExpectedHash      string `json:"expected_hash,omitempty"` // pre-parsed SHA256 for this asset
	HashVerified      bool   `json:"hash_verified"`           // set to true after successful checksum verification
	SignatureVerified bool   `json:"signature_verified"`      // true iff Ed25519 .sig also verified
}

// allowedRedirectHosts is the closed set of hostnames our update HTTP
// client will follow redirects to. GitHub's Releases API can legitimately
// redirect to *.githubusercontent.com (for asset bodies) and within
// github.com; anything else is a supply-chain attack signal — an
// attacker who hijacked DNS or BGP for api.github.com could otherwise
// 301 us to a server that serves a malicious binary plus matching
// SHA256SUMS, defeating checksum verification.
var allowedRedirectHosts = map[string]bool{
	"api.github.com":              true,
	"github.com":                  true,
	"objects.githubusercontent.com": true,
	"release-assets.githubusercontent.com": true,
	"codeload.github.com":         true,
}

// updateCheckRedirect rejects any redirect whose target host isn't in
// allowedRedirectHosts. Used by both CheckForUpdate and DownloadUpdate.
func updateCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("too many redirects")
	}
	if err := checkUpdateURL(req.URL); err != nil {
		return err
	}
	return nil
}

// checkUpdateURL enforces https + a GitHub-owned host. CheckRedirect only
// guards redirect HOPS, not the INITIAL request, so callers must run this
// on the first URL too — otherwise a tampered API body handing us a plain
// http:// asset URL, or a non-GitHub host, would be fetched with no guard.
//
// Enforcement is skipped under `go test` so the suite can drive local
// httptest (http://127.0.0.1) servers; the strict logic lives in
// checkUpdateURLStrict, which is unit-tested directly.
func checkUpdateURL(u *url.URL) error {
	if testing.Testing() {
		return nil
	}
	return checkUpdateURLStrict(u)
}

func checkUpdateURLStrict(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("refusing non-https update URL (scheme %q)", u.Scheme)
	}
	if !allowedRedirectHosts[u.Hostname()] {
		return fmt.Errorf("refusing update URL for disallowed host %q", u.Hostname())
	}
	return nil
}

// checkUpdateRawURL parses rawURL and validates it via checkUpdateURL.
func checkUpdateRawURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid update URL: %w", err)
	}
	return checkUpdateURL(u)
}

// newUpdateClient builds an http.Client that locks the redirect domain
// set to GitHub-owned hosts. All update-related HTTP traffic must use
// this constructor.
func newUpdateClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: updateCheckRedirect,
	}
}

// CheckForUpdate queries GitHub Releases API for a newer version.
//
// Kept as a context-less, no-cache convenience wrapper for tests and
// any external caller that doesn't have a cancellation surface to
// thread. Production code paths go through CheckForUpdateConditional
// (via Scheduler) so they share the ETag + ctx-cancellation
// machinery.
func CheckForUpdate() (*UpdateInfo, error) {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiEndpoint, nil)
	if err != nil {
		return nil, err
	}
	client := newUpdateClient(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("checking updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return &UpdateInfo{Available: false, CurrentVer: currentVersion}, nil
	}

	var release Release
	// Limit response body to 10 MB to prevent resource exhaustion from
	// malicious or unexpectedly large API responses.
	limited := io.LimitReader(resp.Body, 10<<20)
	if err := json.NewDecoder(limited).Decode(&release); err != nil {
		return nil, err
	}

	latestVer := strings.TrimPrefix(release.TagName, "v")
	if !isNewerVersion(latestVer, currentVersion) {
		return &UpdateInfo{Available: false, CurrentVer: currentVersion}, nil
	}

	// Find matching asset for current OS/arch
	assetName := matchAsset(release.Assets)
	if assetName == "" {
		slog.Warn("update available but no matching asset for this platform",
			"version", latestVer, "os", runtime.GOOS, "arch", runtime.GOARCH)
		return &UpdateInfo{Available: false, CurrentVer: currentVersion}, nil
	}
	downloadURL := ""
	var assetSize int64
	checksumURL := ""
	for _, a := range release.Assets {
		if a.Name == assetName {
			downloadURL = a.BrowserDownloadURL
			assetSize = a.Size
		}
		// Match SHA256SUMS files exactly. Loose substring matching
		// accepts decoy filenames like `not-a-real-sha256-thing.dat`
		// and lets a release with multiple "checksum"-named files
		// non-deterministically pick the wrong one.
		if isCanonicalChecksumName(a.Name) && checksumURL == "" {
			checksumURL = a.BrowserDownloadURL
		}
	}

	// Reject assets with a zero or suspiciously small size reported by the
	// GitHub API. A zero size can indicate a failed upload or a tampered
	// release; a very small size is never valid for a packaged application.
	if assetSize <= 0 {
		return nil, fmt.Errorf("refusing update %s: GitHub reports asset size 0 (failed upload or tampered release)", latestVer)
	}
	if assetSize < minAssetSize {
		return nil, fmt.Errorf("refusing update %s: asset size %d bytes is below minimum %d (likely corrupted or malicious)", latestVer, assetSize, minAssetSize)
	}

	// Try to pre-fetch the expected hash from the checksum file.
	var expectedHash string
	if checksumURL != "" && assetName != "" {
		expectedHash = fetchExpectedHash(ctx, checksumURL, assetName, client)
	}

	return &UpdateInfo{
		Available:    true,
		Version:      latestVer,
		CurrentVer:   currentVersion,
		ReleaseURL:   release.HTMLURL,
		DownloadURL:  downloadURL,
		ReleaseNotes: release.Body,
		AssetName:    assetName,
		AssetSize:    assetSize,
		ChecksumURL:  checksumURL,
		ExpectedHash: expectedHash,
	}, nil
}

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

// testOverridePubKey lets tests substitute the production
// expectedPublicKey constant without flipping a real release key.
// Empty in production builds; tests assign to it via
// withTestPublicKey() and restore on cleanup. The activePublicKey
// gate ALSO checks testing.Testing() so a future contributor adding
// a //go:build dev file that mutates this var doesn't accidentally
// expose a signature-bypass path in production binaries.
var testOverridePubKey = ""

// activePublicKey returns the hex-encoded Ed25519 public key the
// verifier should use: the test override if set AND we're running
// in a `go test` binary, otherwise the embedded constant. Production
// builds (where testing.Testing() is false) cannot use the override.
func activePublicKey() string {
	if testOverridePubKey != "" && testing.Testing() {
		return testOverridePubKey
	}
	return expectedPublicKey
}

// verifyChecksumSignature downloads the SHA256SUMS file and its .sig
// sibling, verifies the signature against the embedded public key, and
// returns the VERIFIED SHA256SUMS bytes. Callers must treat the returned
// bytes as the only trusted source of asset hashes: a hash fetched at
// check time (info.ExpectedHash) is unauthenticated and may have been
// swapped between check and download — verifying a signature over a
// fresh copy without also taking the hash FROM that copy would let a
// repo-write attacker pass both checks with a malicious binary (serve
// tampered SHA256SUMS at check time, restore the genuine signed pair at
// download time).
func verifyChecksumSignature(checksumURL string, client *http.Client) ([]byte, error) {
	pubHex := activePublicKey()
	if pubHex == "" {
		// Caller already gated; defensive double-check. Return an error
		// (not success) so no caller can mistake unverified bytes for
		// verified ones.
		return nil, fmt.Errorf("no signing public key configured")
	}
	if checksumURL == "" {
		return nil, fmt.Errorf("no SHA256SUMS URL on this release")
	}
	pk, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, fmt.Errorf("malformed embedded public key: %w", err)
	}
	if len(pk) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("embedded public key size: got %d, want %d", len(pk), ed25519.PublicKeySize)
	}

	sumsBody, err := fetchSmall(checksumURL, client)
	if err != nil {
		return nil, fmt.Errorf("download SHA256SUMS: %w", err)
	}
	// Build the .sig URL via url.Parse so a release-asset URL with
	// a query string (CDN-redirected, signed Cloudflare URLs, etc.)
	// gets ".sig" appended to the *path* and not after the query.
	sigURL, err := appendSigSuffix(checksumURL)
	if err != nil {
		return nil, fmt.Errorf("compute .sig URL: %w", err)
	}
	sigBody, err := fetchSmall(sigURL, client)
	if err != nil {
		return nil, fmt.Errorf("download SHA256SUMS.sig: %w", err)
	}

	if err := verifyEd25519(sumsBody, sigBody, pk); err != nil {
		return nil, err
	}
	return sumsBody, nil
}

// appendSigSuffix appends ".sig" to the URL's path, preserving any
// query string and fragment. Plain string concatenation breaks for
// URLs like "https://cdn.example.com/SHA256SUMS?token=abc" which
// would become "...?token=abc.sig".
func appendSigSuffix(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	u.Path += ".sig"
	return u.String(), nil
}

// verifyEd25519 returns nil iff sig is a valid Ed25519 signature of
// content under pubkey. Pulled out of verifyChecksumSignature for
// unit-testability — tests can pass freshly-generated test key pairs
// without monkey-patching globals.
func verifyEd25519(content, sig, pubkey []byte) error {
	if len(pubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("public key size: got %d, want %d",
			len(pubkey), ed25519.PublicKeySize)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature size: got %d, want %d (sig file must be raw 64 bytes, no encoding)",
			len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pubkey, content, sig) {
		return fmt.Errorf("signature does not verify against embedded public key")
	}
	return nil
}

// fetchSmall downloads a small file (≤ 1 MB) and returns its bytes.
// Used for SHA256SUMS and .sig — both are tiny and need to be in
// memory for verification.
func fetchSmall(url string, client *http.Client) ([]byte, error) {
	if err := checkUpdateRawURL(url); err != nil {
		return nil, err
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// isNewerVersion compares two semver strings (without "v" prefix).
// Returns true if latest is newer than current.
//
// Pre-release suffixes (`-dev2`, `-rc1`, `-beta`, build metadata after
// `+`) are stripped before comparison: we only compare numeric
// MAJOR.MINOR.PATCH parts. This means a `-dev2` build correctly sees
// `99.0.0` as newer (the previous strconv.Atoi("1-dev2") returned nil
// and the function returned false for *every* comparison from a dev
// binary), and a future `-rc1` build sees the matching stable as the
// same version rather than newer.
//
// Strict semver pre-release ordering (rc1 < rc2 < stable) is NOT
// implemented — our release flow doesn't ship `-rcN` tags, and the
// extra complexity would only matter if it did. If we ever do, switch
// to golang.org/x/mod/semver instead of hand-rolling it.
func isNewerVersion(latest, current string) bool {
	stripSuffix := func(v string) string {
		// Drop semver build metadata first (`+sha.5114`), then any
		// pre-release tail (`-dev2`, `-rc1`). The order matters because
		// "+" can legally appear inside a pre-release segment.
		if i := strings.IndexByte(v, '+'); i >= 0 {
			v = v[:i]
		}
		if i := strings.IndexByte(v, '-'); i >= 0 {
			v = v[:i]
		}
		return v
	}
	parseParts := func(v string) []int {
		v = stripSuffix(v)
		if v == "" {
			return nil
		}
		var parts []int
		for _, s := range strings.Split(v, ".") {
			n, err := strconv.Atoi(s)
			if err != nil {
				return nil
			}
			parts = append(parts, n)
		}
		return parts
	}
	lp := parseParts(latest)
	cp := parseParts(current)
	if lp == nil || cp == nil {
		// If either version string is not valid semver, don't report as newer
		// to avoid false positives from malformed tag names.
		return false
	}
	for i := 0; i < len(lp) && i < len(cp); i++ {
		if lp[i] > cp[i] {
			return true
		}
		if lp[i] < cp[i] {
			return false
		}
	}
	return len(lp) > len(cp)
}

// fetchExpectedHash downloads a SHA256SUMS-style file and extracts
// the hash for the given asset name. Supported formats:
//
//   - GNU coreutils: "<hex-hash>  <filename>" (two spaces, text mode)
//   - GNU coreutils: "<hex-hash> *<filename>" (binary mode, leading *)
//   - BSD-style:     "SHA256 (<filename>) = <hex-hash>"
//   - filenames containing spaces (rare, but legal — the hash is
//     still the first whitespace-delimited token)
//
// Returns an empty string if the URL fetch fails or no line matches.
func fetchExpectedHash(ctx context.Context, checksumURL, assetName string, client *http.Client) string {
	if err := checkUpdateRawURL(checksumURL); err != nil {
		return ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checksumURL, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return ""
	}
	return parseExpectedHash(body, assetName)
}

// parseExpectedHash extracts the hash for assetName from SHA256SUMS-style
// content. Factored out of fetchExpectedHash so DownloadUpdate can run the
// same parser over the SIGNATURE-VERIFIED bytes — the authoritative source —
// instead of a separately-fetched copy. Returns "" when no line matches.
func parseExpectedHash(body []byte, assetName string) string {
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// BSD-style first: "SHA256 (filename) = hash"
		if hash := matchBSDChecksumLine(line, assetName); hash != "" {
			return hash
		}
		// GNU/coreutils: hash whitespace [*]filename
		// strings.Fields collapses runs of whitespace, but the
		// filename can itself contain spaces — split *only* on the
		// first run so the rest of the line stays intact.
		idx := indexAnyWhitespace(line)
		if idx < 0 {
			continue
		}
		hash := line[:idx]
		filename := strings.TrimLeft(line[idx:], " \t")
		// Optional leading '*' indicates binary mode.
		filename = strings.TrimPrefix(filename, "*")
		if !isHexString(hash) {
			continue
		}
		if strings.EqualFold(filename, assetName) {
			return hash
		}
	}
	return ""
}

var bsdChecksumLine = regexp.MustCompile(`^SHA256\s*\(\s*(.+?)\s*\)\s*=\s*([0-9a-fA-F]+)\s*$`)

func matchBSDChecksumLine(line, assetName string) string {
	m := bsdChecksumLine.FindStringSubmatch(line)
	if len(m) != 3 {
		return ""
	}
	if strings.EqualFold(m[1], assetName) {
		return m[2]
	}
	return ""
}

func indexAnyWhitespace(s string) int {
	for i, r := range s {
		if r == ' ' || r == '\t' {
			return i
		}
	}
	return -1
}

func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// matchAsset picks the release asset matching the running OS+arch.
// It prefers exact ".dmg/.zip/.exe/.tar.gz" extensions over auxiliary
// artifacts (debug symbols, manifests) when multiple candidates
// would match.
func matchAsset(assets []Asset) string {
	arch := runtime.GOARCH

	osNames := []string{runtime.GOOS}
	switch runtime.GOOS {
	case "darwin":
		osNames = append(osNames, "macos", "osx")
	case "windows":
		osNames = append(osNames, "win", "win64")
	}

	preferredExt := preferredExtensions(runtime.GOOS)

	// Pass 1: token-anchored OS+arch match with preferred extension.
	for _, ext := range preferredExt {
		for _, a := range assets {
			name := strings.ToLower(a.Name)
			if !strings.HasSuffix(name, ext) {
				continue
			}
			if assetMatchesOSArch(name, osNames, arch) {
				return a.Name
			}
		}
	}
	// Pass 2: token-anchored OS+arch with any extension (fallback
	// for releases that ship .pkg / .app.tar.gz / etc.).
	for _, a := range assets {
		name := strings.ToLower(a.Name)
		if assetMatchesOSArch(name, osNames, arch) {
			return a.Name
		}
	}
	return ""
}

func assetMatchesOSArch(name string, osNames []string, arch string) bool {
	hasArch := matchTokenAnchored(name, arch)
	if !hasArch {
		return false
	}
	for _, osn := range osNames {
		if matchTokenAnchored(name, osn) {
			return true
		}
	}
	return false
}

// matchTokenAnchored returns true if `token` appears in `name`
// surrounded by start-of-string / dash / underscore / dot on the
// left, and the same OR end-of-token-followed-by-extension on the
// right. Prevents `arm` matching inside `arm64` and similar.
func matchTokenAnchored(name, token string) bool {
	idx := 0
	for idx < len(name) {
		i := strings.Index(name[idx:], token)
		if i < 0 {
			return false
		}
		start := idx + i
		end := start + len(token)
		// Left boundary
		leftOK := start == 0
		if !leftOK {
			c := name[start-1]
			leftOK = c == '-' || c == '_' || c == '.'
		}
		// Right boundary
		rightOK := end == len(name)
		if !rightOK {
			c := name[end]
			rightOK = c == '-' || c == '_' || c == '.'
		}
		if leftOK && rightOK {
			return true
		}
		idx = start + 1
	}
	return false
}

// isCanonicalChecksumName matches only well-known checksum-file
// names (case-insensitive). New tooling tends to use one of these.
func isCanonicalChecksumName(name string) bool {
	switch strings.ToLower(name) {
	case "sha256sums", "sha256sums.txt", "checksums.txt", "checksums",
		"sha256.txt", "shasums":
		return true
	}
	return false
}

func preferredExtensions(goos string) []string {
	switch goos {
	case "darwin":
		return []string{".dmg", ".zip", ".pkg"}
	case "linux":
		return []string{".tar.gz", ".tar.xz", ".deb", ".rpm", ".appimage"}
	case "windows":
		return []string{".exe", ".msi", ".zip"}
	}
	return []string{".zip", ".tar.gz"}
}

// BrewPath returns the absolute path to the brew binary, or empty string
// if brew is not found. GUI apps launched from Finder may not have
// /opt/homebrew/bin in PATH, so we check common paths directly.
func BrewPath() string {
	for _, p := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// IsBrewInstall returns true if WireGuide was installed via Homebrew.
// Homebrew cask copies (not symlinks) the app to /Applications, so we
// can't rely on the binary path containing "homebrew". The presence
// of a Caskroom receipt directory is sufficient evidence that brew
// installed this app (the directory is created by brew itself); we
// don't additionally require `brew` to be in PATH because GUI apps
// launched from Finder may not have Homebrew's bin directory on
// their PATH while the install is still managed by brew.
func IsBrewInstall() bool {
	caskroomPaths := []string{
		"/opt/homebrew/Caskroom/wireguide",
		"/usr/local/Caskroom/wireguide",
	}
	for _, p := range caskroomPaths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}
