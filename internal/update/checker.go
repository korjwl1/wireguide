// Package update checks for new releases and handles auto-update.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	githubRepo     = "korjwl1/wireguide"
	apiEndpoint    = "https://api.github.com/repos/" + githubRepo + "/releases/latest"
	currentVersion = "0.5.2"

	// minAssetSize is the minimum acceptable size for a release asset.
	// A macOS .dmg/.zip containing WireGuide.app is always well over 1 MB;
	// anything smaller is almost certainly corrupted or a placeholder file
	// injected by an attacker.
	minAssetSize = 1 << 20 // 1 MB

)

// expectedPublicKey is the hex Ed25519 public key injected with -ldflags -X.
// Tagged release builds require signed SHA256SUMS; untagged development builds
// can use checksum-only verification when no key is embedded.
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
	Available         bool   `json:"available"`
	Version           string `json:"version"`
	CurrentVer        string `json:"current_version"`
	ReleaseURL        string `json:"release_url"`
	DownloadURL       string `json:"download_url"`
	ReleaseNotes      string `json:"release_notes"`
	AssetName         string `json:"asset_name"`
	AssetSize         int64  `json:"asset_size"`
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
	"api.github.com":                       true,
	"github.com":                           true,
	"objects.githubusercontent.com":        true,
	"release-assets.githubusercontent.com": true,
	"codeload.github.com":                  true,
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

	return parseReleaseBody(ctx, resp, client)
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
