// Package update checks for new releases and handles auto-update.
package update

import (
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
	currentVersion = "0.2.0"

	// minAssetSize is the minimum acceptable size for a release asset.
	// A macOS .dmg/.zip containing WireGuide.app is always well over 1 MB;
	// anything smaller is almost certainly corrupted or a placeholder file
	// injected by an attacker.
	minAssetSize = 1 << 20 // 1 MB

	// expectedPublicKey is the hex-encoded Ed25519 public key whose
	// matching private key signs each release's SHA256SUMS file. The
	// signature lives next to SHA256SUMS as <SHA256SUMS>.sig (raw
	// 64-byte signature, no encoding).
	//
	// EMPTY UNTIL THE FIRST SIGNED RELEASE. While empty we fall back
	// to checksum-only authentication (SHA256SUMS itself can be
	// replaced by a compromised GitHub account, so this is a
	// degraded mode — flip the constant on the same release where
	// you ship the first SHA256SUMS.sig).
	//
	// Key generation, signing, and rotation procedure: see
	// docs/release.md.
	expectedPublicKey = ""
)

// CurrentVersion returns the hardcoded app version string.
func CurrentVersion() string { return currentVersion }

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

// CheckForUpdate queries GitHub Releases API for newer version.
func CheckForUpdate() (*UpdateInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(apiEndpoint)
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
		expectedHash = fetchExpectedHash(checksumURL, assetName, client)
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
func DownloadUpdate(info *UpdateInfo) (string, error) {
	if info.DownloadURL == "" {
		return "", fmt.Errorf("no download URL for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	// Defensive even though CheckForUpdate also rejects this — a
	// future caller might construct UpdateInfo by hand.
	if info.AssetSize <= 0 {
		return "", fmt.Errorf("refusing to download: invalid AssetSize %d", info.AssetSize)
	}

	client := &http.Client{Timeout: 5 * time.Minute}
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

	// Checksum verification is mandatory — refuse to install without it.
	if info.ExpectedHash == "" {
		os.Remove(destPath)
		return "", fmt.Errorf("refusing to install update: no checksum available for verification")
	}

	actual := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(actual, info.ExpectedHash) {
		os.Remove(destPath)
		return "", fmt.Errorf("checksum mismatch: expected %s, got %s", info.ExpectedHash, actual)
	}
	info.HashVerified = true

	// Ed25519 signature verification — defends against a compromised
	// GitHub account replacing both the asset AND its SHA256SUMS
	// entry. The private key signs SHA256SUMS once per release; one
	// .sig covers every asset transitively because each asset's hash
	// is in the file.
	if activePublicKey() != "" {
		if err := verifyChecksumSignature(info.ChecksumURL, client); err != nil {
			os.Remove(destPath)
			return "", fmt.Errorf("signature verification: %w", err)
		}
		info.SignatureVerified = true
	} else {
		slog.Warn("signature verification skipped: no public key embedded; falling back to SHA256-only authentication")
	}

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
// sibling, then verifies the signature against the embedded public
// key. We re-download SHA256SUMS (instead of reusing fetchExpectedHash's
// fetch) so this function is self-contained and easy to test without
// threading bytes through the rest of DownloadUpdate.
func verifyChecksumSignature(checksumURL string, client *http.Client) error {
	pubHex := activePublicKey()
	if pubHex == "" {
		// Caller already gated; defensive double-check.
		return nil
	}
	if checksumURL == "" {
		return fmt.Errorf("no SHA256SUMS URL on this release")
	}
	pk, err := hex.DecodeString(pubHex)
	if err != nil {
		return fmt.Errorf("malformed embedded public key: %w", err)
	}
	if len(pk) != ed25519.PublicKeySize {
		return fmt.Errorf("embedded public key size: got %d, want %d", len(pk), ed25519.PublicKeySize)
	}

	sumsBody, err := fetchSmall(checksumURL, client)
	if err != nil {
		return fmt.Errorf("download SHA256SUMS: %w", err)
	}
	// Build the .sig URL via url.Parse so a release-asset URL with
	// a query string (CDN-redirected, signed Cloudflare URLs, etc.)
	// gets ".sig" appended to the *path* and not after the query.
	sigURL, err := appendSigSuffix(checksumURL)
	if err != nil {
		return fmt.Errorf("compute .sig URL: %w", err)
	}
	sigBody, err := fetchSmall(sigURL, client)
	if err != nil {
		return fmt.Errorf("download SHA256SUMS.sig: %w", err)
	}

	return verifyEd25519(sumsBody, sigBody, pk)
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
func isNewerVersion(latest, current string) bool {
	parseParts := func(v string) []int {
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
func fetchExpectedHash(checksumURL, assetName string, client *http.Client) string {
	resp, err := client.Get(checksumURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return ""
	}
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
