// Package update checks for new releases and handles auto-update.
package update

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	githubRepo     = "korjwl1/wireguide"
	apiEndpoint    = "https://api.github.com/repos/" + githubRepo + "/releases/latest"
	currentVersion = "0.1.3"
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
	ChecksumURL  string `json:"checksum_url,omitempty"`  // URL to SHA256SUMS file
	ExpectedHash string `json:"expected_hash,omitempty"` // pre-parsed SHA256 for this asset
	HashVerified bool   `json:"hash_verified"`           // set to true after successful checksum verification
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
		// Look for checksum file (SHA256SUMS, checksums.txt, etc.)
		lower := strings.ToLower(a.Name)
		if strings.Contains(lower, "sha256") || strings.Contains(lower, "checksum") {
			checksumURL = a.BrowserDownloadURL
		}
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

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(info.DownloadURL)
	if err != nil {
		return "", fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
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
	if _, err := io.Copy(writer, limitedBody); err != nil {
		f.Close()
		os.Remove(destPath)
		return "", err
	}
	f.Close()

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

	// TODO: Add minisign/Ed25519 signature verification.
	// After checksum passes, download <asset>.minisig from the release and
	// verify against an embedded public key. Until signing infrastructure is
	// in place, log a warning so operators are aware.
	slog.Warn("signature verification not yet implemented — update authenticated by SHA256 checksum only")

	return destPath, nil
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

// fetchExpectedHash downloads a SHA256SUMS-style file and extracts the hash
// for the given asset name. Format: "<hex-hash>  <filename>" per line.
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
		parts := strings.Fields(line)
		if len(parts) == 2 && strings.EqualFold(parts[1], assetName) {
			return parts[0]
		}
	}
	return ""
}

func matchAsset(assets []Asset) string {
	arch := runtime.GOARCH

	// Map Go OS names to common release naming conventions.
	osNames := []string{runtime.GOOS}
	switch runtime.GOOS {
	case "darwin":
		osNames = append(osNames, "macos", "osx")
	case "windows":
		osNames = append(osNames, "win", "win64")
	}

	for _, a := range assets {
		name := strings.ToLower(a.Name)
		for _, osn := range osNames {
			if strings.Contains(name, osn) && strings.Contains(name, arch) {
				return a.Name
			}
		}
	}
	return ""
}

// IsBrewInstall returns true if the running binary appears to be managed
// by Homebrew (lives under a Homebrew Cellar/Caskroom path).
func IsBrewInstall() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		resolved = exe
	}
	lower := strings.ToLower(resolved)
	return strings.Contains(lower, "homebrew") || strings.Contains(lower, "cellar") || strings.Contains(lower, "caskroom")
}
