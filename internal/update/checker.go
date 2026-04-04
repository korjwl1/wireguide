// Package update checks for new releases and handles auto-update.
package update

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	githubRepo  = "korjwl1/wireguide"
	apiEndpoint = "https://api.github.com/repos/" + githubRepo + "/releases/latest"
	currentVersion = "0.2.0"
)

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
	Available   bool   `json:"available"`
	Version     string `json:"version"`
	CurrentVer  string `json:"current_version"`
	ReleaseURL  string `json:"release_url"`
	DownloadURL string `json:"download_url"`
	ReleaseNotes string `json:"release_notes"`
	AssetName   string `json:"asset_name"`
	AssetSize   int64  `json:"asset_size"`
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
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	latestVer := strings.TrimPrefix(release.TagName, "v")
	if latestVer <= currentVersion {
		return &UpdateInfo{Available: false, CurrentVer: currentVersion}, nil
	}

	// Find matching asset for current OS/arch
	assetName := matchAsset(release.Assets)
	downloadURL := ""
	var assetSize int64
	for _, a := range release.Assets {
		if a.Name == assetName {
			downloadURL = a.BrowserDownloadURL
			assetSize = a.Size
			break
		}
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
	}, nil
}

// DownloadUpdate downloads the release asset to a temp directory.
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

	tmpDir := os.TempDir()
	destPath := filepath.Join(tmpDir, info.AssetName)
	f, err := os.Create(destPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return "", err
	}

	return destPath, nil
}

func matchAsset(assets []Asset) string {
	os := runtime.GOOS
	arch := runtime.GOARCH

	// Expected naming: wireguide-{os}-{arch}.{ext}
	patterns := []string{
		fmt.Sprintf("wireguide-%s-%s", os, arch),
		fmt.Sprintf("wireguide_%s_%s", os, arch),
	}

	for _, a := range assets {
		name := strings.ToLower(a.Name)
		for _, p := range patterns {
			if strings.Contains(name, p) {
				return a.Name
			}
		}
	}
	return ""
}
