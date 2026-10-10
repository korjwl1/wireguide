package update

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// Progress phases reported by Apply. The frontend maps them to labels
// (see UpdateNotice.svelte); "install" is shared with the Homebrew path.
const (
	PhaseDownload = "download" // fetching + verifying the release asset
	PhaseInstall  = "install"  // running the installer / swapping the bundle
)

// testOverrideAPIEndpoint lets tests point fetchLatestRelease at an
// httptest server. Same gating as testOverridePubKey: honoured only
// inside a `go test` binary, so a production build can never be steered
// at a different release feed.
var testOverrideAPIEndpoint = ""

func releaseAPIEndpoint() string {
	if testOverrideAPIEndpoint != "" && testing.Testing() {
		return testOverrideAPIEndpoint
	}
	return apiEndpoint
}

// fetchLatestRelease performs an unconditional (no ETag) release lookup
// and parses it with the same code the scheduler uses. Unlike
// CheckForUpdate it treats a non-200 as an error — Apply must not
// mistake a rate-limit for "no update".
func fetchLatestRelease(ctx context.Context) (*UpdateInfo, error) {
	client := newUpdateClient(10 * time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releaseAPIEndpoint(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("checking updates: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github returned HTTP %d", resp.StatusCode)
	}
	return parseReleaseBody(ctx, resp, client)
}

// Apply runs the full direct-download update chain for a non-Homebrew
// install: re-fetch release metadata → download → verify (SHA256SUMS,
// plus its Ed25519 signature whenever a key is embedded, which
// production builds require) → install. Any verification failure aborts
// with an error; nothing unverified is ever executed or swapped in.
//
// wantVersion is the version the user agreed to install (from the banner
// the frontend showed). The release metadata is deliberately NOT taken
// from the frontend: the UpdateInfo it passes back is plain JSON, so
// Apply looks the release up again here and only proceeds if it still
// names wantVersion.
//
// Returns an error wrapping ErrSelfUpdateUnsupported (before any
// download) when this installation can't update itself; callers fall
// back to the Releases page in that case only.
func Apply(ctx context.Context, wantVersion string, progress func(phase string)) (*InstallResult, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if err := SelfUpdateSupport(); err != nil {
		return nil, err
	}

	progress(PhaseDownload)
	info, err := fetchLatestRelease(ctx)
	if err != nil {
		return nil, fmt.Errorf("re-checking release: %w", err)
	}
	if info == nil || !info.Available {
		return nil, fmt.Errorf("no update available")
	}
	if wantVersion != "" && info.Version != wantVersion {
		return nil, fmt.Errorf("latest release is now %s (expected %s) — check for updates again", info.Version, wantVersion)
	}

	path, err := DownloadUpdate(info)
	if err != nil {
		return nil, err
	}
	// On Windows the installer usually terminates this process before
	// Install returns, so the temp file can outlive us; that's harmless
	// (it's in the user's temp dir and verified content).
	defer os.Remove(path)

	progress(PhaseInstall)
	return Install(ctx, path, info)
}
