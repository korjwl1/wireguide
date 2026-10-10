package update

import (
	"context"
	"fmt"
	"os"
	"testing"
)

// Progress phases reported by Apply. The frontend maps them to labels
// (see UpdateNotice.svelte); "install" is shared with the Homebrew path.
const (
	PhaseDownload = "download" // fetching + verifying the release asset
	PhaseInstall  = "install"  // running the installer / swapping the bundle
)

// testOverrideAPIEndpoint lets tests point the release lookup at an
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

// Apply runs the full direct-download update chain for a non-Homebrew
// install: re-fetch release metadata → download → verify (SHA256SUMS,
// plus its Ed25519 signature whenever a key is embedded, which
// production builds require) → install. Any verification failure aborts
// with an error; nothing unverified is ever executed or swapped in.
//
// wantVersion is the version the user agreed to install (from the banner
// the frontend showed) and is required. The release metadata is
// deliberately NOT taken from the frontend: the UpdateInfo it passes back
// is plain JSON, so Apply looks the release up again here (unconditional
// fetch — a rate-limit is an error, not "no update") and only proceeds if
// it still names wantVersion.
//
// Returns an error wrapping ErrSelfUpdateUnsupported (before any
// download) when this installation can't update itself; callers fall
// back to the Releases page in that case only.
func Apply(ctx context.Context, wantVersion string, progress func(phase string)) (*InstallResult, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if wantVersion == "" {
		return nil, fmt.Errorf("no update version given")
	}
	if err := SelfUpdateSupport(); err != nil {
		return nil, err
	}

	progress(PhaseDownload)
	res, err := CheckForUpdateConditional(ctx, "", "")
	if err != nil {
		return nil, fmt.Errorf("re-checking release: %w", err)
	}
	info := res.Info
	if info == nil || !info.Available {
		return nil, fmt.Errorf("no update available")
	}
	if info.Version != wantVersion {
		return nil, fmt.Errorf("latest release is now %s (expected %s) — check for updates again", info.Version, wantVersion)
	}

	path, err := DownloadUpdate(info)
	if err != nil {
		return nil, err
	}
	// On Windows the installer usually terminates this process before
	// Install returns; the installer waiter deletes the file then.
	defer os.Remove(path)

	progress(PhaseInstall)
	return Install(ctx, path, info)
}
