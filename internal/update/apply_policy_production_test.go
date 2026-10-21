//go:build production

package update

import (
	"context"
	"testing"
)

// Run with `go test -tags production ./internal/update/`. A production
// build that somehow lacks the embedded key must refuse to install even a
// checksum-consistent release (require_signed_release.go).
func TestApply_ProductionBuildWithoutKey_Refuses(t *testing.T) {
	restore := withTestPublicKey(t, "")
	defer restore()
	if expectedPublicKey != "" {
		t.Skip("binary was built with an embedded key; nothing to test")
	}
	newFakeRelease(t, nil)
	calls := stubPlatform(t, nil)

	if _, err := Apply(context.Background(), "99.0.0", nil); err == nil {
		t.Fatal("production build installed an unsigned release")
	}
	if len(*calls) != 0 {
		t.Fatal("platform installer ran without a signature")
	}
}

// Install itself re-checks the policy: a hash-verified but unsigned info
// is rejected in production builds.
func TestInstall_ProductionRequiresSignature(t *testing.T) {
	calls := stubPlatform(t, nil)
	info := &UpdateInfo{HashVerified: true, verifiedSHA256: "ab"}
	if _, err := Install(context.Background(), "x.exe", info); err == nil {
		t.Fatal("Install accepted an unsigned update in a production build")
	}
	if len(*calls) != 0 {
		t.Fatal("platform installer ran without a signature")
	}
}
