//go:build !production

package update

import (
	"context"
	"strings"
	"testing"
)

// Dev builds (no `production` tag, no embedded key) follow
// require_signed_dev.go: SHA256SUMS is still mandatory, the signature is
// not. The counterpart in apply_policy_production_test.go pins that a
// production build refuses the same release.
func TestApply_DevBuildWithoutKey_ChecksumOnly(t *testing.T) {
	restore := withTestPublicKey(t, "")
	defer restore()
	newFakeRelease(t, nil) // unsigned: .sig is 404
	calls := stubPlatform(t, nil)

	if _, err := Apply(context.Background(), "99.0.0", nil); err != nil {
		t.Fatalf("dev build should accept a checksum-verified release: %v", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("platform installer called %d times, want 1", len(*calls))
	}
	if c := (*calls)[0].info; !c.HashVerified || c.SignatureVerified {
		t.Errorf("want hash verified, signature not: hash=%v sig=%v", c.HashVerified, c.SignatureVerified)
	}
}

// Even in a dev build, a release without a usable SHA256SUMS entry is
// never installed.
func TestApply_DevBuildWithoutKey_NoChecksumRefused(t *testing.T) {
	restore := withTestPublicKey(t, "")
	defer restore()
	fr := newFakeRelease(t, nil)
	fr.sums = []byte(strings.Repeat("a", 64) + "  unrelated.bin\n")
	calls := stubPlatform(t, nil)

	_, err := Apply(context.Background(), "99.0.0", nil)
	if err == nil || !strings.Contains(err.Error(), "no checksum available") {
		t.Fatalf("err = %v, want 'no checksum available'", err)
	}
	if len(*calls) != 0 {
		t.Fatal("platform installer ran without a checksum")
	}
}
