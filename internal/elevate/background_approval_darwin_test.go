//go:build darwin && cgo

package elevate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The child queries the actual framework, then replaces only its in-process
// status method to exercise denied/unknown states without changing OS policy.
func TestNativeBackgroundApproval(t *testing.T) {
	if os.Getenv("WIREGUIDE_TEST_BTM") != "1" {
		t.Skip("set WIREGUIDE_TEST_BTM=1 for the native ServiceManagement probe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	exe := filepath.Join(t.TempDir(), "approval-probe")
	if out, err := exec.CommandContext(ctx, "clang", "-mmacosx-version-min=12.0", "-framework", "Foundation", "-framework", "ServiceManagement", "testdata/native_background_approval_probe.m", "background_approval_darwin.m", "-o", exe).CombinedOutput(); err != nil {
		t.Fatalf("compile approval probe: %v\n%s", err, out)
	}
	out, err := exec.CommandContext(ctx, exe).CombinedOutput()
	if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 77 {
		t.Skip("ServiceManagement approval queries require macOS 13+")
	}
	if err != nil {
		t.Fatalf("native approval probe: %v\n%s", err, out)
	}
	t.Log(string(out))
}
