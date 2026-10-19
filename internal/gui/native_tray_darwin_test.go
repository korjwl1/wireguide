//go:build darwin

package gui

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/wailsapp/wails/v3/pkg/icons"
)

// A standalone Cocoa process uses the production Objective-C bridge and
// actual NSStatusItem/NSMenu. It never starts a VPN or privileged helper.
func TestNativeStatusItemMenuLifecycle(t *testing.T) {
	if os.Getenv("WIREGUIDE_TEST_TRAY") != "1" {
		t.Skip("requires a logged-in macOS desktop")
	}
	dir := t.TempDir()
	icon := filepath.Join(dir, "icon.png")
	if err := os.WriteFile(icon, icons.SystrayMacTemplate, 0600); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(dir, "probe")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "clang", "-framework", "Cocoa", "-fblocks", "testdata/native_tray_probe.m", "-o", probe).CombinedOutput(); err != nil {
		t.Fatalf("compile Cocoa fixture: %v\n%s", err, out)
	}
	if out, err := exec.CommandContext(ctx, probe, icon).CombinedOutput(); err != nil {
		t.Fatalf("native tray lifecycle: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
