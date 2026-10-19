//go:build linux && cgo && !gtk4

package gui

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeApplicationConnectionIcon(t *testing.T) {
	if os.Getenv("WIREGUIDE_TEST_APP_ICON") != "1" {
		t.Skip("opt-in native GTK/Xvfb integration")
	}
	source, err := os.ReadFile("../../build/appicon.png")
	if err != nil {
		t.Fatal(err)
	}
	images, err := buildConnectionIconImages(source)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, data := range map[string][]byte{"base.png": images.base, "connected.png": images.connected} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	flags, err := exec.CommandContext(ctx, "pkg-config", "--cflags", "--libs", "gtk+-3.0").Output()
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "probe")
	args := append([]string{"testdata/native_connection_icon_linux_probe.c", "-o", exe}, strings.Fields(string(flags))...)
	if out, err := exec.CommandContext(ctx, "cc", args...).CombinedOutput(); err != nil {
		t.Fatalf("compile GTK fixture: %v\n%s", err, out)
	}
	if out, err := exec.CommandContext(ctx, "xvfb-run", "-a", exe, filepath.Join(dir, "base.png"), filepath.Join(dir, "connected.png")).CombinedOutput(); err != nil {
		t.Fatalf("native GTK icon: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
