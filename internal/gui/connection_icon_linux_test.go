//go:build linux && cgo && !gtk3

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
	flags, err := exec.CommandContext(ctx, "pkg-config", "--cflags", "--libs", "gtk4").Output()
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

func TestNativeGTK4WebviewRoundTrip(t *testing.T) {
	if os.Getenv("WIREGUIDE_TEST_APP_ICON") != "1" {
		t.Skip("opt-in native GTK4/WebKitGTK/Xvfb integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	exe := filepath.Join(t.TempDir(), "gtk4-webview")
	if out, err := exec.CommandContext(ctx, "go", "build", "-tags", "production", "-o", exe, "./testdata/gtk4_webview").CombinedOutput(); err != nil {
		t.Fatalf("compile GTK4 webview fixture: %v\n%s", err, out)
	}
	cmd := exec.CommandContext(ctx, "xvfb-run", "-a", "dbus-run-session", "--", exe)
	cmd.Env = append(os.Environ(), "GDK_BACKEND=x11", "GSK_RENDERER=cairo", "LIBGL_ALWAYS_SOFTWARE=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native GTK4 webview: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
