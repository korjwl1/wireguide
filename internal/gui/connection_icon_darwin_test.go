package gui

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeApplicationConnectionIcon(t *testing.T) {
	if os.Getenv("WIREGUIDE_TEST_APP_ICON") != "1" {
		t.Skip("requires a logged-in macOS desktop")
	}
	dir, err := os.MkdirTemp("/private/tmp", "wg-app-icon-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	contents := filepath.Join(dir, "Connection Icon Test.app", "Contents")
	for _, part := range []string{"MacOS", "Resources"} {
		if err := os.MkdirAll(filepath.Join(contents, part), 0700); err != nil {
			t.Fatal(err)
		}
	}
	plist := `<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.wireguide.native-icon-test</string><key>CFBundleName</key><string>Connection Icon Test</string><key>CFBundleExecutable</key><string>probe</string><key>CFBundleIconFile</key><string>icons</string><key>LSUIElement</key><true/></dict></plist>`
	icon, err := os.ReadFile("../../build/darwin/icons.icns")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(contents, "Resources", "icons.icns"), icon, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(contents, "Info.plist"), []byte(plist), 0600); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(contents, "MacOS", "probe")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "clang", "-framework", "Cocoa", "testdata/native_connection_icon_probe.m", "connection_icon_darwin.m", "-o", exe).CombinedOutput(); err != nil {
		t.Fatalf("compile native icon fixture: %v\n%s", err, out)
	}
	if out, err := exec.CommandContext(ctx, exe).CombinedOutput(); err != nil {
		t.Fatalf("native application icon: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
