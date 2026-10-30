package autostart

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMacAutostartPlistGolden(t *testing.T) {
	got := macAutostartPlist("/Applications/WireGuide.app/Contents/MacOS/wireguide")
	const want = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.wireguide.gui</string>
    <key>AssociatedBundleIdentifiers</key>
    <array>
        <string>com.korjwl1.wireguide</string>
    </array>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/WireGuide.app/Contents/MacOS/wireguide</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
`
	if got != want {
		t.Fatalf("LaunchAgent plist drifted:\n%s", got)
	}
	if !strings.Contains(got, "<string>com.korjwl1.wireguide</string>") {
		t.Fatal("AssociatedBundleIdentifiers must name the app bundle id")
	}
}

// An upgraded user's LaunchAgent written before AssociatedBundleIdentifiers
// existed is rewritten; an up-to-date one is left alone; a missing one is
// never created.
func TestSyncMacAutostartFile(t *testing.T) {
	const exe = "/Applications/WireGuide.app/Contents/MacOS/wireguide"
	dir := t.TempDir()
	path := filepath.Join(dir, "com.wireguide.gui.plist")

	if changed, err := syncMacAutostartFile(path, exe); err != nil || changed {
		t.Fatalf("missing file: changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("sync must not create a LaunchAgent the user removed")
	}

	const old = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.wireguide.gui</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/WireGuide.app/Contents/MacOS/wireguide</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
`
	if err := os.WriteFile(path, []byte(old), 0644); err != nil {
		t.Fatal(err)
	}
	changed, err := syncMacAutostartFile(path, exe)
	if err != nil || !changed {
		t.Fatalf("old plist: changed=%v err=%v", changed, err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != macAutostartPlist(exe) || !strings.Contains(string(got), "AssociatedBundleIdentifiers") {
		t.Fatalf("rewritten plist:\n%s", got)
	}

	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0644 {
		t.Fatalf("rewritten plist mode = %v, err = %v, want 0644", fi.Mode().Perm(), err)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".wireguide-*.tmp")); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}

	if changed, err := syncMacAutostartFile(path, exe); err != nil || changed {
		t.Fatalf("up-to-date plist must not be rewritten: changed=%v err=%v", changed, err)
	}

	// A copy running from elsewhere (DMG, translocation, second install)
	// must never retarget the login item.
	if err := os.WriteFile(path, []byte(old), 0644); err != nil {
		t.Fatal(err)
	}
	const other = "/Volumes/WireGuide/WireGuide.app/Contents/MacOS/wireguide"
	if changed, err := syncMacAutostartFile(path, other); err != nil || changed {
		t.Fatalf("plist for another binary must be left alone: changed=%v err=%v", changed, err)
	}
	if got, _ := os.ReadFile(path); string(got) != old {
		t.Fatalf("plist for another binary was modified:\n%s", got)
	}
}

func TestSyncAutostartIgnoresNonBundleBinary(t *testing.T) {
	if changed, err := SyncAutostart("/Users/dev/go/bin/wireguide"); err != nil || changed {
		t.Fatalf("a binary outside an app bundle must never be synced: changed=%v err=%v", changed, err)
	}
}
