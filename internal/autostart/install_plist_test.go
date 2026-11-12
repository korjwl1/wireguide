package autostart

import (
	"os"
	"path/filepath"
	"runtime"
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

const syncTestExe = "/Applications/WireGuide.app/Contents/MacOS/wireguide"

// syncOnce writes content to a temp LaunchAgent, runs the sync for appPath and
// returns whether it rewrote the file plus the resulting bytes.
func syncOnce(t *testing.T, content, appPath string) (bool, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "com.wireguide.gui.plist")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	changed, err := syncMacAutostartFile(path, appPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return changed, string(got)
}

func TestSyncMacAutostartFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "com.wireguide.gui.plist")
	if changed, err := syncMacAutostartFile(path, syncTestExe); err != nil || changed {
		t.Fatalf("missing file: changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("sync must not create a LaunchAgent the user removed")
	}
}

// Every plist an earlier release generated for this appPath is migrated to
// the current template.
func TestSyncMacAutostartFileMigratesGeneratedTemplates(t *testing.T) {
	for _, appPath := range []string{syncTestExe, "/Applications/Wire & Guide.app/Contents/MacOS/wireguide"} {
		legacy, err := legacyMacAutostartPlists(appPath)
		if err != nil {
			t.Fatal(err)
		}
		if len(legacy) < 2 {
			t.Fatalf("expected at least two historical templates, got %d", len(legacy))
		}
		want, _ := renderMacAutostart(appPath)
		for i, l := range legacy {
			changed, got := syncOnce(t, l, appPath)
			if !changed || got != want {
				t.Fatalf("template %d for %q: changed=%v, got:\n%s", i, appPath, changed, got)
			}
			if !strings.Contains(got, "AssociatedBundleIdentifiers") {
				t.Fatalf("template %d not migrated", i)
			}
		}
	}
}

func TestSyncMacAutostartFileWriteDetails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "com.wireguide.gui.plist")
	legacy, _ := legacyMacAutostartPlists(syncTestExe)
	if err := os.WriteFile(path, []byte(legacy[1]), 0644); err != nil {
		t.Fatal(err)
	}
	if changed, err := syncMacAutostartFile(path, syncTestExe); err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0644 {
		t.Fatalf("rewritten plist mode = %v, want 0644", fi.Mode().Perm())
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".wireguide-*.tmp")); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
	if changed, err := syncMacAutostartFile(path, syncTestExe); err != nil || changed {
		t.Fatalf("up-to-date plist must not be rewritten: changed=%v err=%v", changed, err)
	}
}

// Anything that is not a byte-identical generated template belongs to the
// user and must be left alone.
func TestSyncMacAutostartFileLeavesOtherPlistsAlone(t *testing.T) {
	legacy, _ := legacyMacAutostartPlists(syncTestExe)
	base := legacy[1]
	cur, _ := renderMacAutostart(syncTestExe)

	withArgs := func(args string) string {
		return strings.Replace(base, "        <string>"+syncTestExe+"</string>\n", args, 1)
	}
	cases := map[string]string{
		"current template": cur,
		"wrapper executable": withArgs("        <string>/usr/local/bin/wrapper</string>\n" +
			"        <string>" + syncTestExe + "</string>\n"),
		"Program overrides ProgramArguments[0]": strings.Replace(base,
			"    <key>ProgramArguments</key>",
			"    <key>Program</key>\n    <string>/usr/local/bin/other</string>\n    <key>ProgramArguments</key>", 1),
		"path only in an XML comment": strings.Replace(base,
			"        <string>"+syncTestExe+"</string>",
			"        <string>/usr/local/bin/other</string>\n        <!-- <string>"+syncTestExe+"</string> -->", 1),
		"historical template plus a custom key": strings.Replace(base,
			"</dict>", "    <key>EnvironmentVariables</key>\n    <dict>\n        <key>FOO</key>\n        <string>bar</string>\n    </dict>\n</dict>", 1),
		"empty file": "",
	}
	for name, content := range cases {
		changed, got := syncOnce(t, content, syncTestExe)
		if changed || got != content {
			t.Errorf("%s: changed=%v, file modified:\n%s", name, changed, got)
		}
	}

	// A recognised template for a different install (second copy, DMG,
	// translocation) must never be retargeted.
	const other = "/Volumes/WireGuide/WireGuide.app/Contents/MacOS/wireguide"
	for i, l := range legacy {
		if changed, got := syncOnce(t, l, other); changed || got != l {
			t.Errorf("template %d for another install: changed=%v, file modified", i, changed)
		}
	}
}

func TestSyncAutostartIgnoresNonBundleBinary(t *testing.T) {
	if changed, err := SyncAutostart("/Users/dev/go/bin/wireguide"); err != nil || changed {
		t.Fatalf("a binary outside an app bundle must never be synced: changed=%v err=%v", changed, err)
	}
}
