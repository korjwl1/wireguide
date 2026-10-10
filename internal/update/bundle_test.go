package update

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppBundleFromExe(t *testing.T) {
	good := filepath.Join(string(filepath.Separator)+"Applications", "WireGuide.app", "Contents", "MacOS", "wireguide")
	got, err := appBundleFromExe(good)
	if err != nil {
		t.Fatalf("appBundleFromExe(%q): %v", good, err)
	}
	if want := filepath.Join(string(filepath.Separator)+"Applications", "WireGuide.app"); got != want {
		t.Errorf("bundle = %q, want %q", got, want)
	}

	for _, bad := range []string{
		filepath.Join("repo", "bin", "wireguide"),
		filepath.Join("x", "WireGuide.app", "Contents", "Resources", "wireguide"),
		filepath.Join("x", "WireGuide", "Contents", "MacOS", "wireguide"),
		"wireguide",
	} {
		if _, err := appBundleFromExe(bad); err == nil {
			t.Errorf("appBundleFromExe(%q) accepted a non-bundle path", bad)
		}
	}
}

func TestIsTranslocated(t *testing.T) {
	if !isTranslocated("/private/var/folders/xy/T/AppTranslocation/1234-ABCD/d/WireGuide.app/Contents/MacOS/wireguide") {
		t.Error("translocated path not detected")
	}
	if isTranslocated("/Applications/WireGuide.app/Contents/MacOS/wireguide") {
		t.Error("/Applications flagged as translocated")
	}
}

func mkBundle(t *testing.T, dir, name, marker string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Join(p, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "Contents", "MacOS", "wireguide"), []byte(marker), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFindStagedBundle(t *testing.T) {
	t.Run("single bundle", func(t *testing.T) {
		dir := t.TempDir()
		want := mkBundle(t, dir, "wireguide.app", "new")
		// Noise ditto/Finder may leave behind must be ignored.
		_ = os.MkdirAll(filepath.Join(dir, "__MACOSX"), 0o755)
		_ = os.MkdirAll(filepath.Join(dir, ".hidden.app"), 0o755)
		got, err := findStagedBundle(dir)
		if err != nil || got != want {
			t.Fatalf("findStagedBundle = %q, %v; want %q", got, err, want)
		}
	})
	t.Run("no bundle", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "wireguide"), []byte("x"), 0o644)
		if _, err := findStagedBundle(dir); err == nil {
			t.Fatal("archive without a bundle accepted")
		}
	})
	t.Run("two bundles", func(t *testing.T) {
		dir := t.TempDir()
		mkBundle(t, dir, "wireguide.app", "a")
		mkBundle(t, dir, "Other.app", "b")
		if _, err := findStagedBundle(dir); err == nil {
			t.Fatal("ambiguous archive accepted")
		}
	})
}

func readMarker(t *testing.T, bundle string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(bundle, "Contents", "MacOS", "wireguide"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSwapBundle_ReplacesTarget(t *testing.T) {
	dir := t.TempDir()
	target := mkBundle(t, dir, "WireGuide.app", "old")
	staging := filepath.Join(dir, ".wireguide-update-x")
	staged := mkBundle(t, filepath.Join(staging, "new"), "wireguide.app", "new")
	backup := filepath.Join(staging, "previous.app")

	if err := swapBundle(staged, target, backup); err != nil {
		t.Fatal(err)
	}
	if got := readMarker(t, target); got != "new" {
		t.Errorf("target holds %q after swap, want new", got)
	}
	if got := readMarker(t, backup); got != "old" {
		t.Errorf("backup holds %q, want old", got)
	}
}

func TestSwapBundle_MissingStagedLeavesTargetAlone(t *testing.T) {
	dir := t.TempDir()
	target := mkBundle(t, dir, "WireGuide.app", "old")
	err := swapBundle(filepath.Join(dir, "nope.app"), target, filepath.Join(dir, "previous.app"))
	if err == nil {
		t.Fatal("swap with a missing staged bundle succeeded")
	}
	if got := readMarker(t, target); got != "old" {
		t.Errorf("target holds %q, want the untouched old app", got)
	}
}
