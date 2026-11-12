package elevate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNativePackagedHelperSignature(t *testing.T) {
	task, err := exec.LookPath("task")
	if err != nil {
		t.Skip("task is required for the native packaging fixture")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.c")
	if err := os.WriteFile(src, []byte("int main(void) { return 0; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	raw := filepath.Join(dir, "wireguide")
	run := func(name string, args ...string) {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	run("/usr/bin/clang", "-mmacosx-version-min=12.0", src, "-o", raw)
	run(task, "--taskfile", filepath.Join(root, "Taskfile.yml"), "darwin:create:app:bundle", "BIN_DIR="+dir, "APP_NAME=wireguide")
	bundle := filepath.Join(dir, "wireguide.app")
	run("/usr/bin/codesign", "--verify", "--deep", "--strict", "--all-architectures", bundle)
	helper := filepath.Join(bundle, "Contents/Library/LaunchServices/com.wireguide.helper")
	run("/usr/bin/codesign", "--verify", "--strict", "--all-architectures", helper)
	helper, err = filepath.EvalSymlinks(helper)
	if err != nil {
		t.Fatal(err)
	}
	guiPath := filepath.Join(bundle, "Contents/MacOS/wireguide")
	source, err := daemonSource(guiPath)
	if err != nil || source != helper {
		t.Fatalf("helper source = %q, %v; want %q", source, err, helper)
	}
	if err := validateDaemonSource(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(dir, "installed-helper")
	if err := os.WriteFile(installed, data, 0755); err != nil {
		t.Fatal(err)
	}
	run("/usr/bin/codesign", "--verify", "--strict", "--all-architectures", installed)
	gui, err := os.ReadFile(guiPath)
	if err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, "legacy-helper")
	if err := os.WriteFile(legacy, gui, 0755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/codesign", "--verify", "--strict", legacy).CombinedOutput(); err == nil {
		t.Fatalf("fixture did not reproduce invalid standalone GUI signature: %s", out)
	}
	plist := filepath.Join(dir, "helper.plist")
	const wantPlist = "fixture plist"
	if err := os.WriteFile(plist, []byte(wantPlist), 0600); err != nil {
		t.Fatal(err)
	}
	if !daemonUpToDateAt(source, wantPlist, installed, plist) {
		t.Fatal("unchanged standalone helper needs reinstall")
	}
	if daemonUpToDateAt(source, wantPlist, legacy, plist) {
		t.Fatal("legacy bundled-GUI copy was accepted as up to date")
	}
	if daemonUpToDateAt(source, "different plist", installed, plist) {
		t.Fatal("changed plist was accepted as up to date")
	}
	run("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", "fixture.impostor", raw)
	run("/usr/bin/codesign", "--verify", "--strict", raw)
	impostor, err := os.ReadFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(helper); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(helper, impostor, 0755); err != nil {
		t.Fatal(err)
	}
	if err := validateDaemonSource(context.Background(), helper); err == nil {
		t.Fatal("accepted a separately valid helper that broke the app bundle signature")
	}
}
