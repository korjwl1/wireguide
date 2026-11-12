package elevate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnsignedBareIntelHelperSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "main.c")
	if err := os.WriteFile(src, []byte("int main(void) { return 0; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "unsigned-intel")
	if out, err := exec.Command("/usr/bin/clang", "-arch", "x86_64", "-mmacosx-version-min=12.0", src, "-o", exe).CombinedOutput(); err != nil {
		t.Fatalf("compile unsigned Intel fixture: %v: %s", err, out)
	}
	if out, err := exec.Command("/usr/bin/codesign", "--verify", "--strict", exe).CombinedOutput(); err == nil || !strings.Contains(string(out), "not signed at all") {
		t.Fatalf("fixture must be unsigned: %v: %s", err, out)
	}
	if err := validateDaemonSource(context.Background(), exe); err != nil {
		t.Fatalf("bare Intel development binary rejected: %v", err)
	}
}

func TestDaemonSource(t *testing.T) {
	for _, kind := range []string{"bundled", "missing", "directory", "not executable", "symlink", "standalone", "symlink to GUI"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			exe := filepath.Join(dir, "WireGuide.app/Contents/MacOS/wireguide")
			helper := filepath.Join(dir, "WireGuide.app/Contents/Library/LaunchServices", daemonLabel)
			if kind == "standalone" {
				exe = filepath.Join(dir, "wireguide")
			}
			if err := os.MkdirAll(filepath.Dir(exe), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(exe, []byte("gui"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(helper), 0700); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing", "standalone":
			case "directory":
				if err := os.Mkdir(helper, 0700); err != nil {
					t.Fatal(err)
				}
			case "not executable":
				if err := os.WriteFile(helper, []byte("helper"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(exe, helper); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(helper, []byte("helper"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			input := exe
			if kind == "symlink to GUI" {
				input = filepath.Join(dir, "cli-link")
				if err := os.Symlink(exe, input); err != nil {
					t.Fatal(err)
				}
			}
			got, err := daemonSource(input)
			valid := kind == "bundled" || kind == "standalone" || kind == "symlink to GUI"
			if !valid {
				if err == nil {
					t.Fatalf("accepted %s helper: %s", kind, got)
				}
				return
			}
			want := helper
			if kind == "standalone" {
				want = exe
			}
			want, resolveErr := filepath.EvalSymlinks(want)
			if resolveErr != nil {
				t.Fatal(resolveErr)
			}
			if err != nil || got != want {
				t.Fatalf("source = %q, %v; want %q", got, err, want)
			}
		})
	}
}
