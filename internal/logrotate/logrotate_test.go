package logrotate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriterRotatesAndCapsFiles(t *testing.T) {
	p := filepath.Join(t.TempDir(), "h.log")
	w, err := Open(p, 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	line := strings.Repeat("x", 39) + "\n" // 40 bytes
	for i := 0; i < 30; i++ {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"", ".1", ".2", ".3"} {
		fi, err := os.Stat(p + name)
		if err != nil {
			t.Fatalf("missing %q: %v", name, err)
		}
		if fi.Size() > 100 {
			t.Errorf("%q is %d bytes, over the cap", name, fi.Size())
		}
	}
	if _, err := os.Stat(p + ".4"); err == nil {
		t.Error("file count exceeded maxFiles")
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644", fi.Mode().Perm())
	}
}

func TestOpenRotatesOversizedExistingLog(t *testing.T) {
	p := filepath.Join(t.TempDir(), "h.log")
	if err := os.WriteFile(p, []byte(strings.Repeat("o", 500)), 0o644); err != nil {
		t.Fatal(err)
	}
	w, err := Open(p, 100, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if fi, _ := os.Stat(p); fi.Size() != 0 {
		t.Errorf("live log size = %d, want 0 after startup rotation", fi.Size())
	}
	if fi, err := os.Stat(p + ".1"); err != nil || fi.Size() != 500 {
		t.Errorf(".1 missing or wrong size: %v", err)
	}
}

func TestOpenKeepsSmallExistingLog(t *testing.T) {
	p := filepath.Join(t.TempDir(), "h.log")
	_ = os.WriteFile(p, []byte("old\n"), 0o644)
	w, err := Open(p, 100, 5)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("new\n"))
	w.Close()
	b, _ := os.ReadFile(p)
	if string(b) != "old\nnew\n" {
		t.Errorf("got %q", b)
	}
	if _, err := os.Stat(p + ".1"); err == nil {
		t.Error("unexpected rotation")
	}
}

func TestOpenRejectsBadLimits(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "x"), 0, 1); err == nil {
		t.Error("expected error")
	}
}
