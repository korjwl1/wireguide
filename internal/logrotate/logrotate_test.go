package logrotate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o644 {
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

func TestLimiter(t *testing.T) {
	l := NewLimiter(60 * time.Second)
	t0 := time.Unix(1000, 0)
	if ok, _ := l.Allow("k", "m", t0); !ok {
		t.Fatal("first must pass")
	}
	for i := 1; i <= 5; i++ {
		if ok, _ := l.Allow("k", "m", t0.Add(time.Duration(i)*time.Second)); ok {
			t.Fatal("repeat within window must be suppressed")
		}
	}
	if ok, _ := l.Allow("other", "m", t0.Add(time.Second)); !ok {
		t.Fatal("different key passes")
	}
	ok, s := l.Allow("k", "m", t0.Add(61*time.Second))
	if !ok || s != 5 {
		t.Fatalf("after window: ok=%v suppressed=%d, want true 5", ok, s)
	}
}

func TestLimiterExpiredSummary(t *testing.T) {
	l := NewLimiter(time.Minute)
	t0 := time.Unix(0, 0)
	l.Allow("k", "raw message", t0)
	l.Allow("k", "raw message", t0.Add(time.Second))
	if got := l.Expired(t0.Add(30 * time.Second)); len(got) != 0 {
		t.Errorf("not expired yet: %v", got)
	}
	got := l.Expired(t0.Add(2 * time.Minute))
	if len(got) != 1 || got[0].Count != 1 || got[0].Message != "raw message" {
		t.Errorf("got %v", got)
	}
	if got := l.Expired(t0.Add(4 * time.Minute)); len(got) != 0 {
		t.Errorf("summary must be emitted once: %v", got)
	}
}

// Flushing a summary must not delay the real warning: the next occurrence
// after the window passes immediately.
func TestLimiterExpiredDoesNotSuppressNextWarning(t *testing.T) {
	l := NewLimiter(time.Minute)
	t0 := time.Unix(0, 0)
	l.Allow("k", "m", t0)
	l.Allow("k", "m", t0.Add(time.Second))
	later := t0.Add(2 * time.Minute)
	if got := l.Expired(later); len(got) != 1 {
		t.Fatalf("Expired = %v, want one summary", got)
	}
	if ok, _ := l.Allow("k", "m", later.Add(time.Second)); !ok {
		t.Fatal("warning must pass right after the window, not wait another window")
	}
}

func TestNormalizeKey(t *testing.T) {
	a := NormalizeKey("[wg:utun4] write udp4 1.2.3.4:5->6.7.8.9:51820: network is unreachable")
	b := NormalizeKey("[wg:utun4] write udp4 10.0.0.1:55->6.7.8.10:51821: network is unreachable")
	if a != b {
		t.Errorf("%q != %q", a, b)
	}
}

// Each tunnel interface keeps its own key, so one tunnel's warning never
// suppresses another's identical one.
func TestNormalizeKeyKeepsInterfacePrefix(t *testing.T) {
	a := NormalizeKey("[wg:utun4] Failed to send: network is unreachable")
	b := NormalizeKey("[wg:utun5] Failed to send: network is unreachable")
	if a == b {
		t.Errorf("different interfaces share key %q", a)
	}
	if !strings.HasPrefix(a, "[wg:utun4] ") {
		t.Errorf("prefix not kept verbatim: %q", a)
	}
}
