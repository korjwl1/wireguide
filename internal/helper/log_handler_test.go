package helper

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/logrotate"
)

func TestBroadcastHandlerRateLimitsEngineWarnings(t *testing.T) {
	var buf bytes.Buffer
	lv := new(slog.LevelVar)
	l := slog.New(newBroadcastHandlerTo(lv, func() func(string, interface{}) { return nil }, &buf))
	for i := 0; i < 50; i++ {
		l.Warn("[wg:utun4] Failed to send data packet: write udp4 1.2.3.4:5->6.7.8.9:51820: network is unreachable")
	}
	l.Warn("something else")
	l.Info("[wg:utun4] info is not limited")
	l.Info("[wg:utun4] info is not limited")
	out := buf.String()
	if n := strings.Count(out, "network is unreachable"); n != 1 {
		t.Errorf("engine warning logged %d times, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, "something else") {
		t.Error("unrelated warning dropped")
	}
	if n := strings.Count(out, "info is not limited"); n != 2 {
		t.Errorf("info lines = %d, want 2", n)
	}
}

func TestBroadcastHandlerRepeatsRealWarningWithSuppressedCount(t *testing.T) {
	var buf bytes.Buffer
	lv := new(slog.LevelVar)
	h := newBroadcastHandlerTo(lv, func() func(string, interface{}) { return nil }, &buf)
	now := time.Unix(1000, 0)
	h.clock = func() time.Time { return now }
	l := slog.New(h)
	for i := 0; i < 300; i++ {
		l.Warn("[wg:utun4] Failed to send: write udp4 1.2.3.4:5->6.7.8.9:51820: network is unreachable")
		now = now.Add(time.Second)
	}
	out := buf.String()
	if n := strings.Count(out, "network is unreachable"); n != 5 {
		t.Errorf("real warning logged %d times over 300s, want 5:\n%s", n, out)
	}
	if n := strings.Count(out, "suppressed_repeats=59"); n != 4 {
		t.Errorf("suppressed_repeats=59 lines = %d, want 4:\n%s", n, out)
	}
	if strings.Contains(out, "suppressed repeated engine warnings") {
		t.Errorf("unexpected trailing summary while the warning keeps recurring:\n%s", out)
	}
}

// A suppressed warning that never recurs must still surface a summary, through
// the same emit path as everything else so the LogViewer broadcast sees it.
func TestBroadcastHandlerTrailingSummaryReachesBroadcast(t *testing.T) {
	var buf bytes.Buffer
	var broadcast []ipc.LogEntry
	bc := func(method string, params interface{}) {
		if e, ok := params.(ipc.LogEntry); ok && method == ipc.EventLog {
			broadcast = append(broadcast, e)
		}
	}
	h := newBroadcastHandlerTo(new(slog.LevelVar), func() func(string, interface{}) { return bc }, &buf)
	now := time.Unix(1000, 0)
	h.clock = func() time.Time { return now }
	l := slog.New(h)
	for i := 0; i < 4; i++ {
		l.Warn("[wg:utun4] Failed to send: network is unreachable")
	}
	now = now.Add(2 * time.Minute)
	l.Info("unrelated line")

	if !strings.Contains(buf.String(), "suppressed repeated engine warnings") || !strings.Contains(buf.String(), "count=3") {
		t.Errorf("summary missing from file output:\n%s", buf.String())
	}
	var sawSummary bool
	for _, e := range broadcast {
		if strings.Contains(e.Message, "suppressed repeated engine warnings") && strings.Contains(e.Message, "count=3") {
			sawSummary = true
		}
	}
	if !sawSummary {
		t.Errorf("summary not broadcast: %+v", broadcast)
	}
	if n := strings.Count(buf.String(), "network is unreachable"); n != 2 { // first line + summary's message attr
		t.Errorf("occurrences = %d, want 2:\n%s", n, buf.String())
	}
}

// Dropped repeats must not be broadcast either.
func TestBroadcastHandlerDropsRepeatsFromBroadcast(t *testing.T) {
	var n int
	bc := func(string, interface{}) { n++ }
	h := newBroadcastHandlerTo(new(slog.LevelVar), func() func(string, interface{}) { return bc }, &bytes.Buffer{})
	l := slog.New(h)
	for i := 0; i < 10; i++ {
		l.Warn("[wg:utun4] same warning")
	}
	if n != 1 {
		t.Errorf("broadcast %d times, want 1", n)
	}
}

func TestHelperLogFile(t *testing.T) {
	dir := "/data"
	cases := []struct {
		goos string
		opt  bool
		want string
	}{
		{"darwin", false, logrotate.HelperLogPath},
		{"darwin", true, logrotate.HelperLogPath},
		{"windows", false, ""},
		{"windows", true, filepath.Join(dir, logrotate.WindowsLogName)},
		{"linux", false, ""},
		{"linux", true, ""},
	}
	for _, c := range cases {
		if got := helperLogFile(c.goos, dir, c.opt); got != c.want {
			t.Errorf("helperLogFile(%s, opt=%v) = %q, want %q", c.goos, c.opt, got, c.want)
		}
	}
}

// Identical warnings from different tunnel interfaces are independent.
func TestBroadcastHandlerRateLimitsPerInterface(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(newBroadcastHandlerTo(new(slog.LevelVar), func() func(string, interface{}) { return nil }, &buf))
	for _, iface := range []string{"utun4", "utun5"} {
		for i := 0; i < 5; i++ {
			l.Warn("[wg:" + iface + "] Failed to send: network is unreachable")
		}
	}
	out := buf.String()
	for _, iface := range []string{"utun4", "utun5"} {
		if n := strings.Count(out, "[wg:"+iface+"]"); n != 1 {
			t.Errorf("%s warning logged %d times, want 1:\n%s", iface, n, out)
		}
	}
}

// An unrelated record arriving first after the window flushes the summary but
// must not delay the real warning by another window.
func TestBroadcastHandlerWarningRepeatsAfterSummaryFlush(t *testing.T) {
	var buf bytes.Buffer
	h := newBroadcastHandlerTo(new(slog.LevelVar), func() func(string, interface{}) { return nil }, &buf)
	now := time.Unix(1000, 0)
	h.clock = func() time.Time { return now }
	l := slog.New(h)
	for i := 0; i < 3; i++ {
		l.Warn("[wg:utun4] Failed to send: network is unreachable")
	}
	now = now.Add(2 * time.Minute)
	l.Info("unrelated line")
	if !strings.Contains(buf.String(), "suppressed repeated engine warnings") {
		t.Fatalf("summary missing:\n%s", buf.String())
	}
	now = now.Add(time.Second)
	buf.Reset()
	l.Warn("[wg:utun4] Failed to send: network is unreachable")
	if n := strings.Count(buf.String(), "Failed to send"); n != 1 {
		t.Errorf("real warning logged %d times right after the summary, want 1:\n%s", n, buf.String())
	}
}

// Handler output must go through the rotating writer so the live file is
// rotated at the size threshold.
func TestBroadcastHandlerWritesThroughRotatingLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.log")
	w, err := logrotate.Open(path, 2048, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	l := slog.New(newBroadcastHandlerTo(new(slog.LevelVar), func() func(string, interface{}) { return nil }, w))
	for i := 0; i < 100; i++ {
		l.Info("a line long enough to fill the rotation budget quickly", "i", i)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("expected a rotated sibling: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() > 2048 {
		t.Errorf("live log missing or over the cap: %v", err)
	}
}
