package helper

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/korjwl1/wireguide/internal/logrotate"
)

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

// Handler output must go through the rotating writer so the live file stays
// bounded.
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
