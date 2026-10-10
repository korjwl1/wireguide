package helper

import (
	"errors"
	"testing"
	"time"
)

type orphanRec struct {
	calls []string
	exist []bool // successive answers for exists
	sleep time.Duration
}

func (r *orphanRec) ops() orphanOps {
	i := 0
	return orphanOps{
		exists: func(string) bool {
			v := r.exist[min(i, len(r.exist)-1)]
			i++
			r.calls = append(r.calls, "exists")
			return v
		},
		recover: func() { r.calls = append(r.calls, "recover") },
		sleep:   func(d time.Duration) { r.sleep = d; r.calls = append(r.calls, "sleep") },
		remove:  func(p string) error { r.calls = append(r.calls, "rm "+p); return nil },
		bootout: func() error {
			r.calls = append(r.calls, "bootout")
			return errors.New("ignored")
		},
	}
}

func TestOrphanedInstall(t *testing.T) {
	t.Run("no flag", func(t *testing.T) {
		r := &orphanRec{exist: []bool{false}}
		if handleOrphanedInstall("", r.ops()) || len(r.calls) != 0 {
			t.Fatalf("must do nothing: %v", r.calls)
		}
	})
	t.Run("relative path ignored", func(t *testing.T) {
		r := &orphanRec{exist: []bool{false}}
		if handleOrphanedInstall("X.app", r.ops()) || len(r.calls) != 0 {
			t.Fatalf("must do nothing: %v", r.calls)
		}
	})
	t.Run("bundle present", func(t *testing.T) {
		r := &orphanRec{exist: []bool{true}}
		if handleOrphanedInstall("/Applications/WireGuide.app", r.ops()) {
			t.Fatal("must keep serving")
		}
		if len(r.calls) != 1 {
			t.Fatalf("one check only: %v", r.calls)
		}
	})
	t.Run("in-place update race", func(t *testing.T) {
		r := &orphanRec{exist: []bool{false, true}}
		if handleOrphanedInstall("/Applications/WireGuide.app", r.ops()) {
			t.Fatal("reappearing bundle must not trigger uninstall")
		}
		for _, c := range r.calls {
			if c == "bootout" || (len(c) > 2 && c[:2] == "rm") {
				t.Fatalf("destructive call during update race: %v", r.calls)
			}
		}
		if r.sleep != orphanRecheckDelay {
			t.Fatalf("recheck delay %v", r.sleep)
		}
	})
	t.Run("removed app uninstalls, bootout last", func(t *testing.T) {
		r := &orphanRec{exist: []bool{false, false}}
		if !handleOrphanedInstall("/Applications/WireGuide.app", r.ops()) {
			t.Fatal("must report handled so the caller exits without serving")
		}
		want := []string{"exists", "sleep", "exists", "recover",
			"rm " + orphanDaemonPlist, "rm " + orphanDaemonBinary, "rm /var/run/com.wireguide.helper.sock", "bootout"}
		if len(r.calls) != len(want) {
			t.Fatalf("calls %v want %v", r.calls, want)
		}
		for i := range want {
			if r.calls[i] != want[i] {
				t.Fatalf("calls %v want %v", r.calls, want)
			}
		}
	})
}
