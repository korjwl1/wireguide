//go:build darwin

package firewall

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// A crashed helper's same-boot lease journal must survive until its reference
// is released. If startup recovery's anchor flush fails, the next enable
// rewrites the journal from the empty in-memory lease and the crashed
// reference (token 999, pfctl PID 7) can never be released.
func TestFailedRecoveryThenEnablePreservesCrashedPFReference(t *testing.T) {
	calls := stubPF(t)
	if err := writePfLease(pfLeaseState{Token: "999", OwnerPID: 7, Boot: "boot-a"}); err != nil {
		t.Fatal(err)
	}
	good := runPfctl
	runPfctl = func(args ...string) ([]byte, error) {
		if len(args) > 2 && args[0] == "-a" {
			return []byte("busy"), errors.New("timeout")
		}
		if args[0] == "-s" {
			*calls = append(*calls, strings.Join(args, " "))
			return []byte("TOKENS:\nPID Process Name TOKEN TIMESTAMP\n7 pfctl 999 0 days 00:00:09\n42 pfctl 1234567890123456789 0 days 00:00:01\n"), nil
		}
		return good(args...)
	}
	if RecoverSavedRules() {
		t.Fatal("flush failure should fail recovery")
	}
	runPfctl = func(args ...string) ([]byte, error) {
		if args[0] == "-s" {
			*calls = append(*calls, strings.Join(args, " "))
			return []byte("TOKENS:\nPID Process Name TOKEN TIMESTAMP\n7 pfctl 999 0 days 00:00:09\n42 pfctl 1234567890123456789 0 days 00:00:01\n"), nil
		}
		return good(args...)
	}
	f := NewPlatformFirewall().(*DarwinFirewall)
	if err := f.EnableKillSwitch("", nil, nil); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(savedPfStateFile)
	t.Logf("journal after enable: %s", data)
	if err := f.DisableKillSwitch(); err != nil {
		t.Fatal(err)
	}
	if err := f.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(*calls, ","), "-X 999") {
		t.Fatalf("BUG: crashed reference 999/pid 7 never released; calls=%v", *calls)
	}
}
