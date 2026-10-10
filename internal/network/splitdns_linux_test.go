//go:build linux

package network

import (
	"errors"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
)

func TestSetSplitDNSResolvectlMissingIsUnsupported(t *testing.T) {
	orig := splitDNSRunCmd
	defer func() { splitDNSRunCmd = orig }()
	var calls [][]string
	splitDNSRunCmd = func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return errors.New("exec: \"resolvectl\": executable file not found in $PATH")
	}
	p := domain.ParseDNSEntries([]string{"10.0.0.1", "~corp.lan"})
	err := setSplitDNSResolvectl("wg0", p)
	if !errors.Is(err, ErrSplitDNSUnsupported) {
		t.Fatalf("err = %v, want ErrSplitDNSUnsupported", err)
	}
	for _, c := range calls {
		if c[0] != "resolvectl" {
			t.Fatalf("split mode ran %v; only resolvectl is allowed", c)
		}
	}
}

func TestSetSplitDNSResolvectlToleratesDefaultRouteFailure(t *testing.T) {
	orig := splitDNSRunCmd
	defer func() { splitDNSRunCmd = orig }()
	splitDNSRunCmd = func(name string, args ...string) error {
		if len(args) > 0 && args[0] == "default-route" {
			return errors.New("unknown command")
		}
		return nil
	}
	p := domain.ParseDNSEntries([]string{"10.0.0.1", "~corp.lan"})
	if err := setSplitDNSResolvectl("wg0", p); err != nil {
		t.Fatalf("default-route failure must be tolerated: %v", err)
	}
}

func TestSetSplitDNSResolvectlRevertsAfterPartialFailure(t *testing.T) {
	orig := splitDNSRunCmd
	defer func() { splitDNSRunCmd = orig }()
	var calls [][]string
	splitDNSRunCmd = func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		if len(args) > 0 && args[0] == "domain" {
			return errors.New("polkit timeout")
		}
		return nil
	}
	p := domain.ParseDNSEntries([]string{"10.0.0.1", "~corp.lan"})
	err := setSplitDNSResolvectl("wg0", p)
	if !errors.Is(err, ErrSplitDNSUnsupported) {
		t.Fatalf("err = %v, want ErrSplitDNSUnsupported", err)
	}
	last := calls[len(calls)-1]
	if len(last) != 3 || last[1] != "revert" || last[2] != "wg0" {
		t.Fatalf("expected trailing resolvectl revert wg0, got %v", calls)
	}
}

func TestSetSplitDNSResolvectlNoRevertWhenDNSFails(t *testing.T) {
	orig := splitDNSRunCmd
	defer func() { splitDNSRunCmd = orig }()
	var calls [][]string
	splitDNSRunCmd = func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return errors.New("fail")
	}
	p := domain.ParseDNSEntries([]string{"10.0.0.1", "~corp.lan"})
	_ = setSplitDNSResolvectl("wg0", p)
	if len(calls) != 1 {
		t.Fatalf("nothing to revert when the first command fails; calls = %v", calls)
	}
}
