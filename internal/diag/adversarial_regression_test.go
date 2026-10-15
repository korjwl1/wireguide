package diag

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAuditResolverEnumerationFailureIsNotSuccess(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fake scutil is macOS specific")
	}
	t.Setenv("PATH", t.TempDir())
	result := RunDNSLeakTestContext(context.Background(), []string{"9.9.9.9"})
	if result.Error == "" {
		t.Fatalf("resolver enumeration failed but diagnostic returned success: %+v", result)
	}
}
func TestAuditMixedDNSDoesNotMaskFailedGlobalCheck(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fake scutil is macOS specific")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "called")
	script := "#!/bin/sh\nif [ ! -f '" + marker + "' ]; then\n : > '" + marker + "'\n exit 1\nfi\n/bin/cat <<'DNS'\nDNS configuration\nresolver #1\n domain : corp.example\n nameserver[0] : 10.1.0.53\nDNS\n"
	if err := os.WriteFile(filepath.Join(dir, "scutil"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	result := RunDNSLeakTestForTunnels([][]string{{"9.9.9.9"}, {"10.1.0.53", "~corp.example"}})
	if result.Error == "" {
		t.Fatalf("mixed mode returned success after the global enumeration failed: %+v", result)
	}
}

func TestGlobalDNSUnverifiedResults(t *testing.T) {
	reader, probe := systemResolverReader, probeDNSServer
	t.Cleanup(func() { systemResolverReader = reader; probeDNSServer = probe })
	for _, tc := range []struct {
		name    string
		servers []string
		err     error
	}{
		{"enumeration error", nil, errors.New("OS resolver query failed")},
		{"empty resolver list", nil, nil},
		{"no responding resolver", []string{"127.0.0.1"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			systemResolverReader = func() ([]string, error) { return tc.servers, tc.err }
			probeDNSServer = func(context.Context, string, string) bool { return false }
			r := RunDNSLeakTestContext(context.Background(), []string{"127.0.0.1"})
			if r.Error == "" || r.Leaked {
				t.Fatalf("unverified result=%+v", r)
			}
		})
	}
}
func TestGlobalDNSRespondingResolverVerdicts(t *testing.T) {
	reader, probe := systemResolverReader, probeDNSServer
	t.Cleanup(func() { systemResolverReader = reader; probeDNSServer = probe })
	systemResolverReader = func() ([]string, error) { return []string{"127.0.0.1"}, nil }
	probeDNSServer = func(context.Context, string, string) bool { return true }
	for _, vpn := range []bool{true, false} {
		var expected []string
		if vpn {
			expected = []string{"127.0.0.1"}
		}
		r := RunDNSLeakTestContext(context.Background(), expected)
		if r.Error != "" || r.Leaked == vpn {
			t.Fatalf("expectedVPN=%v result=%+v", vpn, r)
		}
	}
}
