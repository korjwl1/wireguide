package diag

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMixedDNSDefaultCannotBorrowSupplementalServerOwnership(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("scutil fixture")
	}
	probe := probeDNSServer
	t.Cleanup(func() { probeDNSServer = probe })
	probeDNSServer = func(context.Context, string, string) bool { return true }
	dir := t.TempDir()
	script := "#!/bin/sh\n/bin/cat <<'DNS'\nDNS configuration\nresolver #1\n nameserver[0] : 127.0.0.1\nresolver #2\n domain : corp.example\n nameserver[0] : 127.0.0.1\nDNS\n"
	if err := os.WriteFile(filepath.Join(dir, "scutil"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	r := RunDNSLeakTestForTunnels([][]string{{"10.0.0.53"}, {"127.0.0.1", "~corp.example"}})
	if !r.Leaked || r.Error != "" {
		t.Fatalf("default LAN resolver masked by supplemental ownership: %+v", r)
	}
	r = RunDNSLeakTestForTunnels([][]string{{"10.0.0.53"}, {"127.0.0.1", "~missing.example"}})
	if !r.Leaked || r.Error == "" {
		t.Fatalf("leak and incomplete configuration must both survive: %+v", r)
	}
}
func TestSupplementalServerIsNotProbedAsDefaultResolver(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("scutil fixture")
	}
	probe := probeDNSServer
	t.Cleanup(func() { probeDNSServer = probe })
	probeDNSServer = func(_ context.Context, server, _ string) bool {
		if server != "127.0.0.1" {
			t.Errorf("supplemental resolver probed globally: %s", server)
		}
		return true
	}
	dir := t.TempDir()
	script := "#!/bin/sh\n/bin/cat <<'DNS'\nDNS configuration\nresolver #1\n nameserver[0] : 127.0.0.1\nresolver #2\n domain : corp.example\n nameserver[0] : 10.1.0.53\nDNS\n"
	if err := os.WriteFile(filepath.Join(dir, "scutil"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	r := RunDNSLeakTestForTunnels([][]string{{"127.0.0.1"}, {"10.1.0.53", "~corp.example"}})
	if r.Leaked || r.Error != "" {
		t.Fatalf("valid mixed configuration rejected: %+v", r)
	}
}
