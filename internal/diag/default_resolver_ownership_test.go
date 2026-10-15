package diag

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
)

// realisticScutil: the tunnel's resolver is the default; another app owns a
// supplemental ts.net resolver; the LAN router is only a scoped resolver.
const realisticScutil = `DNS configuration

resolver #1
  nameserver[0] : 10.0.0.53
  if_index : 14 (en0)
  flags    : Request A records
  reach    : 0x00000002 (Reachable)

resolver #2
  domain   : ts.net
  nameserver[0] : 100.100.100.100
  flags    : Supplemental, Request A records
  reach    : 0x00000003 (Reachable,Transient Connection)

resolver #3
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  if_index : 14 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
`

func fakeScutilOutput(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n/bin/cat <<'DNS'\n" + body + "DNS\n"
	if err := os.WriteFile(filepath.Join(dir, "scutil"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

// recordProbes makes every probed server answer and returns the probed set.
func recordProbes(t *testing.T) func() []string {
	t.Helper()
	orig := probeDNSServer
	t.Cleanup(func() { probeDNSServer = orig })
	var mu sync.Mutex
	var probed []string
	probeDNSServer = func(_ context.Context, server, _ string) bool {
		mu.Lock()
		probed = append(probed, server)
		mu.Unlock()
		return true
	}
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := slices.Clone(probed)
		slices.Sort(out)
		return out
	}
}

// Review N-5: the global check must own the same default-resolver set
// whether or not a split tunnel is also up.
func TestGlobalAndMixedChecksShareDefaultResolverOwnership(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("scutil fixture")
	}
	fakeScutilOutput(t, realisticScutil)

	probed := recordProbes(t)
	global := RunDNSLeakTestForTunnels([][]string{{"10.0.0.53"}})
	globalProbed := probed()

	probed = recordProbes(t)
	mixed := RunDNSLeakTestForTunnels([][]string{{"10.0.0.53"}, {"100.100.100.100", "~ts.net"}})
	mixedProbed := probed()

	if global.Leaked || global.Error != "" {
		t.Fatalf("global-only check reported scoped/supplemental resolvers as a leak: %+v", global)
	}
	if mixed.Leaked || mixed.Error != "" {
		t.Fatalf("mixed check: %+v", mixed)
	}
	if want := []string{"10.0.0.53"}; !slices.Equal(globalProbed, want) || !slices.Equal(mixedProbed, want) {
		t.Fatalf("probe sets differ: global=%v mixed=%v, want %v", globalProbed, mixedProbed, want)
	}
}

// The narrowed set still catches a real leak: a non-tunnel default resolver.
func TestGlobalCheckStillDetectsDefaultResolverLeak(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("scutil fixture")
	}
	fakeScutilOutput(t, "DNS configuration\n\nresolver #1\n  nameserver[0] : 192.168.1.1\n\n"+
		"resolver #2\n  domain : ts.net\n  nameserver[0] : 100.100.100.100\n  flags : Supplemental\n")
	for _, tunnels := range [][][]string{
		{{"10.0.0.53"}},
		{{"10.0.0.53"}, {"100.100.100.100", "~ts.net"}},
	} {
		probed := recordProbes(t)
		r := RunDNSLeakTestForTunnels(tunnels)
		if !r.Leaked || !slices.Equal(probed(), []string{"192.168.1.1"}) {
			t.Fatalf("tunnels %v: leak through the default resolver missed: %+v probed=%v", tunnels, r, probed())
		}
	}
}

// A resolver flagged Scoped is not a default resolver even when listed
// outside the "for scoped queries" section.
func TestScopedFlagExcludesResolverFromDefaults(t *testing.T) {
	blocks := parseScutilDNS("DNS configuration\n\nresolver #1\n  nameserver[0] : 10.0.0.53\n\n" +
		"resolver #2\n  nameserver[0] : 192.168.1.1\n  if_index : 14 (en0)\n  flags : Scoped, Request A records\n")
	if got := darwinDefaultResolvers(blocks); !slices.Equal(got, []string{"10.0.0.53"}) {
		t.Fatalf("defaults = %v", got)
	}
}
