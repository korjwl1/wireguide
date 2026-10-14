package diag

import (
	"context"
	"reflect"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
)

const scutilSample = `DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.50.1
  if_index : 15 (en0)
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
  order    : 200000

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  order    : 300000

resolver #3
  domain   : intranet.example
  nameserver[0] : 192.168.1.1
  flags    : Request A records
  reach    : 0x00000002 (Reachable)
  order    : 101600

resolver #4
  domain   : 1.168.192.in-addr.arpa
  nameserver[0] : 192.168.1.1
  order    : 101800

DNS configuration (for scoped queries)

resolver #1
  domain   : corp.lan
  nameserver[0] : 192.168.1.1
  if_index : 15 (en0)
`

func TestParseScutilDNS(t *testing.T) {
	blocks := parseScutilDNS(scutilSample)
	if len(blocks) != 5 {
		t.Fatalf("got %d blocks: %+v", len(blocks), blocks)
	}
	want := scutilResolver{Domain: "intranet.example", Nameservers: []string{"192.168.1.1"}}
	if !reflect.DeepEqual(blocks[2], want) {
		t.Fatalf("block 3 = %+v, want %+v", blocks[2], want)
	}
	if !blocks[4].Scoped || blocks[0].Scoped {
		t.Fatalf("scoped flags wrong: %+v", blocks)
	}
}

func TestEvaluateSplitDNS(t *testing.T) {
	blocks := parseScutilDNS(scutilSample)
	p := domain.ParseDNSEntries([]string{"192.168.1.1", "~intranet.example", "~1.168.192.in-addr.arpa", "~corp.lan", "~absent.lan"})
	missing := evaluateSplitDNS(blocks, p)
	// corp.lan only exists in the scoped section, which does not count.
	want := []string{"absent.lan", "corp.lan"}
	if !reflect.DeepEqual(missing, want) {
		t.Fatalf("missing = %v, want %v", missing, want)
	}
	// A resolver for the domain pointing at some other server does not count.
	p2 := domain.ParseDNSEntries([]string{"10.9.9.9", "~intranet.example"})
	if m := evaluateSplitDNS(blocks, p2); len(m) != 1 {
		t.Fatalf("wrong-server resolver accepted: %v", m)
	}
}

// Split mode must never be reported as a leak, and must not probe resolvers.
func TestSplitModeIsNotALeak(t *testing.T) {
	res := RunDNSLeakTestContext(context.Background(), []string{"192.168.1.1", "~home.lan"})
	if res.Leaked {
		t.Fatal("split mode reported as leak")
	}
	if !res.SplitMode {
		t.Fatal("SplitMode not set")
	}
	if res.TestDomain != "" {
		t.Fatal("split mode should not run the probe test")
	}
}

func TestExpectedDNSForTunnelsPrefersGlobal(t *testing.T) {
	split := []string{"192.168.1.1", "~intranet.example"}
	global := []string{"10.0.0.1"}
	got := ExpectedDNSForTunnels([][]string{split, global, nil})
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "192.168.1.1" {
		t.Fatalf("global entries plus split server IPs (no ~ tokens), got %v", got)
	}
	got = ExpectedDNSForTunnels([][]string{split})
	if len(got) != 2 {
		t.Fatalf("split-only must keep entries, got %v", got)
	}
	if ExpectedDNSForTunnels(nil) != nil {
		t.Fatal("no tunnels must give empty expectation")
	}
}
