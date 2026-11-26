package diag

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestPickResolver(t *testing.T) {
	blocks := parseScutilDNS(scutilSample)
	if b, ok := pickResolver(blocks, "nas.intranet.example"); !ok || b.Domain != "intranet.example" || b.Nameservers[0] != "192.168.1.1" {
		t.Fatalf("match domain: %+v %v", b, ok)
	}
	if b, ok := pickResolver(blocks, "example.com"); !ok || b.Domain != "" || b.Nameservers[0] != "192.168.50.1" {
		t.Fatalf("default: %+v %v", b, ok)
	}
	// corp.lan exists only in the scoped section and must not match.
	if b, _ := pickResolver(blocks, "x.corp.lan"); b.Domain == "corp.lan" {
		t.Fatalf("scoped resolver matched: %+v", b)
	}
}

func TestResolveWith(t *testing.T) {
	scutil := func(context.Context) (string, error) { return scutilSample, nil }
	ok := resolveDeps{
		lookup: func(context.Context, string) ([]string, error) { return []string{"192.168.1.20"}, nil },
		scutil: scutil,
	}
	r := resolveWith(context.Background(), ok, " nas.intranet.example ")
	if r.Error != "" || r.Resolver != "192.168.1.1" || r.MatchDomain != "intranet.example" || len(r.Addrs) != 1 {
		t.Fatalf("%+v", r)
	}
	nx := resolveDeps{
		lookup: func(context.Context, string) ([]string, error) {
			return nil, &net.DNSError{Err: "no such host", Name: "x", IsNotFound: true}
		},
		scutil: scutil,
	}
	if r := resolveWith(context.Background(), nx, "x.intranet.example"); !r.NXDomain || r.Error != "NXDOMAIN" {
		t.Fatalf("%+v", r)
	}
	to := resolveDeps{
		lookup: func(context.Context, string) ([]string, error) { return nil, context.DeadlineExceeded },
		scutil: func(context.Context) (string, error) { return "", errors.New("n/a") },
	}
	if r := resolveWith(context.Background(), to, "slow.example"); !r.TimedOut || r.Resolver != "" {
		t.Fatalf("%+v", r)
	}
	if r := resolveWith(context.Background(), ok, "bad name"); r.Error == "" {
		t.Fatal("invalid name accepted")
	}
}
