package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
)

// TestValidatorAcceptsMixedDNS verifies that the validator no longer
// rejects hostname DNS entries. Regression test for the bug where our
// splitDNSEntries logic in darwin.go was dead code because the validator
// refused anything that wasn't an IP.
func TestValidatorAcceptsMixedDNS(t *testing.T) {
	base := &domain.WireGuardConfig{
		Interface: domain.InterfaceConfig{
			PrivateKey: "cGFzc3dvcmRwYXNzd29yZHBhc3N3b3JkcGFzc3dvcmQ=", // 32 bytes base64
			Address:    []string{"10.0.0.2/24"},
		},
		Peers: []domain.PeerConfig{
			{
				PublicKey:  "cGFzc3dvcmRwYXNzd29yZHBhc3N3b3JkcGFzc3dvcmQ=",
				AllowedIPs: []string{"0.0.0.0/0"},
			},
		},
	}

	cases := []struct {
		name    string
		dns     []string
		wantErr bool
	}{
		{"single ip", []string{"1.1.1.1"}, false},
		{"single hostname", []string{"corp.example.com"}, false},
		{"mixed ip and hostname", []string{"1.1.1.1", "corp.example.com"}, false},
		{"ipv6", []string{"2606:4700:4700::1111"}, false},
		{"bogus text with space", []string{"not a hostname"}, true},
		{"starts with dash", []string{"-bad.example.com"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := *base
			cfg.Interface.DNS = tc.dns
			result := Validate(&cfg)
			var dnsErrs []string
			for _, e := range result.Errors {
				if strings.HasPrefix(e.Field, "Interface.DNS") {
					dnsErrs = append(dnsErrs, e.Message)
				}
			}
			if tc.wantErr && len(dnsErrs) == 0 {
				t.Fatalf("expected DNS error, got none; dns=%v", tc.dns)
			}
			if !tc.wantErr && len(dnsErrs) > 0 {
				t.Fatalf("unexpected DNS error: %v", dnsErrs)
			}
		})
	}
}

func TestValidatorSplitDNS(t *testing.T) {
	base := &domain.WireGuardConfig{
		Interface: domain.InterfaceConfig{
			PrivateKey: "cGFzc3dvcmRwYXNzd29yZHBhc3N3b3JkcGFzc3dvcmQ=",
			Address:    []string{"10.0.0.2/24"},
		},
		Peers: []domain.PeerConfig{
			{PublicKey: "cGFzc3dvcmRwYXNzd29yZHBhc3N3b3JkcGFzc3dvcmQ=", AllowedIPs: []string{"10.0.0.0/24"}},
		},
	}
	many := []string{"10.0.0.1"}
	for i := 0; i < 33; i++ {
		many = append(many, fmt.Sprintf("~d%d.lan", i))
	}
	long := "~" + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + ".lan"

	cases := []struct {
		name    string
		dns     []string
		wantErr bool
	}{
		{"match domain", []string{"192.168.1.1", "~home.lan"}, false},
		{"reverse zone", []string{"192.168.1.1", "~1.168.192.in-addr.arpa"}, false},
		{"match plus search", []string{"192.168.1.1", "~home.lan", "corp.example"}, false},
		{"ipv6 server", []string{"fd00::1", "~home.lan"}, false},
		{"bare tilde", []string{"10.0.0.1", "~"}, true},
		{"tilde dot", []string{"10.0.0.1", "~."}, true},
		{"double tilde", []string{"10.0.0.1", "~~x"}, true},
		{"trailing dot", []string{"10.0.0.1", "~home.lan."}, true},
		{"leading dash", []string{"10.0.0.1", "~-bad"}, true},
		{"empty label", []string{"10.0.0.1", "~a..b"}, true},
		{"space", []string{"10.0.0.1", "~a b"}, true},
		{"newline", []string{"10.0.0.1", "~x\ny"}, true},
		{"quote", []string{"10.0.0.1", `~x"y`}, true},
		{"no server", []string{"~home.lan"}, true},
		{"search only no server", []string{"~home.lan", "corp.example"}, true},
		{"too many", many, true},
		{"32 ok", many[:33], false},
		{"too long", []string{"10.0.0.1", long}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := *base
			cfg.Interface.DNS = tc.dns
			var errs []string
			for _, e := range Validate(&cfg).Errors {
				if strings.HasPrefix(e.Field, "Interface.DNS") {
					errs = append(errs, e.Message)
				}
			}
			if tc.wantErr && len(errs) == 0 {
				t.Fatalf("expected DNS error for %q", tc.dns)
			}
			if !tc.wantErr && len(errs) > 0 {
				t.Fatalf("unexpected DNS errors: %v", errs)
			}
		})
	}
}
