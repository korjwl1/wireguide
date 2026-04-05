package config

import (
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
