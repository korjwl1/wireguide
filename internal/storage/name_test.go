package storage

import (
	"strings"
	"testing"
)

func TestValidateTunnelName(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"simple", "home", false},
		{"with dash", "work-vpn", false},
		{"with underscore", "corp_vpn", false},
		{"mixed case and digits", "ProdRegion2", false},

		{"empty", "", true},
		{"space in middle", "my vpn", false},
		{"space in name with digits", "Work VPN 2", false},
		{"leading space", " vpn", true},
		{"trailing space", "vpn ", true},
		{"dot (would confuse extension)", "work.vpn", true},
		{"slash (path traversal)", "a/b", true},
		{"backslash", "a\\b", true},
		{"dot dot", "..", true},
		// 100 valid characters — exercises the length limit, not the
		// character class (100 null bytes would trip the char check first).
		{"too long", strings.Repeat("a", 100), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTunnelName(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateTunnelName(%q) err=%v, wantErr=%v", tc.input, err, tc.wantErr)
			}
		})
	}
}
