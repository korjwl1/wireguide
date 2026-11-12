package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// fixRoundTripCase is one entry of testdata/dns_fix_roundtrip.json. The same
// file drives frontend/src/lib/wireguard-lint.test.js, which asserts that the
// editor's fixChanges(input, append_dns value) produces exactly Fixed. Here the
// Go side checks the rest of the loop: Lint on Input offers (or withholds) that
// fix, and Fixed survives Parse and Validate.
type fixRoundTripCase struct {
	Name    string `json:"name"`
	Input   string `json:"input"`
	Value   string `json:"value"`
	Fixed   string `json:"fixed"`
	Offered bool   `json:"offered"`
	Error   string `json:"error"`
}

func loadFixRoundTrip(t *testing.T) []fixRoundTripCase {
	t.Helper()
	b, err := os.ReadFile("testdata/dns_fix_roundtrip.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []fixRoundTripCase
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	return cases
}

func dnsValidationErrors(cfg *WireGuardConfig) []string {
	var out []string
	for _, e := range Validate(cfg).Errors {
		if e.Field == "Interface.DNS" {
			out = append(out, e.Message)
		}
	}
	return out
}

func TestLintReverseZoneFixRoundTrip(t *testing.T) {
	old := lintGOOS
	defer func() { lintGOOS = old }()
	lintGOOS = "darwin"

	for _, tc := range loadFixRoundTrip(t) {
		t.Run(tc.Name, func(t *testing.T) {
			in, err := Parse(tc.Input)
			if err != nil {
				t.Fatalf("parse input: %v", err)
			}
			if res := Validate(in); !res.IsValid() {
				t.Fatalf("input must be valid: %v", res.ErrorMessages())
			}
			ds := Lint(in, nil)
			for _, d := range ds {
				if d.Fix != nil && d.Fix.Action == FixAppendDNS && !tc.Offered {
					t.Fatalf("fix offered for a config it would break: %+v", d)
				}
			}

			fixed, err := Parse(tc.Fixed)
			if err != nil {
				t.Fatalf("parse fixed: %v", err)
			}
			if !tc.Offered {
				d := find(ds, "dns_no_reverse_limit")
				if d == nil || d.Fix != nil || d.Severity != SeverityInfo {
					t.Fatalf("expected dns_no_reverse_limit without a fix, got %+v", ds)
				}
				if find(ds, "dns_no_reverse") != nil {
					t.Fatal("dns_no_reverse must not be reported alongside the limit variant")
				}
				if d.Args["zones"] != tc.Value {
					t.Errorf("zones %q, want %q", d.Args["zones"], tc.Value)
				}
				// Applying the full set would make the config unsavable,
				// with the limit named by the case.
				errs := strings.Join(dnsValidationErrors(fixed), "|")
				if !strings.Contains(errs, tc.Error) {
					t.Fatalf("fixed config errors %q, want %q", errs, tc.Error)
				}
				return
			}

			d := find(ds, "dns_no_reverse")
			if d == nil || d.Fix == nil || d.Fix.Action != FixAppendDNS {
				t.Fatalf("expected dns_no_reverse with fix, got %+v", ds)
			}
			if d.Fix.Value != tc.Value {
				t.Fatalf("fix value %q, want %q", d.Fix.Value, tc.Value)
			}
			if res := Validate(fixed); !res.IsValid() {
				t.Fatalf("fixed config does not validate: %v", res.ErrorMessages())
			}
			for _, z := range strings.Split(tc.Value, ", ") {
				found := false
				for _, e := range fixed.Interface.DNS {
					if e == z {
						found = true
					}
				}
				if !found {
					t.Errorf("zone %s missing from parsed DNS %v (landed in a comment?)", z, fixed.Interface.DNS)
				}
			}
			after := Lint(fixed, nil)
			if find(after, "dns_no_reverse") != nil || find(after, "dns_no_reverse_limit") != nil {
				t.Errorf("reverse-zone diagnostic remains after the fix: %+v", after)
			}
		})
	}
}
