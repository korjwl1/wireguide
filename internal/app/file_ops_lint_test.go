package app

import (
	"testing"

	"github.com/korjwl1/wireguide/internal/config"
)

const lintTestKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestLintConfigFor(t *testing.T) {
	s := &TunnelService{}
	content := "[Interface]\nPrivateKey = " + lintTestKey + "\nAddress = 10.0.0.2/32\nDNS = ~intranet.example\n" +
		"[Peer]\nPublicKey = " + lintTestKey + "\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 10.0.0.0/24\n"
	ds, err := s.LintConfigFor("", content)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range ds {
		if d.Code == "dns_error" && d.Severity == config.SeverityError {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected dns_error, got %+v", ds)
	}

	ds, err = s.LintConfigFor("x", "not a config")
	if err != nil || ds == nil || len(ds) != 0 {
		t.Fatalf("unparseable content: ds=%v err=%v", ds, err)
	}
}

func TestSafeLintRecovers(t *testing.T) {
	orig := lintConfig
	t.Cleanup(func() { lintConfig = orig })
	lintConfig = func(*config.WireGuardConfig, map[string]*config.WireGuardConfig) []config.Diagnostic {
		panic("lint failure")
	}
	if ds := safeLint(&config.WireGuardConfig{}, nil); ds != nil {
		t.Fatalf("recovered panic must yield nil, got %v", ds)
	}
}
