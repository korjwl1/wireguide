package app

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/storage"
)

const lintTestKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestLintConfig(t *testing.T) {
	s := &TunnelService{}
	content := "[Interface]\nPrivateKey = " + lintTestKey + "\nAddress = 10.0.0.2/32\nDNS = ~intranet.example\n" +
		"[Peer]\nPublicKey = " + lintTestKey + "\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 10.0.0.0/24\n"
	ds, err := s.LintConfig("", content)
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

	ds, err = s.LintConfig("", "not a config")
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

func lintTestConf(addr string) string {
	return "[Interface]\nPrivateKey = " + lintTestKey + "\nAddress = " + addr + "\n" +
		"[Peer]\nPublicKey = " + lintTestKey + "\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 10.9.0.0/24\n"
}

func hasCode(ds []config.Diagnostic, code string) bool {
	for _, d := range ds {
		if d.Code == code {
			return true
		}
	}
	return false
}

func TestLintConfigCrossTunnel(t *testing.T) {
	s := &TunnelService{tunnelStore: storage.NewTunnelStore(t.TempDir())}
	if _, err := s.ImportConfig("home-vpn", lintTestConf("10.66.66.2/32")); err != nil {
		t.Fatal(err)
	}
	// A new tunnel sharing the address is flagged.
	ds, err := s.LintConfig("", lintTestConf("10.66.66.2/24"))
	if err != nil || !hasCode(ds, "address_shared") {
		t.Fatalf("expected address_shared, got %+v err=%v", ds, err)
	}
	// Editing home-vpn itself must not conflict with its own saved copy.
	ds, err = s.LintConfig("home-vpn", lintTestConf("10.66.66.2/32"))
	if err != nil || hasCode(ds, "address_shared") {
		t.Fatalf("self-conflict: %+v err=%v", ds, err)
	}
}

func TestImportConfigWarnsOnSharedAddress(t *testing.T) {
	s := &TunnelService{tunnelStore: storage.NewTunnelStore(t.TempDir())}
	first, err := s.ImportConfig("home-vpn", lintTestConf("10.66.66.2/32"))
	if err != nil || len(first.Warnings) != 0 {
		t.Fatalf("first import: %+v err=%v", first, err)
	}
	second, err := s.ImportConfig("office-vpn", lintTestConf("10.66.66.2/32"))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Warnings) != 1 || second.Warnings[0].Code != "address_shared" ||
		second.Warnings[0].Args["tunnel"] != "home-vpn" {
		t.Fatalf("expected one address_shared warning, got %+v", second.Warnings)
	}
}

func TestImportZipWarnsOnSharedAddress(t *testing.T) {
	s := &TunnelService{tunnelStore: storage.NewTunnelStore(t.TempDir())}
	if _, err := s.ImportConfig("home-vpn", lintTestConf("10.66.66.2/32")); err != nil {
		t.Fatal(err)
	}
	data := buildZip(t, map[string]string{
		"office-vpn.conf": lintTestConf("10.66.66.2/32"),
		"cafe-vpn.conf":   lintTestConf("10.77.77.2/32"),
	})
	results, err := s.ImportZipData(data)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]ZipImportResult{}
	for _, r := range results {
		byName[r.Name] = r
	}
	if r := byName["office-vpn"]; r.Error != "" || len(r.Warnings) == 0 || r.Warnings[0].Code != "address_shared" {
		t.Errorf("office-vpn: %+v", r)
	}
	if r := byName["cafe-vpn"]; r.Error != "" || len(r.Warnings) != 0 {
		t.Errorf("cafe-vpn: %+v", r)
	}
}

func TestImportZipWarnsOnAddressSharedWithEarlierEntry(t *testing.T) {
	s := &TunnelService{tunnelStore: storage.NewTunnelStore(t.TempDir())}
	data := buildZip(t, map[string]string{
		"a-vpn.conf": lintTestConf("10.66.66.2/32"),
		"b-vpn.conf": lintTestConf("10.66.66.2/32"),
	})
	results, err := s.ImportZipData(data)
	if err != nil {
		t.Fatal(err)
	}
	warned := 0
	for _, r := range results {
		if r.Error != "" {
			t.Fatalf("%s: %s", r.Name, r.Error)
		}
		warned += len(r.Warnings)
	}
	// Whichever entry is imported second is flagged against the first.
	if warned != 1 {
		t.Fatalf("expected exactly one warning across the zip, got %d: %+v", warned, results)
	}
}

func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
