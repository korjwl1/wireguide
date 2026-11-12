package app

import (
	"reflect"
	"testing"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/storage"
)

func TestListTunnelsLocalReportsDNSMode(t *testing.T) {
	store := storage.NewTunnelStore(t.TempDir())
	for name, dns := range map[string][]string{
		"split-vpn":  {"10.66.66.1", "~corp.example"},
		"global-vpn": {"1.1.1.1"},
		"plain-vpn":  nil,
	} {
		cfg := &config.WireGuardConfig{Name: name}
		cfg.Interface.PrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		cfg.Interface.DNS = dns
		if err := store.Save(cfg); err != nil {
			t.Fatal(err)
		}
	}
	s := &TunnelService{tunnelStore: store}
	rows, err := s.ListTunnelsLocal()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]TunnelInfo{}
	for _, r := range rows {
		got[r.Name] = r
	}
	if r := got["split-vpn"]; r.DNSMode != "split" || !reflect.DeepEqual(r.DNSDomains, []string{"corp.example"}) {
		t.Errorf("split: %+v", r)
	}
	if r := got["global-vpn"]; r.DNSMode != "global" || len(r.DNSDomains) != 0 {
		t.Errorf("global: %+v", r)
	}
	if r := got["plain-vpn"]; r.DNSMode != "none" {
		t.Errorf("none: %+v", r)
	}
}
