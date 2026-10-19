package wifi

import "testing"

func TestParseRouteGetDefault(t *testing.T) {
	out := `   route to: default
destination: default
       mask: default
    gateway: 192.168.50.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`
	gw, iface := parseRouteGetDefault(out)
	if gw != "192.168.50.1" || iface != "en0" {
		t.Errorf("got %q %q", gw, iface)
	}
	// Link-scoped default (no IP gateway).
	gw, iface = parseRouteGetDefault("    gateway: link#14\n  interface: en5\n")
	if gw != "" || iface != "en5" {
		t.Errorf("got %q %q", gw, iface)
	}
	if gw, iface = parseRouteGetDefault(""); gw != "" || iface != "" {
		t.Errorf("empty: %q %q", gw, iface)
	}
}

func TestParseWiFiHardwarePorts(t *testing.T) {
	out := `Hardware Port: Ethernet Adapter (en4)
Device: en4
Ethernet Address: aa:bb

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: cc:dd

Hardware Port: Thunderbolt Bridge
Device: bridge0
`
	d := parseWiFiHardwarePorts(out)
	if !d["en0"] || d["en4"] || d["bridge0"] || len(d) != 1 {
		t.Errorf("got %v", d)
	}
}
