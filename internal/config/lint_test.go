package config

import (
	"fmt"
	"strings"
	"testing"
)

const lintKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func lintCfg(t *testing.T, iface, allowed string) *WireGuardConfig {
	t.Helper()
	cfg, err := Parse("[Interface]\nPrivateKey = " + lintKey + "\nAddress = 10.0.0.2/32\n" + iface +
		"\n[Peer]\nPublicKey = " + lintKey + "\nEndpoint = 1.2.3.4:51820\nAllowedIPs = " + allowed + "\n")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// findGlobalOutside returns the global-DNS-outside diagnostic under either
// of its platform-specific codes.
func findGlobalOutside(ds []Diagnostic) *Diagnostic {
	if d := find(ds, "dns_global_outside"); d != nil {
		return d
	}
	return find(ds, "dns_global_outside_adapter")
}

func find(ds []Diagnostic, code string) *Diagnostic {
	for i := range ds {
		if ds[i].Code == code {
			return &ds[i]
		}
	}
	return nil
}

func TestLintDNSErrorsMirrorValidator(t *testing.T) {
	cfg := lintCfg(t, "DNS = ~intranet.example\nMTU = 1380", "192.168.1.0/24")
	res := Validate(cfg)
	if res.IsValid() {
		t.Fatal("expected validator error")
	}
	ds := Lint(cfg, nil)
	d := find(ds, "dns_error")
	if d == nil || d.Severity != SeverityError || d.Field != "Interface.DNS" {
		t.Fatalf("missing dns error: %+v", ds)
	}
	want := res.Errors[0].Message
	if d.Message != want {
		t.Fatalf("message %q != validator %q", d.Message, want)
	}
	for _, tc := range []string{"~", "~.", "~foo.", "~~foo", "1.1.1.1, ~bad_name"} {
		c := lintCfg(t, "DNS = "+tc+"\nMTU = 1380", "192.168.1.0/24")
		if find(Lint(c, nil), "dns_error") == nil {
			t.Errorf("no dns_error for %q", tc)
		}
	}
	many := []string{"1.1.1.1"}
	for i := 0; i < 33; i++ {
		many = append(many, "~d"+strings.Repeat("a", i%5)+string(rune('a'+i%26))+string(rune('a'+i/26))+".lan")
	}
	c := lintCfg(t, "DNS = "+strings.Join(many, ", ")+"\nMTU = 1380", "192.168.1.0/24")
	var found bool
	for _, d := range Lint(c, nil) {
		if d.Code == "dns_error" && strings.Contains(d.Message, "too many") {
			found = true
		}
	}
	if !found {
		t.Error("no too-many-domains error")
	}
}

func TestLintGlobalDNSOutsideAllowedIPs(t *testing.T) {
	cfg := lintCfg(t, "DNS = 1.1.1.1\nMTU = 1380", "192.168.1.0/24")
	d := findGlobalOutside(Lint(cfg, nil))
	if d == nil || d.Severity != SeverityWarning || d.Fix == nil || d.Fix.Action != FixRemoveDNS {
		t.Fatalf("expected warning with remove fix, got %+v", d)
	}
	old := lintGOOS
	defer func() { lintGOOS = old }()
	lintGOOS = "darwin"
	if g := findGlobalOutside(Lint(cfg, nil)); g.Code != "dns_global_outside" || !strings.Contains(g.Message, "replaces system DNS on every network service") {
		t.Errorf("darwin diagnostic: %+v", g)
	}
	lintGOOS = "windows"
	if g := findGlobalOutside(Lint(cfg, nil)); g.Code != "dns_global_outside_adapter" || strings.Contains(g.Message, "network service") {
		t.Errorf("non-darwin diagnostic: %+v", g)
	}
	lintGOOS = old
	// Inside AllowedIPs: no warning.
	if findGlobalOutside(Lint(lintCfg(t, "DNS = 192.168.1.1\nMTU = 1380", "192.168.1.0/24"), nil)) != nil {
		t.Error("unexpected warning for in-range DNS")
	}
	// Full tunnel: no warning.
	if findGlobalOutside(Lint(lintCfg(t, "DNS = 1.1.1.1\nMTU = 1380", "0.0.0.0/0, ::/0"), nil)) != nil {
		t.Error("unexpected warning for full tunnel")
	}
	// Split mode: no warning.
	if findGlobalOutside(Lint(lintCfg(t, "DNS = 1.1.1.1, ~corp.lan\nMTU = 1380", "192.168.1.0/24"), nil)) != nil {
		t.Error("unexpected warning in split mode")
	}
}

func TestLintMDNSAndWindows(t *testing.T) {
	cfg := lintCfg(t, "DNS = 192.168.1.1, ~foo.local\nMTU = 1380", "192.168.1.0/24")
	if find(Lint(cfg, nil), "dns_mdns") == nil {
		t.Error("missing mdns warning")
	}
	if find(Lint(lintCfg(t, "DNS = 192.168.1.1, ~corp.lan\nMTU = 1380", "192.168.1.0/24"), nil), "dns_mdns") != nil {
		t.Error("unexpected mdns warning")
	}
	old := lintGOOS
	defer func() { lintGOOS = old }()
	lintGOOS = "windows"
	if find(Lint(cfg, nil), "dns_split_windows") == nil {
		t.Error("missing windows warning")
	}
	w := find(Lint(cfg, nil), "dns_split_windows")
	if w.Severity != SeverityWarning || !strings.Contains(w.Message, "connecting will fail") {
		t.Errorf("windows diagnostic: %+v", w)
	}
	lintGOOS = "darwin"
	ds := Lint(cfg, nil)
	if find(ds, "dns_split_windows") != nil || find(ds, "dns_split_linux") != nil {
		t.Error("platform diagnostics on darwin")
	}
	lintGOOS = "linux"
	ds = Lint(cfg, nil)
	l := find(ds, "dns_split_linux")
	if l == nil || l.Severity != SeverityInfo || !strings.Contains(l.Message, "systemd-resolved") || find(ds, "dns_split_windows") != nil {
		t.Errorf("linux diagnostic: %+v", ds)
	}
	lintGOOS = "linux"
	if find(Lint(lintCfg(t, "DNS = 192.168.1.1\nMTU = 1380", "192.168.1.0/24"), nil), "dns_split_linux") != nil {
		t.Error("linux info without split DNS")
	}
}

func TestLintMTU(t *testing.T) {
	if find(Lint(lintCfg(t, "DNS = 10.0.0.1", "10.0.0.0/24"), nil), "mtu_missing") != nil {
		t.Error("unset MTU must not produce a diagnostic")
	}
	d := find(Lint(lintCfg(t, "MTU = 1500", "10.0.0.0/24"), nil), "mtu_high")
	if d == nil || d.Severity != SeverityInfo {
		t.Error("missing mtu_high info")
	}
	if find(Lint(lintCfg(t, "MTU = 1420", "10.0.0.0/24"), nil), "mtu_high") != nil {
		t.Error("unexpected mtu_high at 1420")
	}
}

func TestLintLANOnlyNoDNS(t *testing.T) {
	d := find(Lint(lintCfg(t, "MTU = 1380", "192.168.1.0/24"), nil), "dns_lan_none")
	if d == nil || d.Severity != SeverityInfo || d.Args["gateway"] != "192.168.1.1" {
		t.Fatalf("expected LAN info with gateway, got %+v", d)
	}
	if find(Lint(lintCfg(t, "MTU = 1380", "0.0.0.0/0"), nil), "dns_lan_none") != nil {
		t.Error("unexpected info for full tunnel")
	}
	if find(Lint(lintCfg(t, "MTU = 1380", "192.168.1.0/24, 8.8.8.0/24"), nil), "dns_lan_none") != nil {
		t.Error("unexpected info for public range")
	}
	if find(Lint(lintCfg(t, "DNS = 192.168.1.1\nMTU = 1380", "192.168.1.0/24"), nil), "dns_lan_none") != nil {
		t.Error("unexpected info when DNS set")
	}
}

func TestLintReverseZoneFix(t *testing.T) {
	cfg := lintCfg(t, "DNS = 192.168.1.1, ~corp.lan\nMTU = 1380", "192.168.1.0/24, 10.5.0.9/32")
	d := find(Lint(cfg, nil), "dns_no_reverse")
	if d == nil || d.Fix == nil || d.Fix.Action != FixAppendDNS {
		t.Fatalf("expected reverse zone info with fix, got %+v", d)
	}
	if d.Fix.Value != "~1.168.192.in-addr.arpa" {
		t.Errorf("fix value %q", d.Fix.Value)
	}
	withZone := lintCfg(t, "DNS = 192.168.1.1, ~corp.lan, ~1.168.192.in-addr.arpa\nMTU = 1380", "192.168.1.0/24")
	if find(Lint(withZone, nil), "dns_no_reverse") != nil {
		t.Error("unexpected info when reverse zone present")
	}
}

func TestLintNeverAffectsValidity(t *testing.T) {
	cfg := lintCfg(t, "DNS = 1.1.1.1\nMTU = 1500", "192.168.1.0/24")
	before := Validate(cfg).IsValid()
	ds := Lint(cfg, nil)
	if len(ds) == 0 {
		t.Fatal("expected diagnostics")
	}
	for _, d := range ds {
		if d.Severity == SeverityError {
			t.Fatalf("unexpected error %+v", d)
		}
	}
	if after := Validate(cfg).IsValid(); after != before || !after {
		t.Error("lint changed validity")
	}
}

func TestDerivedHelpers(t *testing.T) {
	gw := GatewayCandidates([]string{"192.168.1.0/24", "10.5.0.9/32", "10.0.0.0/16", "0.0.0.0/0", "::/0"})
	want := []string{"192.168.1.1", "10.5.0.1", "10.0.0.1"}
	if strings.Join(gw, ",") != strings.Join(want, ",") {
		t.Errorf("gateways %v", gw)
	}
	z := ReverseZones([]string{"192.168.1.0/24", "10.0.0.0/16", "10.0.0.0/8", "0.0.0.0/0"})
	wz := []string{"1.168.192.in-addr.arpa", "0.10.in-addr.arpa", "10.in-addr.arpa"}
	if strings.Join(z, ",") != strings.Join(wz, ",") {
		t.Errorf("zones %v", z)
	}
}

func TestReverseZonesNeverWiderThanRoute(t *testing.T) {
	// /12 and /10 would need >8 sub-zones: skipped, never a whole-/8 zone.
	if z := ReverseZones([]string{"172.16.0.0/12", "100.64.0.0/10"}); len(z) != 0 {
		t.Errorf("wide prefixes must yield no zone, got %v", z)
	}
	// Longer than /24: the containing /24 zone would be wider than the route.
	if z := ReverseZones([]string{"10.0.0.5/32", "10.0.0.128/25", "10.0.0.252/30"}); len(z) != 0 {
		t.Errorf("prefixes longer than /24 must yield no zone, got %v", z)
	}
	z := ReverseZones([]string{"10.1.0.0/22", "10.2.0.0/23"})
	want := "0.1.10.in-addr.arpa,1.1.10.in-addr.arpa,2.1.10.in-addr.arpa,3.1.10.in-addr.arpa,0.2.10.in-addr.arpa,1.2.10.in-addr.arpa"
	if strings.Join(z, ",") != want {
		t.Errorf("zones %v", z)
	}
}

func TestLintIPv4MappedAllowedIPsDoesNotPanic(t *testing.T) {
	cfg := lintCfg(t, "DNS = 10.0.0.1, ~corp.lan", "::ffff:10.0.0.0/16")
	_ = Lint(cfg, nil)
	if z := ReverseZones([]string{"::ffff:10.0.0.0/16"}); len(z) != 0 {
		t.Errorf("zones %v", z)
	}
	if g := GatewayCandidates([]string{"::ffff:10.0.0.0/16"}); len(g) != 0 {
		t.Errorf("gateways %v", g)
	}
}

func TestLintGlobalDNSOutsideWithIPv6OnlyDefault(t *testing.T) {
	cfg := lintCfg(t, "DNS = 1.1.1.1", "10.0.0.0/24, ::/0")
	if findGlobalOutside(Lint(cfg, nil)) == nil {
		t.Error("expected warning when the only default route is IPv6")
	}
	full := lintCfg(t, "DNS = 1.1.1.1", "0.0.0.0/0, ::/0")
	if findGlobalOutside(Lint(full, nil)) != nil {
		t.Error("real full tunnel must not warn")
	}
}

func TestLintDNSErrorsIncludeResolverLimits(t *testing.T) {
	// Combined match+search cap: 20 match + 20 search, each under the
	// per-list limit but above 32 in total.
	entries := []string{"10.0.0.1"}
	for i := 0; i < 20; i++ {
		entries = append(entries, fmt.Sprintf("~m%d.example", i), fmt.Sprintf("s%d.example", i))
	}
	assertDNSErrorsMirror(t, entries, "too many split DNS match/search domains")

	// 2000-byte command limit.
	long := []string{"10.0.0.1"}
	for i := 0; i < 31; i++ {
		long = append(long, "~"+strings.Repeat("a", 60)+fmt.Sprint(i)+".example")
	}
	assertDNSErrorsMirror(t, long, "2000-byte")
}

// assertDNSErrorsMirror checks that Validate and Lint report the same text
// for entries and that it contains want.
func assertDNSErrorsMirror(t *testing.T, entries []string, want string) {
	t.Helper()
	cfg := lintCfg(t, "MTU = 1380", "10.0.0.0/24")
	cfg.Interface.DNS = entries
	var validator []string
	for _, e := range Validate(cfg).Errors {
		if e.Field == "Interface.DNS" {
			validator = append(validator, e.Message)
		}
	}
	var linted []string
	for _, d := range Lint(cfg, nil) {
		if d.Code == "dns_error" {
			linted = append(linted, d.Message)
		}
	}
	if strings.Join(validator, "|") != strings.Join(linted, "|") {
		t.Fatalf("lint %v != validator %v", linted, validator)
	}
	if !strings.Contains(strings.Join(linted, "|"), want) {
		t.Fatalf("want %q in %v", want, linted)
	}
}

func TestDNSErrorsValidInput(t *testing.T) {
	if errs := dnsErrors([]string{"10.0.0.1", "~corp.example", "corp.example"}); len(errs) != 0 {
		t.Fatalf("unexpected errors %v", errs)
	}
	if errs := dnsErrors(nil); len(errs) != 0 {
		t.Fatalf("unexpected errors %v", errs)
	}
}
