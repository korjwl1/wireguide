//go:build darwin

package firewall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type pfCall struct {
	stdin string
	args  []string
}

func (c pfCall) String() string { return strings.Join(c.args, " ") }

type fakePf struct {
	calls []pfCall
	// mainRuleset is returned for `pfctl -sr` (no anchor).
	mainRuleset string
	// anchorRules is returned for `pfctl -a X -sr`.
	anchorRules string
	token       string
	// anchorNoise is stderr-style noise pfctl emits on query probes; only the
	// combined-output seam (pfctlExec) sees it, like the real CombinedOutput.
	anchorNoise string
	// pfStatus is the `-s info` Status line; defaults to enabled.
	pfStatus string
	// failX, if set, makes `-X` fail with this output.
	failX string
	// failMatch makes any call whose joined args contain it fail once per call.
	failMatch string
}

func (p *fakePf) query(args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	p.calls = append(p.calls, pfCall{args: append([]string(nil), args...)})
	switch {
	case joined == "-sr":
		return []byte(p.mainRuleset), nil
	case strings.HasSuffix(joined, "-sr"):
		return []byte(p.anchorRules), nil
	case joined == "-s info":
		st := p.pfStatus
		if st == "" {
			st = "Enabled"
		}
		return []byte("Status: " + st + "\n"), nil
	}
	return nil, nil
}

func (p *fakePf) exec(stdin string, args ...string) ([]byte, error) {
	p.calls = append(p.calls, pfCall{stdin: stdin, args: append([]string(nil), args...)})
	joined := strings.Join(args, " ")
	if p.failMatch != "" && strings.Contains(joined, p.failMatch) {
		return []byte("pfctl: injected failure"), errors.New("exit status 1")
	}
	switch {
	case joined == "-sr":
		return []byte(p.mainRuleset), nil
	case strings.HasPrefix(joined, "-a ") && strings.HasSuffix(joined, " -sr"):
		return []byte(p.anchorNoise + p.anchorRules), nil
	case strings.HasPrefix(joined, "-X ") && p.failX != "":
		return []byte(p.failX), errors.New("exit status 1")
	case joined == "-E":
		return []byte("pf enabled\nToken : " + p.token + "\n"), nil
	}
	return nil, nil
}

func (p *fakePf) count(prefix string) int {
	n := 0
	for _, c := range p.calls {
		if strings.HasPrefix(c.String(), prefix) {
			n++
		}
	}
	return n
}

func (p *fakePf) has(s string) bool { return p.count(s) > 0 }

func (p *fakePf) reset() { p.calls = nil }

func setupFakePf(t *testing.T) (*fakePf, string) {
	t.Helper()
	fp := &fakePf{mainRuleset: `anchor "com.apple/*" all`, token: "1234567890"}
	dir := t.TempDir()
	oldExec, oldQuery, oldDir, oldBoot := pfctlExec, pfctlQuery, stateDir, bootID
	pfctlExec = fp.exec
	pfctlQuery = fp.query
	stateDir = dir
	bootID = func() (string, error) { return "boot-A", nil }
	t.Cleanup(func() { pfctlExec, pfctlQuery, stateDir, bootID = oldExec, oldQuery, oldDir, oldBoot })
	return fp, dir
}

func newTestFw() *DarwinFirewall {
	return NewPlatformFirewall().(*DarwinFirewall)
}

func assertNoEnableDisable(t *testing.T, fp *fakePf) {
	t.Helper()
	for _, c := range fp.calls {
		for _, a := range c.args {
			if a == "-e" || a == "-d" {
				t.Fatalf("forbidden pfctl invocation: %s", c)
			}
		}
	}
}

func lastLoad(fp *fakePf, anchor string) string {
	out := ""
	for _, c := range fp.calls {
		if c.String() == "-a "+anchor+" -f -" {
			out = c.stdin
		}
	}
	return out
}

// --- renderer golden tests ---

func TestRenderDNSOnly(t *testing.T) {
	permits := []DNSPermit{
		{Interface: "utun5", Server: "10.0.0.1"},
		{Interface: "", Server: "1.1.1.1"},
		{Interface: "utun4", Server: "10.0.0.1"},
		{Interface: "utun5", Server: "10.0.0.1"}, // duplicate
	}
	got := renderDNSAnchor(false, permits)
	want := "pass out quick on lo0 proto {tcp, udp} to any port 53\n" +
		"pass out quick proto {tcp, udp} to 1.1.1.1 port 53\n" +
		"pass out quick on utun4 proto {tcp, udp} to 10.0.0.1 port 53\n" +
		"pass out quick on utun5 proto {tcp, udp} to 10.0.0.1 port 53\n" +
		"block drop out quick proto {tcp, udp} to any port 53\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	main, err := renderMainAnchor(false, nil, permits)
	if err != nil || main != "anchor \"dns\"\n" {
		t.Fatalf("main = %q, %v", main, err)
	}
	if m, _ := renderMainAnchor(false, nil, nil); m != "" {
		t.Fatalf("empty model must render empty main, got %q", m)
	}
	if renderDNSAnchor(false, nil) != "" {
		t.Fatal("empty permits must render empty DNS anchor")
	}
}

func TestRenderKillSwitchPlusDNS(t *testing.T) {
	tunnels := map[string][]string{"utun4": {"203.0.113.1:51820"}}
	main, err := renderMainAnchor(true, tunnels, []DNSPermit{{Interface: "utun4", Server: "10.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := buildKillSwitchRulesForTunnels(tunnels)
	if main != want {
		t.Fatalf("kill-switch main anchor must be the existing renderer output")
	}
	if !strings.Contains(main, "anchor \"dns\"\n") {
		t.Fatal("kill-switch rules must reference the dns sub-anchor")
	}
	dns := renderDNSAnchor(true, []DNSPermit{{Interface: "utun4", Server: "10.0.0.1"}})
	if !strings.Contains(dns, "pass out quick on utun4 proto {tcp, udp} to 10.0.0.1 port 53\n") {
		t.Fatalf("missing pinned permit:\n%s", dns)
	}
}

func TestRenderKillSwitchDropsUnpinned(t *testing.T) {
	dns := renderDNSAnchor(true, []DNSPermit{
		{Interface: "", Server: "1.1.1.1"},
		{Interface: "utun4", Server: "10.0.0.1"},
	})
	if strings.Contains(dns, "1.1.1.1") {
		t.Fatalf("unpinned permit must be dropped in kill-switch mode:\n%s", dns)
	}
	if !strings.Contains(dns, "10.0.0.1") {
		t.Fatalf("pinned permit must survive:\n%s", dns)
	}
	if renderDNSAnchor(true, []DNSPermit{{Server: "1.1.1.1"}}) != "" {
		t.Fatal("only-unpinned set in kill-switch mode must render nothing")
	}
}

func TestRenderLoopbackExemptionPresent(t *testing.T) {
	dns := renderDNSAnchor(false, []DNSPermit{{Server: "9.9.9.9"}})
	lo := strings.Index(dns, "on lo0 proto {tcp, udp} to any port 53")
	block := strings.Index(dns, "block drop out quick")
	if lo < 0 || block < 0 || lo > block {
		t.Fatalf("lo0 pass must precede the block:\n%s", dns)
	}
}

func TestRenderSkipsInvalidEntries(t *testing.T) {
	permits := []DNSPermit{
		{Interface: "utun4;rm", Server: "10.0.0.1"},
		{Interface: "utun4", Server: "not-an-ip"},
		{Interface: "UTUN4", Server: "10.0.0.2"},
		{Interface: "utun4", Server: "10.0.0.3"},
	}
	got := renderDNSAnchor(false, permits)
	if strings.Contains(got, "10.0.0.1") || strings.Contains(got, "not-an-ip") || strings.Contains(got, "10.0.0.2") {
		t.Fatalf("invalid entries leaked into rules:\n%s", got)
	}
	if !strings.Contains(got, "to 10.0.0.3 port 53") {
		t.Fatalf("valid entry missing:\n%s", got)
	}
	if clean := sanitizePermits(permits); len(clean) != 1 {
		t.Fatalf("sanitize kept %d entries, want 1", len(clean))
	}
}

// --- state machine ---

func TestSetDNSPermitsThenNilTearsDown(t *testing.T) {
	fp, dir := setupFakePf(t)
	fw := newTestFw()

	if err := fw.SetDNSPermits([]DNSPermit{{Interface: "utun4", Server: "10.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	if !fw.IsDNSProtectionEnabled() {
		t.Fatal("DNS protection should be enabled")
	}
	if fp.count("-E") != 1 {
		t.Fatalf("expected one -E, calls: %v", fp.calls)
	}
	if !strings.Contains(lastLoad(fp, dnsAnchorName), "10.0.0.1") {
		t.Fatal("DNS anchor not loaded")
	}
	if lastLoad(fp, anchorName) != "anchor \"dns\"\n" {
		t.Fatalf("main anchor = %q", lastLoad(fp, anchorName))
	}
	data, err := os.ReadFile(filepath.Join(dir, pfTokenFile))
	if err != nil {
		t.Fatalf("token file missing: %v", err)
	}
	if !strings.Contains(string(data), `"token":1234567890`) || !strings.Contains(string(data), `"boot_id":"boot-A"`) {
		t.Fatalf("token file = %s", data)
	}
	if fi, _ := os.Stat(filepath.Join(dir, pfTokenFile)); fi.Mode().Perm() != 0600 {
		t.Fatalf("token file mode = %v", fi.Mode().Perm())
	}

	fp.reset()
	if err := fw.SetDNSPermits(nil); err != nil {
		t.Fatal(err)
	}
	if fw.IsDNSProtectionEnabled() {
		t.Fatal("DNS protection should be disabled")
	}
	if !fp.has("-a "+dnsAnchorName+" -F rules") || !fp.has("-a "+anchorName+" -F all") {
		t.Fatalf("both anchors must be flushed: %v", fp.calls)
	}
	if !fp.has("-X 1234567890") {
		t.Fatalf("token must be released: %v", fp.calls)
	}
	if _, err := os.Stat(filepath.Join(dir, pfTokenFile)); !os.IsNotExist(err) {
		t.Fatal("token file must be removed")
	}
	assertNoEnableDisable(t, fp)
}

func TestSecondSetDoesNotReEnable(t *testing.T) {
	fp, _ := setupFakePf(t)
	fw := newTestFw()
	if err := fw.SetDNSPermits([]DNSPermit{{Interface: "utun4", Server: "10.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	if err := fw.SetDNSPermits([]DNSPermit{{Interface: "utun4", Server: "10.0.0.1"}, {Server: "1.1.1.1"}}); err != nil {
		t.Fatal(err)
	}
	if fp.count("-E") != 1 {
		t.Fatalf("-E ran %d times", fp.count("-E"))
	}
	assertNoEnableDisable(t, fp)
}

func TestKillSwitchToggleNeverResurrectsDNS(t *testing.T) {
	fp, _ := setupFakePf(t)
	fw := newTestFw()
	if err := fw.SetDNSPermits([]DNSPermit{{Interface: "utun4", Server: "10.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	if err := fw.SetDNSPermits(nil); err != nil {
		t.Fatal(err)
	}
	fp.reset()
	if err := fw.EnableKillSwitch("utun4", nil, []string{"203.0.113.1:51820"}); err != nil {
		t.Fatal(err)
	}
	if got := lastLoad(fp, dnsAnchorName); got != "" {
		t.Fatalf("DNS anchor must not be loaded with empty permits, got %q", got)
	}
	if err := fw.DisableKillSwitch(); err != nil {
		t.Fatal(err)
	}
	if got := lastLoad(fp, dnsAnchorName); got != "" {
		t.Fatalf("DNS rules resurrected: %q", got)
	}
	if fw.IsDNSProtectionEnabled() || fw.IsKillSwitchEnabled() {
		t.Fatal("state should be fully off")
	}
	if !fp.has("-X 1234567890") {
		t.Fatalf("pf reference must be released when the kill switch goes off: %v", fp.calls)
	}
	assertNoEnableDisable(t, fp)
}

func TestKillSwitchOffKeepsDNSOnlyRules(t *testing.T) {
	fp, _ := setupFakePf(t)
	fw := newTestFw()
	_ = fw.SetDNSPermits([]DNSPermit{{Interface: "utun4", Server: "10.0.0.1"}})
	_ = fw.EnableKillSwitch("utun4", nil, nil)
	fp.reset()
	if err := fw.DisableKillSwitch(); err != nil {
		t.Fatal(err)
	}
	if lastLoad(fp, anchorName) != "anchor \"dns\"\n" {
		t.Fatalf("main anchor = %q", lastLoad(fp, anchorName))
	}
	if fp.has("-X") {
		t.Fatal("pf reference must stay held while DNS rules remain")
	}
}

func TestRecoverFromCrashNoFilesStillFlushes(t *testing.T) {
	fp, _ := setupFakePf(t)
	fw := newTestFw()
	if fw.RecoverFromCrash() {
		t.Fatal("nothing found, expected false")
	}
	if !fp.has("-a "+dnsAnchorName+" -F rules") || !fp.has("-a "+anchorName+" -F all") {
		t.Fatalf("recovery must flush both anchors: %v", fp.calls)
	}
	assertNoEnableDisable(t, fp)
}

func TestRecoverFromCrashReportsLoadedAnchor(t *testing.T) {
	fp, _ := setupFakePf(t)
	fp.anchorRules = "block drop out quick proto tcp to any port 53"
	if !newTestFw().RecoverFromCrash() {
		t.Fatal("stale rules present, expected true")
	}
}

func TestRecoverStaleBootTokenDeletedWithoutRelease(t *testing.T) {
	fp, dir := setupFakePf(t)
	path := filepath.Join(dir, pfTokenFile)
	if err := os.WriteFile(path, []byte(`{"token":42,"boot_id":"boot-OLD"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if !newTestFw().RecoverFromCrash() {
		t.Fatal("token file found, expected true")
	}
	if fp.has("-X") {
		t.Fatalf("stale token must not be released: %v", fp.calls)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("stale token file must be deleted")
	}
}

func TestRecoverCurrentBootTokenReleased(t *testing.T) {
	fp, dir := setupFakePf(t)
	path := filepath.Join(dir, pfTokenFile)
	if err := os.WriteFile(path, []byte(`{"token":42,"boot_id":"boot-A"}`), 0600); err != nil {
		t.Fatal(err)
	}
	newTestFw().RecoverFromCrash()
	if !fp.has("-X 42") {
		t.Fatalf("current-boot token must be released: %v", fp.calls)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("token file must be deleted after release")
	}
}

func TestRecoverLegacyStateFileDeletedWithoutDisablingPf(t *testing.T) {
	fp, dir := setupFakePf(t)
	legacy := filepath.Join(dir, legacyPfStateFile)
	if err := os.WriteFile(legacy, []byte("0"), 0600); err != nil {
		t.Fatal(err)
	}
	if !newTestFw().RecoverFromCrash() {
		t.Fatal("legacy file found, expected true")
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("legacy file must be deleted")
	}
	assertNoEnableDisable(t, fp)
}

func TestMainRulesetReloadedOnlyWhenAnchorMissing(t *testing.T) {
	fp, _ := setupFakePf(t)
	fw := newTestFw()
	_ = fw.SetDNSPermits([]DNSPermit{{Server: "1.1.1.1"}})
	if fp.has("-f /etc/pf.conf") {
		t.Fatal("pf.conf must not be reloaded when the anchor is already evaluated")
	}
	fp2, _ := setupFakePf(t)
	fp2.mainRuleset = ""
	fw2 := newTestFw()
	_ = fw2.SetDNSPermits([]DNSPermit{{Server: "1.1.1.1"}})
	if !fp2.has("-f /etc/pf.conf") {
		t.Fatal("pf.conf must be reloaded when the main ruleset lacks the anchor")
	}
	assertNoEnableDisable(t, fp2)
}

func TestCleanupFlushesAndReleases(t *testing.T) {
	fp, dir := setupFakePf(t)
	fw := newTestFw()
	_ = fw.EnableKillSwitch("utun4", nil, nil)
	_ = fw.SetDNSPermits([]DNSPermit{{Interface: "utun4", Server: "10.0.0.1"}})
	fp.reset()
	if err := fw.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if !fp.has("-X 1234567890") {
		t.Fatalf("cleanup must release token: %v", fp.calls)
	}
	if fw.IsKillSwitchEnabled() || fw.IsDNSProtectionEnabled() {
		t.Fatal("model must be cleared")
	}
	if _, err := os.Stat(filepath.Join(dir, pfTokenFile)); !os.IsNotExist(err) {
		t.Fatal("token file must be removed")
	}
	assertNoEnableDisable(t, fp)
}

func TestEnableDNSProtectionIgnoresSearchDomains(t *testing.T) {
	fp, _ := setupFakePf(t)
	fw := newTestFw()
	if err := fw.EnableDNSProtection("utun4", []string{"corp.lan", "10.0.0.1", "~x.y"}); err != nil {
		t.Fatal(err)
	}
	dns := lastLoad(fp, dnsAnchorName)
	if !strings.Contains(dns, "on utun4") || strings.Contains(dns, "corp.lan") {
		t.Fatalf("dns anchor:\n%s", dns)
	}
	fp.reset()
	if err := fw.EnableDNSProtection("utun4", []string{"corp.lan"}); err != nil {
		t.Fatalf("search-domain-only list must not error: %v", err)
	}
	if len(fp.calls) != 0 {
		t.Fatalf("search-domain-only list must be a no-op: %v", fp.calls)
	}
	if err := fw.DisableDNSProtection(); err != nil {
		t.Fatal(err)
	}
	if fw.IsDNSProtectionEnabled() {
		t.Fatal("expected disabled")
	}
}

func TestRecoverFromCrashIgnoresPfctlStderrNoise(t *testing.T) {
	fp, _ := setupFakePf(t)
	fp.anchorNoise = "No ALTQ support in kernel\nALTQ related functions disabled\n"
	if newTestFw().RecoverFromCrash() {
		t.Fatal("empty anchors with stderr noise must not count as recovered rules")
	}
}

func TestMainRulesetScrubAnchorDoesNotCount(t *testing.T) {
	fp, _ := setupFakePf(t)
	fp.mainRuleset = "scrub-anchor \"com.apple/*\" all fragment reassemble\npass out all\n"
	_ = newTestFw().SetDNSPermits([]DNSPermit{{Server: "1.1.1.1"}})
	if !fp.has("-f /etc/pf.conf") {
		t.Fatal("scrub-anchor alone must not satisfy the main-ruleset check")
	}
}

func TestFailedReleaseOnStoppedPfDropsToken(t *testing.T) {
	fp, dir := setupFakePf(t)
	fw := newTestFw()
	if err := fw.EnableKillSwitch("utun4", nil, nil); err != nil {
		t.Fatal(err)
	}
	fp.failX = "pfctl: pf not enabled"
	fp.pfStatus = "Disabled"
	if err := fw.DisableKillSwitch(); err != nil {
		t.Fatalf("stale token must not make disable fail: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, pfTokenFile)); !os.IsNotExist(err) {
		t.Fatal("token file must be removed")
	}
	fp.reset()
	fp.failX = ""
	if err := fw.EnableKillSwitch("utun4", nil, nil); err != nil {
		t.Fatal(err)
	}
	if fp.count("-E") != 1 {
		t.Fatalf("re-enable must take a fresh -E, calls: %v", fp.calls)
	}
}

func TestHeldTokenButPfDisabledReacquires(t *testing.T) {
	fp, _ := setupFakePf(t)
	fw := newTestFw()
	if err := fw.EnableKillSwitch("utun4", nil, nil); err != nil {
		t.Fatal(err)
	}
	fp.reset()
	fp.pfStatus = "Disabled"
	if err := fw.AddKillSwitchTunnel("utun5", nil, nil); err != nil {
		t.Fatal(err)
	}
	if fp.count("-E") != 1 {
		t.Fatalf("pf disabled externally: expected a fresh -E, calls: %v", fp.calls)
	}
}

func TestFailedReleaseTimeoutKeepsToken(t *testing.T) {
	fp, dir := setupFakePf(t)
	fw := newTestFw()
	_ = fw.EnableKillSwitch("utun4", nil, nil)
	fp.failX = "signal: killed"
	if err := fw.Cleanup(); err == nil {
		t.Fatal("a non-rejection -X failure while pf runs must be reported")
	}
	if _, err := os.Stat(filepath.Join(dir, pfTokenFile)); err != nil {
		t.Fatal("token file must be kept when -X failed for another reason")
	}
}

func TestMainLoadFailureRollsBackDNSAnchorAndModel(t *testing.T) {
	fp, _ := setupFakePf(t)
	fw := newTestFw()
	permits := []DNSPermit{{Server: "1.1.1.1"}, {Interface: "utun4", Server: "10.0.0.1"}}
	if err := fw.SetDNSPermits(permits); err != nil {
		t.Fatal(err)
	}
	dnsBefore := lastLoad(fp, dnsAnchorName)
	fp.failMatch = "-a " + anchorName + " -f -"
	if err := fw.EnableKillSwitch("utun4", nil, nil); err == nil {
		t.Fatal("expected failure")
	}
	if fw.IsKillSwitchEnabled() {
		t.Fatal("model must be restored after a failed enable")
	}
	if !fw.IsDNSProtectionEnabled() {
		t.Fatal("DNS permits must be restored")
	}
	if got := lastLoad(fp, dnsAnchorName); got != dnsBefore {
		t.Fatalf("DNS anchor not rolled back:\n%s\nwant:\n%s", got, dnsBefore)
	}
}

func TestDisableMainLoadFailureRollsBackDNSAnchor(t *testing.T) {
	fp, _ := setupFakePf(t)
	fw := newTestFw()
	_ = fw.SetDNSPermits([]DNSPermit{{Server: "1.1.1.1"}, {Interface: "utun4", Server: "10.0.0.1"}})
	if err := fw.EnableKillSwitch("utun4", nil, nil); err != nil {
		t.Fatal(err)
	}
	dnsBefore := lastLoad(fp, dnsAnchorName)
	if strings.Contains(dnsBefore, "1.1.1.1") {
		t.Fatalf("kill-switch DNS anchor must not carry unpinned permits:\n%s", dnsBefore)
	}
	fp.failMatch = "-a " + anchorName + " -f -"
	if err := fw.DisableKillSwitch(); err == nil {
		t.Fatal("expected failure")
	}
	if !fw.IsKillSwitchEnabled() {
		t.Fatal("kill switch model must be restored")
	}
	if got := lastLoad(fp, dnsAnchorName); got != dnsBefore {
		t.Fatalf("DNS anchor left open after failed disable:\n%s", got)
	}
}
