//go:build darwin

package network

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
)

// fakeSystem stubs every external seam the split-DNS path touches.
type fakeSystem struct {
	mu       sync.Mutex
	scripts  []string
	runCalls [][]string
	flushes  int
	// showOut is returned for "show" scripts; listOut for "list" scripts.
	// When empty, "show" renders the keys installed via "set" like scutil does.
	showOut   string
	installed map[string]string
	listOut   string
	// removeOut is the stdout of remove scripts (e.g. "  No such key").
	removeOut string
}

func installFakeSystem(t *testing.T) *fakeSystem {
	t.Helper()
	f := &fakeSystem{installed: map[string]string{}}
	origScutil, origRun, origFlush := scutilExec, run, flushDNSCache
	scutilExec = func(script string) ([]byte, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.scripts = append(f.scripts, script)
		switch {
		case strings.HasPrefix(script, "show "):
			if f.showOut != "" {
				return []byte(f.showOut), nil
			}
			key := strings.TrimSpace(strings.SplitN(strings.TrimPrefix(script, "show "), "\n", 2)[0])
			return []byte(f.installed[key]), nil
		case strings.Contains(script, "\nset "):
			f.installed[fakeSetKey(script)] = fakeShow(script)
			return nil, nil
		case strings.HasPrefix(script, "list "):
			return []byte(f.listOut), nil
		case strings.HasPrefix(script, "remove "):
			return []byte(f.removeOut), nil
		}
		return nil, nil
	}
	run = func(name string, args ...string) error {
		f.mu.Lock()
		f.runCalls = append(f.runCalls, append([]string{name}, args...))
		f.mu.Unlock()
		return nil
	}
	flushDNSCache = func() { f.mu.Lock(); f.flushes++; f.mu.Unlock() }
	t.Cleanup(func() { scutilExec, run, flushDNSCache = origScutil, origRun, origFlush })
	return f
}

func fakeSetKey(script string) string {
	i := strings.Index(script, "\nset ") + len("\nset ")
	return strings.TrimSpace(strings.SplitN(script[i:], "\n", 2)[0])
}

// fakeShow renders the d.add array lines of a script as scutil show would.
func fakeShow(script string) string {
	var b strings.Builder
	b.WriteString("<dictionary> {\n")
	for _, line := range strings.Split(script, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "d.add" || f[2] != "*" {
			continue
		}
		fmt.Fprintf(&b, "  %s : <array> {\n", f[1])
		for i, v := range f[3:] {
			fmt.Fprintf(&b, "    %d : %s\n", i, v)
		}
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func (f *fakeSystem) removed() []string {
	var keys []string
	for _, s := range f.scripts {
		if strings.HasPrefix(s, "remove ") {
			keys = append(keys, strings.TrimSpace(strings.SplitN(strings.TrimPrefix(s, "remove "), "\n", 2)[0]))
		}
	}
	return keys
}

func TestBuildSplitDNSScriptGolden(t *testing.T) {
	got, err := buildSplitDNSScript("utun5", splitKindMatch, []string{"192.168.1.1", "fd00::1"},
		[]string{"intranet.example", "1.168.192.in-addr.arpa"}, true)
	if err != nil {
		t.Fatal(err)
	}
	want := "d.init\n" +
		"d.add ServerAddresses * 192.168.1.1 fd00::1\n" +
		"d.add SupplementalMatchDomains * intranet.example 1.168.192.in-addr.arpa\n" +
		"d.add SupplementalMatchDomainsNoSearch # 1\n" +
		"set State:/Network/Service/com.wireguide.utun5.match/DNS\n" +
		"quit\n"
	if got != want {
		t.Fatalf("script mismatch\n got: %q\nwant: %q", got, want)
	}
	search, err := buildSplitDNSScript("utun5", splitKindSearch, []string{"192.168.1.1"}, []string{"corp.example"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(search, "NoSearch # 0\n") || !strings.Contains(search, "set State:/Network/Service/com.wireguide.utun5.search/DNS\n") {
		t.Fatalf("search script wrong: %q", search)
	}
	for _, bad := range []string{"InterfaceName", "IPv4", "SearchDomains "} {
		if strings.Contains(got+search, bad) {
			t.Fatalf("script must not contain %q", bad)
		}
	}
}

func TestBuildSplitDNSScriptRejectsInjection(t *testing.T) {
	good := []string{"192.168.1.1"}
	goodDom := []string{"corp.lan"}
	cases := []struct {
		name    string
		iface   string
		servers []string
		domains []string
	}{
		{"newline in domain", "utun5", good, []string{"corp.lan\nremove State:/Network/Global/IPv4"}},
		{"space in domain", "utun5", good, []string{"a b"}},
		{"quote in domain", "utun5", good, []string{`a"b`}},
		{"newline in server", "utun5", []string{"1.1.1.1\nset State:/Network/Global/DNS"}, goodDom},
		{"hostname as server", "utun5", []string{"evil.example"}, goodDom},
		{"bad iface", "utun5/../x", good, goodDom},
		{"iface newline", "utun5\nquit", good, goodDom},
		{"empty iface", "", good, goodDom},
		{"tilde domain", "utun5", good, []string{"~corp.lan"}},
		{"trailing dot", "utun5", good, []string{"corp.lan."}},
		{"too long", "utun5", good, []string{strings.Repeat("a.", 130) + "lan"}},
		{"no servers", "utun5", nil, goodDom},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if s, err := buildSplitDNSScript(c.iface, splitKindMatch, c.servers, c.domains, true); err == nil {
				t.Fatalf("expected rejection, got script %q", s)
			}
		})
	}
}

func TestSetDNSSplitTouchesNoNetworkServices(t *testing.T) {
	f := installFakeSystem(t)
	m := NewPlatformManager().(*DarwinManager)

	if err := m.SetDNS("utun5", []string{"192.168.1.1", "~intranet.example", "corp.example"}); err != nil {
		t.Fatalf("SetDNS split: %v", err)
	}
	if len(f.runCalls) != 0 {
		t.Fatalf("split SetDNS ran external commands via run(): %v", f.runCalls)
	}
	var sets []string
	for _, s := range f.scripts {
		if strings.Contains(s, "\nset ") {
			sets = append(sets, s)
		}
	}
	if len(sets) != 2 {
		t.Fatalf("expected a match and a search key set, got %d: %q", len(sets), f.scripts)
	}
	if !strings.Contains(sets[0], "SupplementalMatchDomains * intranet.example\n") || !strings.Contains(sets[0], "NoSearch # 1") {
		t.Errorf("match script wrong: %q", sets[0])
	}
	if !strings.Contains(sets[1], "SupplementalMatchDomains * corp.example\n") || !strings.Contains(sets[1], "NoSearch # 0") {
		t.Errorf("search script wrong: %q", sets[1])
	}
	if f.flushes == 0 {
		t.Error("DNS cache was not flushed")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dnsActive || m.lastDNS != nil || len(m.savedDNS) != 0 {
		t.Fatalf("split mode touched override state: active=%v lastDNS=%v saved=%v", m.dnsActive, m.lastDNS, m.savedDNS)
	}
}

func TestSetDNSSplitNeedsServerAndFailsClosed(t *testing.T) {
	f := installFakeSystem(t)
	m := NewPlatformManager().(*DarwinManager)
	if err := m.SetDNS("utun5", []string{"~intranet.example"}); err == nil {
		t.Fatal("split without a server must fail")
	}
	if len(f.scripts) != 0 || len(f.runCalls) != 0 {
		t.Fatalf("nothing should have been executed: %q %v", f.scripts, f.runCalls)
	}
}

func TestSetDNSSplitInjectionInstallsNothing(t *testing.T) {
	f := installFakeSystem(t)
	m := NewPlatformManager().(*DarwinManager)
	err := m.SetDNS("utun5", []string{"192.168.1.1", "~ok.lan", "bad.lan\nremove State:/Network/Global/IPv4"})
	if err == nil {
		t.Fatal("expected error for injected domain")
	}
	for _, s := range f.scripts {
		if strings.Contains(s, "Global") {
			t.Fatalf("injected command reached scutil: %q", s)
		}
	}
	if len(f.runCalls) != 0 {
		t.Fatalf("run() called: %v", f.runCalls)
	}
}

func TestSetDNSSplitReadBackFailureCleansUp(t *testing.T) {
	f := installFakeSystem(t)
	f.showOut = "  No such key\n"
	m := NewPlatformManager().(*DarwinManager)
	if err := m.SetDNS("utun5", []string{"192.168.1.1", "~intranet.example"}); err == nil {
		t.Fatal("expected read-back failure")
	}
	if len(f.removed()) == 0 {
		t.Fatal("failed install did not remove its keys")
	}
}

func TestRestoreDNSAndCleanupRemoveKeysWhenNotDNSActive(t *testing.T) {
	for _, name := range []string{"RestoreDNS", "Cleanup"} {
		t.Run(name, func(t *testing.T) {
			f := installFakeSystem(t)
			m := NewPlatformManager().(*DarwinManager)
			var err error
			if name == "RestoreDNS" {
				err = m.RestoreDNS("utun7")
			} else {
				err = m.Cleanup("utun7")
			}
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(f.removed(), " ")
			for _, want := range []string{
				"State:/Network/Service/com.wireguide.utun7.match/DNS",
				"State:/Network/Service/com.wireguide.utun7.search/DNS",
			} {
				if !strings.Contains(got, want) {
					t.Errorf("%s did not remove %s (removed: %s)", name, want, got)
				}
			}
			for _, c := range f.runCalls {
				if c[0] == "networksetup" {
					t.Errorf("unexpected networksetup call %v", c)
				}
			}
		})
	}
}

func TestRemoveSplitDNSIdempotentAndStrict(t *testing.T) {
	f := installFakeSystem(t)
	f.removeOut = "  No such key\n"
	m := NewPlatformManager().(*DarwinManager)
	if err := m.RemoveSplitDNS("utun9"); err != nil {
		t.Fatalf("missing keys must not be an error: %v", err)
	}
	if f.flushes != 0 {
		t.Error("nothing was removed, no flush expected")
	}
	f.removeOut = "something unexpected\n"
	if err := m.RemoveSplitDNS("utun9"); err == nil {
		t.Fatal("unexpected scutil output after remove must be an error")
	}
	n := len(f.scripts)
	if err := m.RemoveSplitDNS("en0; rm"); err != nil || len(f.scripts) != n {
		t.Fatalf("invalid iface must be a silent no-op, err=%v scripts=%d", err, len(f.scripts)-n)
	}
}

func TestCleanupStaleSplitDNSOnlyOurPrefix(t *testing.T) {
	f := installFakeSystem(t)
	f.listOut = "  subKey [0] = State:/Network/Service/com.wireguide.utun5.match/DNS\n" +
		"  subKey [1] = State:/Network/Service/ABCD-1234/DNS\n" +
		"  subKey [2] = State:/Network/Service/com.wireguide.utun6.search/DNS\n" +
		"  subKey [3] = State:/Network/Service/com.wireguideX.evil/DNS\n" +
		"  subKey [4] = State:/Network/Service/NetBird-Match-0/DNS\n" +
		"  subKey [5] = State:/Network/Service/com.wireguide.a b/DNS\n"
	if err := CleanupStaleSplitDNS(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"State:/Network/Service/com.wireguide.utun5.match/DNS",
		"State:/Network/Service/com.wireguide.utun6.search/DNS",
	}
	got := f.removed()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("removed %v, want only %v", got, want)
	}
	if !strings.HasPrefix(f.scripts[0], "list State:/Network/Service/com\\.wireguide\\..*/DNS\n") {
		t.Errorf("list pattern wrong: %q", f.scripts[0])
	}
}

func TestApplyDNSGuardsRefuseSplitTokens(t *testing.T) {
	f := installFakeSystem(t)
	m := NewPlatformManager().(*DarwinManager)
	entries := []string{"1.1.1.1", "~corp.lan"}
	if err := m.applyDNS(entries); err == nil {
		t.Error("applyDNS accepted a split token")
	}
	if err := m.applyDNSIfDrifted(entries); err == nil {
		t.Error("applyDNSIfDrifted accepted a split token")
	}
	m.applyDNSToServices(entries, []string{"Wi-Fi"})
	if len(f.runCalls) != 0 {
		t.Fatalf("networksetup reached with a split token: %v", f.runCalls)
	}
}

func TestParseDNSEntriesSplitIsSeenByDarwin(t *testing.T) {
	p := domain.ParseDNSEntries([]string{"10.0.0.1", "~a.lan", "b.lan"})
	if len(p.Match) != 1 || len(p.Search) != 1 || len(p.Servers) != 1 {
		t.Fatalf("unexpected parse: %+v", p)
	}
}

func TestBuildSplitDNSScriptRejectsOverlongLine(t *testing.T) {
	var doms []string
	for i := 0; i < 32; i++ {
		doms = append(doms, strings.Repeat("a", 60)+fmt.Sprintf("%02d.example.com", i))
	}
	if s, err := buildSplitDNSScript("utun5", splitKindMatch, []string{"192.168.1.1"}, doms, true); err == nil {
		t.Fatalf("expected overlong line rejection, got %q", s)
	}
}

func TestSetSplitDNSRejectsTruncatedReadBack(t *testing.T) {
	f := installFakeSystem(t)
	m := NewPlatformManager().(*DarwinManager)
	// scutil kept the server but dropped the second domain.
	f.showOut = "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 192.168.1.1\n  }\n  SupplementalMatchDomains : <array> {\n    0 : a.loc\n  }\n}\n"
	err := m.SetDNS("utun5", []string{"192.168.1.1", "~a.loc", "~b.loc"})
	if err == nil {
		t.Fatal("expected failure when read-back lacks a domain")
	}
	if len(f.removed()) == 0 {
		t.Fatal("partial install must be rolled back")
	}
}
