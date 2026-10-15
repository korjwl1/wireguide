//go:build darwin

package firewall

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// fakePFKernel models the xnu reference semantics pfctl exposes
// (bsd/net/pf_ioctl.c): DIOCSTARTREF (-E) starts PF and issues a token,
// DIOCSTOP (-d) stops PF and invalidates every token, and DIOCSTOPREF (-X)
// fails with ENOENT while stopped and EINVAL for an unknown token. The error
// texts are the ones /sbin/pfctl prints ("pf not enabled", "pf: token
// invalid"); its success line is "Token : %llu".
type fakePFKernel struct {
	running bool
	next    uint64
	tokens  map[string]bool
	anchors map[string]string
	calls   []string
}

func stubPFKernel(t *testing.T) *fakePFKernel {
	t.Helper()
	stubPF(t)
	k := &fakePFKernel{next: 100, tokens: map[string]bool{}, anchors: map[string]string{}}
	runPfctl = func(args ...string) ([]byte, error) {
		k.calls = append(k.calls, strings.Join(args, " "))
		switch args[0] {
		case "-E":
			k.next++
			tok := fmt.Sprint(k.next)
			k.tokens[tok] = true
			k.running = true
			return []byte("pf enabled\nToken : " + tok + "\n"), nil
		case "-X":
			if !k.running {
				return []byte("pfctl: pf not enabled\n"), errors.New("exit status 1")
			}
			if !k.tokens[args[1]] {
				return []byte("pf: token invalid\n"), errors.New("exit status 1")
			}
			delete(k.tokens, args[1])
			if len(k.tokens) == 0 {
				k.running = false
			}
			return nil, nil
		case "-si":
			if k.running {
				return []byte("Status: Enabled for 0 days 00:00:01"), nil
			}
			return []byte("Status: Disabled for 0 days 00:00:01"), nil
		case "-s":
			if len(k.tokens) == 0 {
				return []byte("No pf starter references held\n"), nil
			}
			out := "TOKENS:\nPID Process Name TOKEN TIMESTAMP\n"
			for token := range k.tokens {
				out += "123 pfctl " + token + " 0 days 00:00:01\n"
			}
			return []byte(out), nil
		case "-sr":
			return []byte("anchor \"com.apple/*\" all\n"), nil
		case "-a":
			delete(k.anchors, args[1])
		}
		return nil, nil
	}
	loadAnchorRules = func(anchor, rules string) error {
		k.anchors[anchor] = rules
		return nil
	}
	return k
}

// externalDisable is `pfctl -d` run by another tool or the user.
func (k *fakePFKernel) externalDisable() {
	k.running = false
	k.tokens = map[string]bool{}
}

func TestPFHeldTokenIsRetakenAfterExternalDisable(t *testing.T) {
	k := stubPFKernel(t)
	if err := enablePf(); err != nil {
		t.Fatal(err)
	}
	k.externalDisable()
	if err := enablePf(); err != nil {
		t.Fatal(err)
	}
	if !k.running || pfLease.state.Token != "102" {
		t.Fatalf("stale reference kept: running=%v token=%q calls=%v", k.running, pfLease.state.Token, k.calls)
	}
	data, err := os.ReadFile(savedPfStateFile)
	if err != nil || !strings.Contains(string(data), `"token":"102"`) {
		t.Fatalf("journal does not record the live token: %s %v", data, err)
	}
}

func TestPFReferenceQueryFailureKeepsHeldToken(t *testing.T) {
	k := stubPFKernel(t)
	if err := enablePf(); err != nil {
		t.Fatal(err)
	}
	good := runPfctl
	runPfctl = func(args ...string) ([]byte, error) {
		if args[0] == "-s" {
			return nil, errors.New("pfctl timed out")
		}
		return good(args...)
	}
	if err := enablePf(); err == nil {
		t.Fatal("unverifiable PF state reported as enforced")
	}
	if pfLease.state.Token != "101" || len(k.tokens) != 1 {
		t.Fatalf("a status hiccup dropped or duplicated the reference: token=%q tokens=%v", pfLease.state.Token, k.tokens)
	}
}

func TestPFReleaseOfInvalidatedTokenSucceeds(t *testing.T) {
	cases := map[string]func(k *fakePFKernel){
		"stopped externally": func(k *fakePFKernel) { k.externalDisable() },
		"restarted by another owner": func(k *fakePFKernel) {
			k.externalDisable()
			k.running, k.tokens["999"] = true, true // pfctl -d; someone -E
		},
	}
	for name, invalidate := range cases {
		t.Run(name, func(t *testing.T) {
			k := stubPFKernel(t)
			if err := enablePf(); err != nil {
				t.Fatal(err)
			}
			invalidate(k)
			if err := disablePf(); err != nil {
				t.Fatalf("invalidated token wedged release: %v", err)
			}
			if pfLease.state.Token != "" {
				t.Fatal("invalidated token retained")
			}
			removePfStateFile()
			if _, err := os.Stat(savedPfStateFile); !os.IsNotExist(err) {
				t.Fatal("journal retained an invalidated token")
			}
			if name == "restarted by another owner" && (!k.running || !k.tokens["999"]) {
				t.Fatal("another owner's reference was released")
			}
		})
	}
}

// Unrecognized failure while PF verifiably runs: the token may be live.
func TestPFReleaseKeepsTokenOnUnexplainedFailure(t *testing.T) {
	k := stubPFKernel(t)
	if err := enablePf(); err != nil {
		t.Fatal(err)
	}
	good := runPfctl
	runPfctl = func(args ...string) ([]byte, error) {
		if args[0] == "-X" {
			return []byte("pfctl: DIOCSTOPREF: Device busy\n"), errors.New("exit status 1")
		}
		return good(args...)
	}
	if err := disablePf(); err == nil || pfLease.state.Token == "" || !k.tokens["101"] {
		t.Fatal("possibly-live reference dropped")
	}
}

func TestRecoveryReleasesInvalidatedSameBootToken(t *testing.T) {
	k := stubPFKernel(t)
	if err := writePfLease(pfLeaseState{Token: "42", Boot: "boot-a"}); err != nil {
		t.Fatal(err)
	}
	if !RecoverSavedRules() {
		t.Fatalf("dead token blocked recovery: %v", k.calls)
	}
	if _, err := os.Stat(savedPfStateFile); !os.IsNotExist(err) {
		t.Fatal("recovery kept the dead token journal")
	}
	f := NewPlatformFirewall()
	if err := f.EnableKillSwitch("utun4", nil, nil); err != nil || !k.running {
		t.Fatalf("PF not enabled after recovery: err=%v running=%v calls=%v", err, k.running, k.calls)
	}
}

// Issue #48 review H-1: after an external `pfctl -d` the kill switch must be
// restorable and removable instead of reporting enabled while unenforced.
func TestKillSwitchSurvivesExternalPFDisable(t *testing.T) {
	k := stubPFKernel(t)
	f := NewPlatformFirewall().(*DarwinFirewall)
	if err := f.EnableKillSwitch("utun4", nil, []string{"203.0.113.1:51820"}); err != nil {
		t.Fatal(err)
	}
	if err := f.EnableDNSProtection([]DNSAllow{{Interface: "utun4", Servers: []string{"10.0.0.1"}}}); err != nil {
		t.Fatal(err)
	}
	k.externalDisable()
	delete(k.anchors, anchorName) // the repair must not depend on surviving rules
	repaired, err := f.RepairEnforcement()
	if err != nil || !repaired || !k.running {
		t.Fatalf("repair: repaired=%v err=%v running=%v", repaired, err, k.running)
	}
	if !strings.Contains(k.anchors[anchorName], "block drop out all") ||
		!strings.Contains(k.anchors[dnsAnchorName], "to 10.0.0.1 port 53") {
		t.Fatalf("repair did not restore the model: %v", k.anchors)
	}
	if repaired, err := f.RepairEnforcement(); repaired || err != nil {
		t.Fatalf("healthy PF repaired again: %v %v", repaired, err)
	}

	k.externalDisable()
	if err := f.DisableDNSProtection(); err != nil {
		t.Fatal(err)
	}
	if err := f.DisableKillSwitch(); err != nil || f.IsKillSwitchEnabled() {
		t.Fatalf("disable wedged after external pfctl -d: err=%v enabled=%v", err, f.IsKillSwitchEnabled())
	}
	if _, err := os.Stat(savedPfStateFile); !os.IsNotExist(err) {
		t.Fatal("journal kept after a clean disable")
	}
}

func TestDNSOnlyProtectionRepairedAfterExternalDisable(t *testing.T) {
	k := stubPFKernel(t)
	f := NewPlatformFirewall().(*DarwinFirewall)
	if err := f.EnableDNSProtection([]DNSAllow{{Servers: []string{"1.1.1.1"}}}); err != nil {
		t.Fatal(err)
	}
	k.externalDisable()
	if repaired, err := f.RepairEnforcement(); err != nil || !repaired || !k.running {
		t.Fatalf("repair: %v %v running=%v", repaired, err, k.running)
	}
	if !strings.Contains(k.anchors[anchorName], "pass out quick proto {tcp, udp} to 1.1.1.1 port 53") {
		t.Fatalf("DNS-only rules not restored: %q", k.anchors[anchorName])
	}
}

func TestRepairEnforcementIsNoopWithoutProtectionOrWhilePFRuns(t *testing.T) {
	k := stubPFKernel(t)
	f := NewPlatformFirewall().(*DarwinFirewall)
	if repaired, err := f.RepairEnforcement(); repaired || err != nil || len(k.calls) != 0 {
		t.Fatalf("idle backend touched PF: %v %v %v", repaired, err, k.calls)
	}
	if err := f.EnableKillSwitch("", nil, nil); err != nil {
		t.Fatal(err)
	}
	k.calls = nil
	if repaired, err := f.RepairEnforcement(); repaired || err != nil || strings.Join(k.calls, ",") != "-s References" {
		t.Fatalf("healthy PF was modified: %v %v %v", repaired, err, k.calls)
	}
}

// Review L-1: only a FILTER anchor line makes pf evaluate our rules.
func TestMainRulesetMarkerRequiresFilterAnchor(t *testing.T) {
	for _, tc := range []struct {
		ruleset string
		reload  bool
	}{
		{"scrub-anchor \"com.apple/*\" all fragment reassemble\n", true},
		{"nat-anchor \"com.apple/*\" all\nrdr-anchor \"com.apple/*\" all\n", true},
		{"scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n", false},
		{"  anchor \"com.apple/*\" all\n", false},
	} {
		calls := stubPF(t)
		ruleset := tc.ruleset
		good := runPfctl
		runPfctl = func(args ...string) ([]byte, error) {
			if args[0] == "-sr" {
				*calls = append(*calls, "-sr")
				return []byte(ruleset), nil
			}
			return good(args...)
		}
		if err := loadDefaultPfRuleset(); err != nil {
			t.Fatal(err)
		}
		reloaded := strings.Contains(strings.Join(*calls, ","), "-f /etc/pf.conf")
		if reloaded != tc.reload {
			t.Fatalf("ruleset %q: reloaded=%v want %v", tc.ruleset, reloaded, tc.reload)
		}
	}
}

// Review M-4: with the kill switch on, the DNS sub-anchor (evaluated before
// block-all) must not carry an unpinned resolver exception; the permit comes
// back when the kill switch is turned off.
func TestKillSwitchExcludesUnpinnedDNSPermits(t *testing.T) {
	k := stubPFKernel(t)
	allow := []DNSAllow{
		{Servers: []string{"1.1.1.1"}},
		{Interface: "utun4", Servers: []string{"10.0.0.1"}},
	}
	const offTunnel = "pass out quick proto {tcp, udp} to 1.1.1.1 port 53"
	f := NewPlatformFirewall().(*DarwinFirewall)
	if err := f.EnableDNSProtection(allow); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(k.anchors[anchorName], offTunnel) {
		t.Fatalf("DNS-only mode lost the off-tunnel permit: %q", k.anchors[anchorName])
	}
	if err := f.EnableKillSwitch("utun4", nil, nil); err != nil {
		t.Fatal(err)
	}
	sub := k.anchors[dnsAnchorName]
	if strings.Contains(sub, offTunnel) || !strings.Contains(sub, "pass out quick on utun4 proto {tcp, udp} to 10.0.0.1 port 53") {
		t.Fatalf("kill-switch DNS sub-anchor:\n%s", sub)
	}
	// Re-applying while the kill switch is on keeps the narrowed set.
	if err := f.EnableDNSProtection(allow); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(k.anchors[dnsAnchorName], offTunnel) {
		t.Fatalf("re-apply under kill switch punched a hole:\n%s", k.anchors[dnsAnchorName])
	}
	if err := f.DisableKillSwitch(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(k.anchors[anchorName], offTunnel) {
		t.Fatalf("off-tunnel permit not restored without kill switch: %q", k.anchors[anchorName])
	}
}
