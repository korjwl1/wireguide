//go:build darwin

package firewall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stubPF(t *testing.T) *[]string {
	t.Helper()
	oldRun, oldLoad, oldPath, oldBoot := runPfctl, loadAnchorRules, savedPfStateFile, pfBootID
	oldAcquire := acquirePfReference
	oldState := pfLease.state
	pfLease.state = pfLeaseState{}
	savedPfStateFile = filepath.Join(t.TempDir(), "lease")
	pfBootID = func() (string, error) { return "boot-a", nil }
	var calls []string
	runPfctl = func(args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		switch args[0] {
		case "-E":
			return []byte("pf enabled\nToken : 1234567890123456789\n"), nil
		case "-sr":
			return []byte("anchor \"com.apple/*\" all\n"), nil
		case "-si":
			return []byte("Status: Enabled"), nil
		case "-s":
			return []byte("TOKENS:\nPID Process Name TOKEN TIMESTAMP\n42 pfctl 1234567890123456789 0 days 00:00:01\n"), nil
		}
		return nil, nil
	}
	acquirePfReference = func() ([]byte, int, error) {
		out, err := runPfctl("-E")
		return out, 42, err
	}
	loadAnchorRules = func(string, string) error { return nil }
	t.Cleanup(func() {
		runPfctl, loadAnchorRules, savedPfStateFile, pfBootID = oldRun, oldLoad, oldPath, oldBoot
		acquirePfReference = oldAcquire
		pfLease.state = oldState
	})
	return &calls
}

func TestPFLeaseDoesNotDisableOtherOwnersOrAccumulateReferences(t *testing.T) {
	calls := stubPF(t)
	if err := enablePf(); err != nil {
		t.Fatal(err)
	}
	if err := enablePf(); err != nil {
		t.Fatal(err)
	}
	if err := disablePf(); err != nil {
		t.Fatal(err)
	}
	// The second enable verifies PF still runs instead of trusting the cached
	// token; it must not take another reference.
	if got := strings.Join(*calls, ","); got != "-E,-s References,-s References,-X 1234567890123456789" {
		t.Fatalf("ownership calls = %s", got)
	}
}

func TestPFLeaseRecoveryOnlyReleasesSameBootToken(t *testing.T) {
	for _, boot := range []string{"boot-a", "previous-boot"} {
		t.Run(boot, func(t *testing.T) {
			calls := stubPF(t)
			if err := writePfLease(pfLeaseState{Token: "1234567890123456789", Boot: boot, OwnerPID: 42}); err != nil {
				t.Fatal(err)
			}
			if err := disablePf(); err != nil {
				t.Fatal(err)
			}
			if len(*calls) != map[bool]int{true: 2, false: 0}[boot == "boot-a"] {
				t.Fatalf("release calls = %v", *calls)
			}
		})
	}
}

func TestPFLegacyStateNeverGloballyDisablesFirewall(t *testing.T) {
	calls := stubPF(t)
	if err := os.WriteFile(savedPfStateFile, []byte("0"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := disablePf(); err != nil || len(*calls) != 0 {
		t.Fatalf("legacy recovery: %v calls=%v", err, *calls)
	}
}

func TestPFStartupFlushesBothAnchorsWithoutRecoveryJournal(t *testing.T) {
	calls := stubPF(t)
	if !RecoverSavedRules() {
		t.Fatal("startup skipped stale rules when the journal was missing")
	}
	want := "-a com.apple/wireguide/dns -F rules,-a com.apple/wireguide -Fa"
	if got := strings.Join(*calls, ","); got != want {
		t.Fatalf("startup calls = %s, want %s", got, want)
	}
}

func TestPFStartupFlushFailureKeepsLeaseForRecovery(t *testing.T) {
	stubPF(t)
	if err := writePfLease(pfLeaseState{Token: "42", Boot: "boot-a"}); err != nil {
		t.Fatal(err)
	}
	goodRun := runPfctl
	released := false
	runPfctl = func(args ...string) ([]byte, error) {
		if args[0] == "-X" {
			released = true
		}
		if args[0] == "-a" {
			return nil, errors.New("flush failed")
		}
		return goodRun(args...)
	}
	if RecoverSavedRules() || released {
		t.Fatal("failed flush was reported recovered or released the PF lease")
	}
	if _, err := os.Stat(savedPfStateFile); err != nil {
		t.Fatal("failed flush lost the recovery journal")
	}
}

func TestDarwinDNSFlushFailureRetainsProtectionForRetry(t *testing.T) {
	stubPF(t)
	f := &DarwinFirewall{dnsProtectionEnabled: true, savedDNSAllow: []DNSAllow{{Interface: "utun4", Servers: []string{"10.0.0.1"}}}}
	goodRun := runPfctl
	runPfctl = func(args ...string) ([]byte, error) { return nil, errors.New("pf lock unavailable") }
	if err := f.DisableDNSProtection(); err == nil || !f.IsDNSProtectionEnabled() {
		t.Fatal("failed flush was recorded as success")
	}
	runPfctl = goodRun
	if err := f.DisableDNSProtection(); err != nil || f.IsDNSProtectionEnabled() {
		t.Fatalf("flush retry: %v", err)
	}
}

func TestDarwinDNSActivationFailureIsReported(t *testing.T) {
	stubPF(t)
	goodRun := runPfctl
	runPfctl = func(args ...string) ([]byte, error) {
		if args[0] == "-E" {
			return nil, errors.New("activation failed")
		}
		return goodRun(args...)
	}
	f := NewPlatformFirewall()
	if err := f.EnableDNSProtection([]DNSAllow{{Servers: []string{"1.1.1.1"}}}); err == nil || f.IsDNSProtectionEnabled() {
		t.Fatal("failed PF activation was reported as protected")
	}
}

func TestPFActivationFailureRollsBackMainAnchor(t *testing.T) {
	for _, mode := range []string{"dns", "kill-switch", "kill-switch-over-dns"} {
		t.Run(mode, func(t *testing.T) {
			stubPF(t)
			goodRun := runPfctl
			runPfctl = func(args ...string) ([]byte, error) {
				if args[0] == "-E" {
					return nil, errors.New("activation failed")
				}
				return goodRun(args...)
			}
			f := &DarwinFirewall{}
			want := ""
			if mode == "kill-switch-over-dns" {
				f.dnsProtectionEnabled = true
				f.savedDNSAllow = []DNSAllow{{Servers: []string{"1.1.1.1"}}}
				want = pfDNSRules(f.savedDNSAllow, false)
			}
			var mainLoads []string
			loadAnchorRules = func(anchor, rules string) error {
				if anchor == anchorName {
					mainLoads = append(mainLoads, rules)
				}
				return nil
			}
			var err error
			if mode == "dns" {
				err = f.EnableDNSProtection([]DNSAllow{{Servers: []string{"9.9.9.9"}}})
			} else {
				err = f.EnableKillSwitch("utun4", nil, nil)
			}
			if err == nil || len(mainLoads) != 2 || mainLoads[1] != want {
				t.Fatalf("failed activation left uncommitted rules: loads=%q error=%v", mainLoads, err)
			}
		})
	}
}

func TestExistingPFMainRulesArePreserved(t *testing.T) {
	calls := stubPF(t)
	if err := loadDefaultPfRuleset(); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 || (*calls)[0] != "-sr" {
		t.Fatalf("existing main rules replaced: %v", *calls)
	}
}

func TestPFReleaseFailureKeepsJournalUntilRetrySucceeds(t *testing.T) {
	stubPF(t)
	if err := enablePf(); err != nil {
		t.Fatal(err)
	}
	goodRun := runPfctl
	runPfctl = func(args ...string) ([]byte, error) {
		if args[0] == "-X" {
			return nil, errors.New("release failed")
		}
		return goodRun(args...)
	}
	if err := disablePf(); err == nil {
		t.Fatal("release failure hidden")
	}
	removePfStateFile()
	if _, err := os.Stat(savedPfStateFile); err != nil {
		t.Fatal("release failure lost recovery journal")
	}
	runPfctl = goodRun
	if err := disablePf(); err != nil {
		t.Fatal(err)
	}
	removePfStateFile()
	if _, err := os.Stat(savedPfStateFile); !os.IsNotExist(err) {
		t.Fatal("successful release retained stale token")
	}
}

func TestDNSSubAnchorFailureDoesNotReplaceMainRules(t *testing.T) {
	stubPF(t)
	f := &DarwinFirewall{dnsProtectionEnabled: true, savedDNSAllow: []DNSAllow{{Interface: "utun4", Servers: []string{"10.0.0.1"}}}}
	mainChanged := false
	loadAnchorRules = func(anchor, rules string) error {
		if anchor == dnsAnchorName {
			return errors.New("sub-anchor load failed")
		}
		mainChanged = true
		return nil
	}
	if err := f.EnableKillSwitch("utun4", nil, nil); err == nil || mainChanged || f.IsKillSwitchEnabled() {
		t.Fatal("failed DNS migration changed the main rules or reported success")
	}
}

func TestKillSwitchDisableRetainsBothPoliciesIfDNSReplacementFails(t *testing.T) {
	calls := stubPF(t)
	f := &DarwinFirewall{killSwitchEnabled: true, dnsProtectionEnabled: true,
		savedDNSAllow: []DNSAllow{{Interface: "utun4", Servers: []string{"10.0.0.1"}}}}
	loadAnchorRules = func(string, string) error { return errors.New("replacement failed") }
	if err := f.DisableKillSwitch(); err == nil || !f.IsKillSwitchEnabled() || !f.IsDNSProtectionEnabled() || len(*calls) != 0 {
		t.Fatal("failed DNS replacement removed existing protection")
	}
}

func TestCorruptPFLeaseIsQuarantinedWithoutReleasingUnknownOwner(t *testing.T) {
	calls := stubPF(t)
	if err := os.WriteFile(savedPfStateFile, []byte("{invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := enablePf(); err != nil {
		t.Fatal(err)
	}
	backups, _ := filepath.Glob(savedPfStateFile + ".corrupt-*")
	if len(backups) != 1 {
		t.Fatal("corrupt ownership evidence was lost")
	}
	for _, call := range *calls {
		if strings.HasPrefix(call, "-X") {
			t.Fatal("released an unknown PF owner")
		}
	}
}
