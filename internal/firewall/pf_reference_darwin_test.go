package firewall

import (
	"testing"
)

func TestPFRepairsItsReferenceEvenWhenAnotherOwnerRestartedPF(t *testing.T) {
	k := stubPFKernel(t)
	f := NewPlatformFirewall().(*DarwinFirewall)
	if err := f.EnableKillSwitch("utun4", nil, nil); err != nil {
		t.Fatal(err)
	}
	k.externalDisable()
	k.running, k.tokens["999"] = true, true
	if repaired, err := f.RepairEnforcement(); err != nil || !repaired {
		t.Fatalf("stale token mistaken for another owner's protection: %v %v", repaired, err)
	}
	if pfLease.state.Token == "101" || !k.tokens[pfLease.state.Token] || !k.tokens["999"] {
		t.Fatalf("reference repair changed the wrong ownership: %v", k.tokens)
	}
	if _, err := runPfctl("-X", "999"); err != nil || !k.running {
		t.Fatal("another owner's Off disabled WireGuide protection")
	}
	if err := f.DisableKillSwitch(); err != nil || k.running {
		t.Fatal("WireGuide Off failed to release the repaired reference")
	}
}

func TestPFReferenceListingMatchesOnlyExactTokenColumn(t *testing.T) {
	for _, tc := range []struct {
		out, token    string
		live, invalid bool
	}{
		{"No pf starter references held\n", "123", false, false},
		{"TOKENS:\nPID Process Name TOKEN TIMESTAMP\n123 process with spaces 456 0 days 00:00:01\n", "456", true, false},
		{"TOKENS:\nPID Process Name TOKEN TIMESTAMP\n123 process123 1234 0 days 00:00:01\n", "123", false, false},
		{"TOKENS:\nPID Process Name TOKEN TIMESTAMP\n1 pfctl 18446744073709551615 123 days 12:34:56\n", "18446744073709551615", true, false},
		{"unexpected output", "123", false, true},
		{"TOKENS:\nPID Process Name TOKEN TIMESTAMP\n", "123", false, true},
		{"TOKENS:\nPID Process Name TOKEN TIMESTAMP\n123 truncated\n", "123", false, true},
	} {
		live, err := parsePfReferences(tc.out, tc.token)
		if live != tc.live || (err != nil) != tc.invalid {
			t.Errorf("listing %q: live=%v err=%v", tc.out, live, err)
		}
	}
}
