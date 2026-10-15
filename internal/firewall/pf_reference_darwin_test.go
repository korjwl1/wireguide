package firewall

import (
	"os"
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

func TestPFReusedTokenDoesNotCountAsOurReference(t *testing.T) {
	k := stubPFKernel(t)
	f := NewPlatformFirewall().(*DarwinFirewall)
	if err := f.EnableKillSwitch("utun4", nil, nil); err != nil {
		t.Fatal(err)
	}
	k.externalDisable()
	k.running, k.tokens["101"], k.owners["101"] = true, true, 777
	if repaired, err := f.RepairEnforcement(); err != nil || !repaired {
		t.Fatalf("reused token mistaken for our reference: %v %v", repaired, err)
	}
	if pfLease.state.Token == "101" || !k.tokens["101"] || !k.tokens[pfLease.state.Token] {
		t.Fatalf("repair changed another owner's reference: %v", k.tokens)
	}
}

func TestPFReleaseDoesNotReleaseReusedToken(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "crash journal"}[recovery], func(t *testing.T) {
			k := stubPFKernel(t)
			if err := enablePf(); err != nil {
				t.Fatal(err)
			}
			k.externalDisable()
			k.running, k.tokens["101"], k.owners["101"] = true, true, 777
			if recovery {
				pfLease.state = pfLeaseState{}
			}
			if err := disablePf(); err != nil || !k.running || !k.tokens["101"] {
				t.Fatalf("released another owner's reused token: %v; %v", err, k.tokens)
			}
		})
	}
}

func TestPFLegacyTokenJournalDoesNotReleaseUnprovenOwnership(t *testing.T) {
	k := stubPFKernel(t)
	k.running, k.tokens["101"] = true, true
	if err := writePfLease(pfLeaseState{Token: "101", Boot: "boot-a"}); err != nil {
		t.Fatal(err)
	}
	if err := disablePf(); err != nil || !k.running || !k.tokens["101"] {
		t.Fatalf("legacy journal released unproven reference: %v; %v", err, k.tokens)
	}
	removePfStateFile()
	if _, err := os.Stat(savedPfStateFile); !os.IsNotExist(err) {
		t.Fatal("legacy journal was not retired")
	}
}

func TestPFReleaseQueryFailureRetainsOwnedJournal(t *testing.T) {
	k := stubPFKernel(t)
	if err := enablePf(); err != nil {
		t.Fatal(err)
	}
	good := runPfctl
	runPfctl = func(args ...string) ([]byte, error) {
		if args[0] == "-s" {
			return nil, os.ErrPermission
		}
		return good(args...)
	}
	if err := disablePf(); err == nil || pfLease.state.Token == "" || !k.tokens["101"] {
		t.Fatal("failed ownership query released the reference or discarded its journal")
	}
	removePfStateFile()
	if _, err := os.Stat(savedPfStateFile); err != nil {
		t.Fatal("unverified ownership lost its recovery journal")
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
		{"TOKENS:\nPID Process Name TOKEN TIMESTAMP\n123 pfctl 18446744073709551615 123 days 12:34:56\n", "18446744073709551615", true, false},
		{"unexpected output", "123", false, true},
		{"TOKENS:\nPID Process Name TOKEN TIMESTAMP\n", "123", false, true},
		{"TOKENS:\nPID Process Name TOKEN TIMESTAMP\n123 truncated\n", "123", false, true},
	} {
		live, err := parsePfReferences(tc.out, tc.token, 123)
		if live != tc.live || (err != nil) != tc.invalid {
			t.Errorf("listing %q: live=%v err=%v", tc.out, live, err)
		}
	}
	out := "TOKENS:\nPID Process Name TOKEN TIMESTAMP\n777 pfctl 1234 0 days 00:00:01\n"
	if live, err := parsePfReferences(out, "1234", 123); err != nil || live {
		t.Fatal("same token issued to another PID counts as ours")
	}
}
