package elevate

import "testing"

func TestValidateArgsSocketSID(t *testing.T) {
	base := Args{SocketPath: "/var/run/wireguide/wireguide.sock", DataDir: "/var/lib/wireguide"}

	valid := base
	valid.SocketSID = "S-1-5-21-3623811015-3361044348-30300820-1013"
	if err := ValidateArgs(valid); err != nil {
		t.Errorf("valid SID rejected: %v", err)
	}

	empty := base // empty SID is fine (Unix / fallback)
	if err := ValidateArgs(empty); err != nil {
		t.Errorf("empty SID rejected: %v", err)
	}

	for _, bad := range []string{
		"IU",              // SDDL alias — we only pass numeric SIDs
		"S-1-5-21-abc",    // non-numeric component
		"S-1",             // too short
		"S-1-5-21-1013;X", // injection attempt into the SDDL/argv
		"S-1-5-21-1013')", // PowerShell breakout attempt
	} {
		inv := base
		inv.SocketSID = bad
		if err := ValidateArgs(inv); err == nil {
			t.Errorf("invalid SID %q accepted", bad)
		}
	}
}
