package elevate

import (
	"runtime"
	"testing"
)

func TestValidateArgsSocketSID(t *testing.T) {
	// The SID rules under test are path-independent, but the base Args must
	// pass validateSpawnPath's absolute-path check on every OS — Unix
	// fixtures are not absolute under Windows filepath rules. The Windows
	// SocketPath is the production pipe address, which IsAbs accepts.
	base := Args{SocketPath: "/var/run/wireguide/wireguide.sock", DataDir: "/var/lib/wireguide"}
	if runtime.GOOS == "windows" {
		base = Args{SocketPath: `\\.\pipe\wireguide`, DataDir: `C:\ProgramData\wireguide`}
	}

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
