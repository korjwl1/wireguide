package storage

import "testing"

// FuzzValidateTunnelName exercises the tunnel-name validator with
// arbitrary input. The validator is the security boundary between
// untrusted .conf filenames and the filesystem; it must never panic and
// must reject anything that could let a name escape the tunnels
// directory.
func FuzzValidateTunnelName(f *testing.F) {
	// Known-good seeds.
	f.Add("home")
	f.Add("work-vpn")
	f.Add("Tunnel 1")
	f.Add("my_tunnel_42")

	// Known-bad seeds — must reject without panicking.
	f.Add("")
	f.Add(" leading-space")
	f.Add("trailing-space ")
	f.Add("../escape")
	f.Add("a/b")
	f.Add("a\x00b")
	f.Add("name.with.dots")
	f.Add(string(make([]byte, 65))) // over length cap

	f.Fuzz(func(t *testing.T, name string) {
		// The contract is just "don't panic". Either return nil (name
		// is valid → must be filesystem-safe) or return an error.
		_ = ValidateTunnelName(name)
	})
}
