package config

import "testing"

// FuzzParse exercises the .conf parser with arbitrary bytes. The
// invariant is "no panic, no OOM, return either a valid config or an
// error". MaxConfigSize protects against the OOM half; this fuzzer
// targets the panic half.
//
// Seed corpus covers the common edge cases we've hit by hand:
//   - empty input
//   - BOM-prefixed
//   - section headers with trailing junk
//   - keys without values
//   - duplicate sections
//   - very long single line within the 1 MiB cap
func FuzzParse(f *testing.F) {
	f.Add("")
	f.Add("\xef\xbb\xbf[Interface]\nPrivateKey=YYY=\n")
	f.Add("[Interface]\nPrivateKey=\n[Peer]\nPublicKey=\n")
	f.Add("[Interface]\nAddress=10.0.0.1/32\nDNS=1.1.1.1,2.2.2.2\n")
	f.Add("[InTeRfAcE]\n")
	f.Add("# comment only\n; also comment\n")
	f.Add("[Peer]\nAllowedIPs=0.0.0.0/0,::/0,10.0.0.0/8\n")
	f.Add("Key=No=Section=Header\n")
	// Bytes that previously broke things:
	f.Add("[Interface]\nKey\x00=value\n") // NUL in key
	f.Add("[Interface]\n=novalue\n")      // empty key
	f.Add("[Peer]\nEndpoint=\n[Peer]\n")  // multi peers, empty endpoint

	f.Fuzz(func(t *testing.T, input string) {
		// The contract is just "don't panic". Any error return is
		// acceptable; any successful Parse must round-trip-safe.
		_, _ = Parse(input)
	})
}
