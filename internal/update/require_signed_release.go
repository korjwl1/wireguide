//go:build production

package update

// Release builds REQUIRE an Ed25519 signature on auto-updates. If
// expectedPublicKey is empty in a production build, Install refuses to
// proceed — this prevents a compromised GitHub repo write token from
// publishing an unsigned malicious release that clients silently install.
//
// To ship a real release: generate a signing key pair, embed the public
// key in checker.go (`expectedPublicKey`), and sign SHA256SUMS as part
// of the release process (see docs/release.md).
const requireSignedUpdates = true
