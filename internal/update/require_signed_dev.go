//go:build !production

package update

// Dev / test builds allow SHA256-only update verification when no
// public key is embedded. Production builds flip this to require a
// real Ed25519 signature (see require_signed_release.go).
const requireSignedUpdates = false
