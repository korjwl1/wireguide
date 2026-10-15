package update

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// testOverridePubKey lets tests substitute the production
// expectedPublicKey constant without flipping a real release key.
// Empty in production builds; tests assign to it via
// withTestPublicKey() and restore on cleanup. The activePublicKey
// gate ALSO checks testing.Testing() so a future contributor adding
// a //go:build dev file that mutates this var doesn't accidentally
// expose a signature-bypass path in production binaries.
var testOverridePubKey = ""

// activePublicKey returns the hex-encoded Ed25519 public key the
// verifier should use: the test override if set AND we're running
// in a `go test` binary, otherwise the embedded constant. Production
// builds (where testing.Testing() is false) cannot use the override.
func activePublicKey() string {
	if testOverridePubKey != "" && testing.Testing() {
		return testOverridePubKey
	}
	return expectedPublicKey
}

// verifyChecksumSignature downloads the SHA256SUMS file and its .sig
// sibling, verifies the signature against the embedded public key, and
// returns the VERIFIED SHA256SUMS bytes. Callers must treat the returned
// bytes as the only trusted source of asset hashes: a hash fetched at
// check time (info.ExpectedHash) is unauthenticated and may have been
// swapped between check and download — verifying a signature over a
// fresh copy without also taking the hash FROM that copy would let a
// repo-write attacker pass both checks with a malicious binary (serve
// tampered SHA256SUMS at check time, restore the genuine signed pair at
// download time).
func verifyChecksumSignature(checksumURL string, client *http.Client) ([]byte, error) {
	pubHex := activePublicKey()
	if pubHex == "" {
		// Caller already gated; defensive double-check. Return an error
		// (not success) so no caller can mistake unverified bytes for
		// verified ones.
		return nil, fmt.Errorf("no signing public key configured")
	}
	if checksumURL == "" {
		return nil, fmt.Errorf("no SHA256SUMS URL on this release")
	}
	pk, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, fmt.Errorf("malformed embedded public key: %w", err)
	}
	if len(pk) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("embedded public key size: got %d, want %d", len(pk), ed25519.PublicKeySize)
	}

	sumsBody, err := fetchSmall(checksumURL, client)
	if err != nil {
		return nil, fmt.Errorf("download SHA256SUMS: %w", err)
	}
	// Build the .sig URL via url.Parse so a release-asset URL with
	// a query string (CDN-redirected, signed Cloudflare URLs, etc.)
	// gets ".sig" appended to the *path* and not after the query.
	sigURL, err := appendSigSuffix(checksumURL)
	if err != nil {
		return nil, fmt.Errorf("compute .sig URL: %w", err)
	}
	sigBody, err := fetchSmall(sigURL, client)
	if err != nil {
		return nil, fmt.Errorf("download SHA256SUMS.sig: %w", err)
	}

	if err := verifyEd25519(sumsBody, sigBody, pk); err != nil {
		return nil, err
	}
	return sumsBody, nil
}

// appendSigSuffix appends ".sig" to the URL's path, preserving any
// query string and fragment. Plain string concatenation breaks for
// URLs like "https://cdn.example.com/SHA256SUMS?token=abc" which
// would become "...?token=abc.sig".
func appendSigSuffix(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	u.Path += ".sig"
	return u.String(), nil
}

// verifyEd25519 returns nil iff sig is a valid Ed25519 signature of
// content under pubkey. Pulled out of verifyChecksumSignature for
// unit-testability — tests can pass freshly-generated test key pairs
// without monkey-patching globals.
func verifyEd25519(content, sig, pubkey []byte) error {
	if len(pubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("public key size: got %d, want %d",
			len(pubkey), ed25519.PublicKeySize)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature size: got %d, want %d (sig file must be raw 64 bytes, no encoding)",
			len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pubkey, content, sig) {
		return fmt.Errorf("signature does not verify against embedded public key")
	}
	return nil
}

// fetchSmall downloads a small file (≤ 1 MB) and returns its bytes.
// Used for SHA256SUMS and .sig — both are tiny and need to be in
// memory for verification.
func fetchSmall(url string, client *http.Client) ([]byte, error) {
	if err := checkUpdateRawURL(url); err != nil {
		return nil, err
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
