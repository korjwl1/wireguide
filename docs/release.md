# Release signing & rotation

The auto-update verifier in `internal/update/checker.go` defends
against a compromised GitHub account by verifying an Ed25519
signature over `SHA256SUMS` with a public key embedded in the binary
at compile time. The matching private key never touches CI or
GitHub — it lives in the maintainer's macOS Keychain.

This doc walks through:

1. Generating the keypair (one-time)
2. Signing each release
3. Rotating the key

---

## 1. Generate the keypair

Run once, on the trusted release machine. The private key is stored
in the macOS Keychain so it isn't on disk in plaintext.

```bash
# Generate keypair, print public key (hex), seed-only private key
# stays in Keychain.
go run ./cmd/wgsign-init
```

The tool (a thin wrapper around `crypto/ed25519`) does:

1. Calls `ed25519.GenerateKey(crypto/rand)`.
2. Stores the 64-byte private key (raw) in Keychain under service
   `wireguide-release-key`, account `default`.
3. Prints the 32-byte public key as 64 hex characters.

Paste the printed hex into `internal/update/checker.go`:

```go
const expectedPublicKey = "0123456789abcdef..."
```

Commit + tag this with the release that ships the first signed
build. Older binaries with `expectedPublicKey == ""` skip
verification and rely on SHA256 alone (degraded mode).

> **DO NOT** put the private key anywhere else — not in `~/.ssh`, not
> in 1Password export, not in a CI secret. Keychain only.
> If your laptop dies, you can't recover; rotate the key (§3).

---

## 2. Sign a release

After GitHub Actions (or your local release script) builds the
artifacts and writes `SHA256SUMS` next to them:

```bash
# In the release working directory (where SHA256SUMS exists)
go run ./cmd/wgsign sign SHA256SUMS
```

This:

1. Reads `SHA256SUMS` from disk.
2. Pulls the private key out of Keychain.
3. Calls `ed25519.Sign(priv, sumsBytes)` (64-byte signature, raw).
4. Writes the signature to `SHA256SUMS.sig` next to `SHA256SUMS`.

Upload **all of**:

- the asset(s) (`.dmg` / `.zip` / etc.)
- `SHA256SUMS`
- `SHA256SUMS.sig`

to the GitHub Release. The verifier expects `SHA256SUMS.sig` at the
same URL prefix as `SHA256SUMS`.

---

## 3. Rotate the key

You need to rotate when:

- the release machine is lost or compromised
- the private key is suspected leaked
- on a long cadence (e.g. every 2 years) as hygiene

Rotation procedure:

1. Generate a NEW keypair (§1) on a clean machine.
2. Replace `expectedPublicKey` in `checker.go` with the new public
   key. Bump the app version.
3. Cut a release. **This release MUST be signed with the OLD key**
   if old binaries are still in the wild — those clients verify
   against the old embedded pubkey, so the SHA256SUMS.sig of the
   new release must still be old-key-signed.
4. After enough users have updated past the cutover, you can stop
   signing with the old key. Future releases sign with new only.

Trade-off: there's no "trust transition" mechanism (no signed key
manifest). Users who skip the cutover release entirely will be
stuck — they verify against the old pubkey but new releases are
signed with the new key. Keep the cutover release available
indefinitely.

If keys are NEVER signed at all (initial state), `expectedPublicKey
== ""` and the verifier just warns in the log and proceeds with
SHA256-only authentication. That's acceptable for the early
0.1.x line; flip the constant the moment you cut a signed release.

---

## Implementation pointers

- Verifier: `internal/update/checker.go` — `verifyChecksumSignature`
- Tests: `internal/update/checker_test.go` —
  `TestVerifyEd25519_*` and `TestVerifyChecksumSignature_*`
- Signing tool (TODO): `cmd/wgsign/`
- Init tool (TODO): `cmd/wgsign-init/`

The signing tools are not in the tree yet — they're trivial
wrappers around `crypto/ed25519` plus the `security` CLI for
Keychain access:

```bash
# Roughly what wgsign sign does:
priv=$(security find-generic-password -s wireguide-release-key -a default -w | xxd -r -p)
echo "$priv" | ... | ed25519 sign SHA256SUMS > SHA256SUMS.sig
```

When you cut the first signed release, write `cmd/wgsign{,-init}/main.go`
and update this section.
