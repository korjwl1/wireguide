# Release signing & rotation

The auto-update verifier in `internal/update/checker.go` defends
against a compromised GitHub account by verifying an Ed25519
signature over `SHA256SUMS` with a public key embedded in the binary
at compile time:

- **Public key** — hex, injected at build time via
  `-ldflags "-X github.com/korjwl1/wireguide/internal/update.expectedPublicKey=<hex>"`.
  Release CI passes it as the `SIGN_PUBKEY` task variable (see
  `UPDATE_SIGNING_PUBKEY` in `.github/workflows/release.yml`); the
  platform Taskfiles fold it into `BUILD_FLAGS` alongside
  `-tags production`, which turns enforcement ON
  (`internal/update/require_signed_release.go`).
- **Private key** — a 32-byte Ed25519 seed, hex-encoded, stored in the
  `UPDATE_SIGNING_KEY` GitHub Actions secret. The release workflow
  signs `SHA256SUMS` → `SHA256SUMS.sig` (raw 64-byte signature) and
  publishes it next to `SHA256SUMS`. A pre-publish check derives the
  public key from the secret and fails the release if it doesn't match
  `UPDATE_SIGNING_PUBKEY` — a mismatched pair would ship binaries that
  reject our own releases.
- **Maintainer backup** — the same seed lives at
  `~/.wireguide/release-signing.key` (mode 0600) on the release
  machine. **Back this file up somewhere safe** (password manager /
  offline). If both the secret and the backup are lost, the key cannot
  be recovered — rotate (§3).

Everything is driven by `tools/updatesign` (stdlib-only; its
sign/verify pair matches the client verifier exactly):

```bash
go run ./tools/updatesign gen -out <seed-file>   # new key; prints PUBLIC hex, never the seed
go run ./tools/updatesign pub                    # seed from $UPDATE_SIGNING_KEY (or -key <file>); prints public hex
go run ./tools/updatesign sign -in SHA256SUMS    # writes SHA256SUMS.sig
go run ./tools/updatesign verify -pub <hex> -in SHA256SUMS
```

---

## 1. One-time setup (already done)

```bash
go run ./tools/updatesign gen -out ~/.wireguide/release-signing.key
#  → prints the public key; paste into UPDATE_SIGNING_PUBKEY in release.yml
gh secret set UPDATE_SIGNING_KEY < ~/.wireguide/release-signing.key
```

Older binaries built with `expectedPublicKey == ""` (all releases up
to and including v0.3.1, and every dev build) skip verification and
rely on SHA256 alone — they are unaffected by any of this.

## 2. Signing a release

Nothing manual: the tag-triggered workflow bakes the public key into
every platform build, then signs `SHA256SUMS` in the `release` job and
attaches `SHA256SUMS.sig` to the GitHub Release. The step **fails the
whole release** if the secret is missing or mismatched, because the
just-built binaries would otherwise refuse all future auto-updates.

## 3. Rotating the key

Rotate when the key may have leaked (GitHub org compromise, laptop
loss if the backup was on it) or on long-cadence hygiene:

1. `go run ./tools/updatesign gen -out <new-seed-file>` on a clean machine.
2. Update `UPDATE_SIGNING_PUBKEY` in `release.yml` with the new public
   key and `gh secret set UPDATE_SIGNING_KEY < <new-seed-file>`.
3. Cut the cutover release. **Its `SHA256SUMS.sig` must verify for the
   binaries already in the wild**, which check the OLD public key — so
   sign that one release manually with the old key
   (`go run ./tools/updatesign sign -key <old-seed-file> ...`, replace
   the workflow-produced .sig on the Release) or temporarily keep the
   old pair in CI for it.
4. Once users have crossed the cutover, new releases are new-key only.
   Keep the cutover release downloadable indefinitely — clients that
   skip it verify new releases against the old key and must go through
   it (or reinstall manually).

There is deliberately no signed key-transition manifest — the fleet is
small and the manual cutover above is simpler to reason about.

---

## Implementation pointers

- Verifier: `internal/update/checker.go` — `verifyChecksumSignature`
  (raw 64-byte `.sig`, hex pubkey, signature over the exact
  `SHA256SUMS` bytes); enforcement gate in
  `internal/update/require_signed_release.go` (`-tags production`).
- Signer/keygen: `tools/updatesign/main.go`
- CI wiring: `.github/workflows/release.yml` (`UPDATE_SIGNING_PUBKEY`
  env, `SIGN_PUBKEY` task var, "Sign SHA256SUMS" step) and the
  `BUILD_FLAGS` vars in `build/{darwin,windows,linux}/Taskfile.yml`.
- Tests: `internal/update/checker_test.go` — `TestVerifyEd25519_*`,
  `TestVerifyChecksumSignature_*`
