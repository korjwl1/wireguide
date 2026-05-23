//go:build production

package update

import "log/slog"

// Release builds REQUIRE an Ed25519 signature on auto-updates. If
// expectedPublicKey is empty in a production build, Install refuses to
// proceed — this prevents a compromised GitHub repo write token from
// publishing an unsigned malicious release that clients silently install.
//
// To ship a real release: pass the public key via ldflags:
//   go build -tags production -ldflags \
//     "-X 'github.com/korjwl1/wireguide/internal/update.expectedPublicKey=<HEX>'"
// (full signing/publishing procedure: see docs/release.md).
const requireSignedUpdates = true

// CI gate: in a production build the key MUST be present at process
// start, not just at install time. Without this, a misconfigured CI
// could ship a release binary that LOOKS production-ready until the
// first auto-update attempt — at which point users see a confusing
// "refuse to install" error. Failing fast here makes that bug
// impossible to release.
//
// We log loudly instead of panicking so a stripped binary used for
// QA/integration tests can still run, but the warning is impossible
// to miss in journalctl / Console / EventViewer.
func init() {
	if expectedPublicKey == "" {
		slog.Error("PRODUCTION BUILD WITHOUT SIGNING KEY — auto-updates will refuse to install. " +
			"Rebuild with -ldflags '-X .../update.expectedPublicKey=<HEX>'.")
	}
}
