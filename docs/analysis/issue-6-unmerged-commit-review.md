# Review of the unmerged cross-platform branch

Reviewed on 2026-09-10 against `analysis/issue-41-macos-helper-loop` at `b528ddf`.
The local branch `fix/cross-platform-hardening` has one unique commit,
`ddd6698` (33 files), while the current branch has 202 commits absent from it.
Its changes therefore cannot be treated as a patch against the current tree.
This review concerns the remaining work described in issue #6:
https://github.com/korjwl1/wireguide/issues/6

## Adopted and adapted

| Area | Decision |
| --- | --- |
| Linux AppImage output | Fix the quoted wildcard, accept capitalized desktop names and exact output names, replace previous build output, and reject missing/ambiguous generated files. Seven script-level tests use a fake linuxdeploy without network access. |
| Linux package dependencies | Keep common polkit, iproute/iproute2 and nftables dependencies in RPM/Arch overrides alongside Ayatana libraries; overrides replace the common dependency list. |
| Linux desktop category | Use Network in both the generated and static desktop entry. |
| Windows MSIX | Match packaged `wireguide.exe` in application executables and installer conversion template. |
| Windows DNS reset | Recognize WireGuide adapter names as well as wg/WireGuard prefixes. Native PowerShell execution still requires Windows validation. |

## Superseded by current implementation

| Old changes | Current disposition |
| --- | --- |
| Helper daemon parent-PID detection on all platforms | Obsolete in the current helper lifecycle; existing startup/GUI grace and #41 recovery changes already address the relevant paths. |
| Linux persistent network state; manager/recovery constructor changes | Current `SetPersistentStateDir` wiring supplies the state directory. Do not restore obsolete constructors. |
| Linux network watcher | Current reconnect detector uses RTNETLINK and default-route snapshots; do not replace it with an `ip monitor` subprocess that reacts to unrelated changes. |
| Linux suspend detector | Current native logind D-Bus subscription supersedes parsing a long-lived gdbus subprocess. |
| Windows suspend detector | Current native suspend/resume notifications supersede the old polling adjustment. |
| Windows route diagnostics and conflict detection | Current platform-specific native IP Helper API code supersedes the old text parsing changes. |
| Wintun engine hint | Current vendor/build integration already bundles Wintun; the old missing-file hint alone is insufficient. |
| Product metadata, desktop identity, Windows info/manifest/NSIS branding | Current files already carry product identity. Only remaining MSIX executable mismatches were adopted. |
| Linux notification subprocess fallback | The old `internal/notify` package no longer exists; do not restore it merely to add a gdbus fallback. |
| macOS network constructor | Part of the obsolete persistent-state constructor change above; no additional macOS fix. |

## Deferred rather than copied

| Old changes | Reason / remaining work |
| --- | --- |
| Linux pre-remove cleanup | Broad `pkill`, firewall deletion and `/var/lib/wireguide` removal do not distinguish upgrade from uninstall or preserve restoration journals. Design graceful per-user helper shutdown and DNS restoration before enabling package hooks. Current hooks remain incomplete. |
| Linux polkit policy | Blanket GUI execution and cached authorization for the whole binary need a scoped helper installation/execution design. Do not install the old policy unchanged. |
| Windows synchronous elevation | Waiting for redirected PowerShell process completion can tie startup to child handle lifetime. Requires native UAC cancellation and delayed-approval tests. |
| NSIS recursive AppData cleanup | The proposed directory can contain user configuration. Locate only the intended WebView2 cache before changing deletion behavior. |
| Linux DNS leak resolver discovery | `/etc/resolv.conf` can expose a local stub rather than upstream servers. Old English `resolvectl` parsing is incomplete for multiline/per-link results; use structured resolver discovery with fixtures. This remains an open defect. |
| Linux Wi-Fi command fallbacks | Requires testing association and interface selection with/without NetworkManager; the old fallback snippet does not establish correct multi-interface behavior. |
| Linux nftables presence hint | Package dependencies now declare nftables and current command failures are bounded; the old LookPath hint adds no validated functional recovery. |
| Skipping Windows Chmod | Chmod does not implement Unix permissions on Windows, but can clear the read-only attribute. Current code already tolerates failure when the directory is writable. Skipping it is not an established stability fix; Windows ACL hardening needs separate design. |

The old commit is recorded here for traceability. After the adopted changes are
committed and verified, its local branch can be deleted; do not delete the active
issue #41/#42 work branch. No remote branch exists for the old branch. This does
not close issue #6 or establish native Windows/Linux test coverage.

Review follow-up: linuxdeploy now runs in a fresh temporary output directory.
If it reports success without producing an expected artifact, packaging fails
and preserves the previous final artifact. Previously, a stale final artifact
could be accepted as the new result. The added regression test fails against
the previous script and passes with output isolation.

Validation: seven AppImage script scenarios, shell syntax, MSIX XML executable
paths, Windows network cross-build, and review of the resulting diff. Installer
execution and Linux distribution package installation still require native tests.
