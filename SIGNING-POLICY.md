# Code Signing Policy

This document describes how Windows binaries published by the
`korjwl1/wireguide` project are signed, who can request a signature,
and what the integrity guarantees are. Required by SignPath Foundation
for projects using their free OSS code-signing service.

## Scope

The signing policy applies to the Windows NSIS installer artifacts:

- `WireGuide-windows-amd64.exe`
- `WireGuide-windows-arm64.exe`

macOS and Linux artifacts are not in scope (macOS uses ad-hoc signing
via `codesign`; Linux ships unsigned).

## Roles

WireGuide is currently maintained by a single person. The same
individual fulfills the three SignPath-required roles:

| Role | Filled by |
|------|-----------|
| Committer (writes code, tags releases) | korjwl1 |
| Reviewer (audits the change before release) | korjwl1 |
| Approver (authorizes the signing request) | korjwl1 |

If additional maintainers join the project, the table will be updated
and signing approval will become a two-person process (the committer
of a release cannot also approve its signing).

## Signing requests are accepted only from

- The `release.yml` workflow in this repository, running on GitHub
  Actions on Windows runners
- Triggered exclusively by a pushed tag matching `v*` (e.g. `v0.3.1`,
  `v0.4.0-rc1`)
- From the `main` branch's tagged history

These origin constraints are enforced by SignPath's "Trusted Build
System" verification, which cross-checks the artifact upload against
GitHub's API for the workflow run, repository, ref, and commit SHA.
Token theft alone cannot produce a signed binary — the token submitter
must additionally be a GitHub Actions workflow on this repository at
the expected ref.

## Reproducibility

Every signed binary is produced from a public commit on the `main`
branch. To reproduce locally:

```sh
git checkout v<version>
wails3 task windows:package ARCH=amd64   # or arm64
```

The resulting `.exe` SHA-256 will differ from the published binary
only by the Authenticode signature appended at the end; strip the
signature (`signtool remove`) to compare against the local build.

## Vulnerability reports

Security issues that should not be disclosed publicly may be sent to
the maintainer via GitHub's private vulnerability reporting:
<https://github.com/korjwl1/wireguide/security/advisories/new>.

The maintainer commits to acknowledging reports within 7 days and
issuing a fix or mitigation within 30 days for confirmed
vulnerabilities.

## License compatibility

WireGuide is MIT-licensed. No commercial dual-licensing or proprietary
components. The project ships only its own source, the `wireguard-go`
userspace WireGuard implementation (MIT), and `wintun.dll` (Apache 2.0)
as a vendored binary fetched and SHA-256 verified at build time.

## Attribution

Per SignPath Foundation requirements, the project README and release
notes display the line:

> Free code signing provided by SignPath.io, certificate by SignPath
> Foundation.

with hyperlinks to `https://signpath.io` and `https://signpath.org`
respectively.
