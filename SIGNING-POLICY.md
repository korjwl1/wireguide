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

## Signing approval workflow

Every signing request requires explicit human approval from an
Approver before SignPath issues the signature. This is enforced at
the SignPath policy level (`release-signing` policy, `Manual approval
required: yes`); the workflow that uploads the unsigned artifact
cannot trigger a signature without a separate, interactive approval
step in the SignPath portal.

While the project has a single maintainer, that maintainer reviews
the diff between the previous release tag and the current one before
issuing approval, and signing is deferred until that review is
complete. The single-maintainer exemption is acknowledged with
SignPath Foundation; if the project gains additional maintainers,
the policy moves to two-person approval (the release Committer
cannot also be the Approver for that release's signing request).

## Account security

All maintainers with signing-approval access have multi-factor
authentication enabled on:

- Their GitHub account (used for repository write + release tagging)
- Their SignPath account (used for signing approval)

GitHub MFA enforcement is also configured at the organization /
repository level so that the requirement cannot be silently relaxed.
Loss of an MFA device for the sole maintainer triggers the SignPath
emergency-access procedure (key revocation + new project enrollment),
not a recovery workaround.

## Privacy &amp; data handling

WireGuide does not transmit telemetry, analytics, or any other
information to networked systems unless the user explicitly initiates
a VPN connection. WireGuard tunnels carry only user-configured peer
traffic; no usage data, configuration content, crash reports, or
metadata is sent to the maintainer, SignPath, or any third party as
a side effect of running the application. Update checks query GitHub
Releases (a public API) only when the user opens the Updates UI;
this is the only outbound HTTP request the application initiates
that is not user-driven via a tunnel.

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
