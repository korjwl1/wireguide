# Homebrew postflight migration

Verified on macOS arm64 on 2026-09-15.

Homebrew 6 deprecates Ruby `postflight` blocks. Its structured install steps
cannot launch apps through LaunchServices, so changing only the stanza name
would break the old kill-and-relaunch sequence. See the
[Cask Cookbook](https://docs.brew.sh/Cask-Cookbook#cask-artifact-trust-and-sandboxing).

The tap and release template now use `postflight_steps` only to remove the
installed app's quarantine attribute, preserving the existing installation
behavior for the ad-hoc-signed release. They no longer kill or launch apps.
Terminal installs/upgrades therefore leave app launch/restart to the user.

For in-app updates, `RunUpdate` waits for Homebrew, verifies the installed
bundle version (including rejecting an unreadable version), and schedules a
detached launcher before normal GUI shutdown. The launcher waits for that
specific GUI process to exit before opening `/Applications/WireGuide.app`.
It gives up after approximately 30 seconds if shutdown does not finish.

## Compatibility transition

Released versions through 0.5.1 depend on the old cask to restart them. After
updating from those versions with the new cask, quit and reopen WireGuide once
to run the new version. Automatic in-app restart applies once a release with
the new `RunUpdate` implementation is running. This change does not publish
a new WireGuide release.

## Verification

- `brew info --cask wireguide` parsed the new cask without the deprecation.
- Actual `brew reinstall --cask wireguide` installed 0.5.1 successfully without
  the deprecation, removed quarantine, and did not automatically launch the app.
- The release template's generated cask matched the tested tap exactly.
- `go test ./internal/app ./internal/update` and `go vet` passed.
- Restart tests used real child processes to verify waiting for exit and
  literal handling of paths containing spaces and shell metacharacters.
  Those tests also passed with the race detector.
- Windows amd64 app cross-build and macOS production packaging passed;
  the packaged app's ad-hoc signature verified.
- A temporary native Wails harness called the production `RunUpdate` method
  against the real Homebrew installation, targeting already installed 0.5.1.
  Homebrew update/upgrade completed; `RunUpdate` returned at 09:59:50.647,
  native shutdown started at 09:59:50.753, and its deliberate one-second
  cleanup finished at 09:59:51.754. Harness PID 51956 exited, then installed
  WireGuide PID 52997 launched. Helper PID 53183 became available with no VPN
  connected. This checks real native exit/relaunch after successful Homebrew
  completion; it does not represent downloading a newer unpublished version
  or upgrading while a VPN is connected.
- Stopped the launched app/helper and removed the temporary harness source
  from the repository. Local logs and harness copy are under
  `/tmp/wireguide-postflight-*`.
