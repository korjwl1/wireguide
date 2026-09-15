# macOS execution checks for #42 and the review fixes

Run on 2026-09-10, macOS arm64, starting from commit `5e6596d`.
Private evidence is in `/tmp/wireguide-macos-live-final` on the test Mac.
Keys, user configuration backups and screenshots remain local.

## Setup

Installed helper SHA-256 `901f2c01…` matched the packaged app containing the
review fixes. Its initial PID was 80031. The earlier helper was stopped first;
the new GUI reached `helper ready` after native authorization.

Two disposable WireGuard peers ran locally on UDP 51891/51892 using
wireguard-go with an in-memory peer interface that returns ICMP echo replies.
The client used the real WireGuide GUI, installed root helper, macOS utun
interfaces, kernel routes and encrypted WireGuard transport. A mode file on
each controlled peer selectively suppressed decrypted ICMP responses while
keeping WireGuard running. This is an actual client VPN test, not a mocked
client tunnel manager; the remote side is a deterministic local test peer.

- `LivePing-A`: `10.254.241.0/24`, `fd42:5747:241::/64`.
- `LivePing-B`: `10.254.242.0/24`, `fd42:5747:242::/64`.
- A third disposable peer/profile, `LivePing-C`, used `10.254.243.0/24` and a
  minimal DNS responder to exercise macOS DNS application/restoration.

The user's existing VPN profile was never connected. Initial active status was
empty. User settings/profiles and DNS/default-route snapshots were backed up
before testing. Network/firewall mutations had independent timed recovery.

## Observed results

| Scenario | Evidence / result |
| --- | --- |
| Real IPv4 and IPv6 traffic | Initial A ping/ping6 each returned 2/2 responses through utun; later B helper health probes reached its IPv6 target. |
| Native settings UI | Saved A with two targets, interval 10 seconds and threshold 2. On-disk metadata matched. B initially displayed disabled, empty targets, 30 seconds and threshold 3. |
| One target fails | Blocked A's `.1` while `.3` replied for 35 seconds. Repeated probe rounds arrived at the peer; no reconnect occurred. |
| All targets fail | A reconnected at 13:53:40 after two failed rounds. B kept its original connection/interface. |
| Persistent outage / cooldown | A reconnected again at 13:55:00, 79.977 seconds after the first reconnect, exceeding the 60-second minimum. B stayed connected throughout. |
| Replies restored | Returning the peer to normal restored A's IPv4 ping (2/2 responses). |
| Disable a queued retry through the GUI | At 13:56:40 a failed round queued reconnect. Native GUI disable/save completed 0.502 seconds later. The helper canceled the retry without tearing down A. |
| Manual disconnect during retry backoff | A remained disconnected for the 12-second observation after the manual action; B remained connected. |
| Per-profile persistence and GUI recovery | Terminated only GUI PID 79900, then launched the rebuilt UI. Helper PID 80031 and B's connection survived; startup reused the helper without authorization. Native UI loaded A disabled/two IPv4 targets and B enabled/one IPv6 target, each at 10 seconds/2 failures. |
| DNS application | C's `10.254.243.1` appeared in `scutil --dns`; a DNS query through the encrypted tunnel returned the controlled response. |
| Kill switch + DNS protection | B/C ICMP and C DNS worked with both protections enabled. A physical-network HTTP request to `1.1.1.1` timed out. |
| Protection/DNS restoration | Disabled protections and disconnected C. `scutil --dns` matched its pretest snapshot byte-for-byte. The same physical-network HTTP request then returned HTTP 301. |
| Actual primary-network transition | Disabled Ethernet for 8 seconds. The helper observed `en0 -> empty -> en0` and reconnected B. Default gateway/interface returned to the original values. |
| Native power notification | Issued `pmset sleepnow` with automatic wake scheduled. The helper received IOKit `SystemHasPoweredOn`, canceled the overlapping network retry, reconnected B, and IPv6 ping returned 2/2 replies. HID activity caused an early wake; this is not a sustained 20-second or overnight sleep test. |
| Helper crash with an active tunnel | Killed helper PID 80031 at 14:04:46. launchd started PID 18217. The GUI detected disconnection at 14:04:46.411 and recovered at 14:04:46.869 without another authorization prompt. The new helper cleaned the orphaned B tunnel and routes. Status was empty afterward: helper availability recovered, but the crashed VPN connection was not automatically restored. |

The cancellation test's cleanup initially used the connected-view accessibility
path after the UI had switched to its disconnected layout. Its scenario checks
had passed; the cleanup selector was corrected and GUI disable/save was verified.
This was a test-driver issue, not a failed application cancellation.

## Additional defect fixed during execution

Submitting enabled monitoring without targets correctly rejected the save, but
the native UI displayed a serialized `{message, cause, kind}` JSON error. The
shared `errText` function now unwraps error-shaped JSON strings, including those
nested inside `Error.message`, while preserving ordinary text and other JSON.

The new Node regression test failed before the change and passed afterward.
Rebuilt and launched the actual app, repeated the invalid save, and verified
the accessibility tree displayed only the readable error message, with no
`RuntimeError` envelope. Invalid input did not overwrite the saved settings.

## Cleanup

Disconnected/deleted all three disposable profiles and stopped the local peers.
Original settings values and tunnel file names/contents matched the pretest
backup exactly. DNS and default-route snapshots matched the initial state;
the test subnet routes were absent. Both protection settings were restored to
their original disabled values. Ethernet was enabled and no scheduled wake
remained. With the GUI stopped, removed only history entries for the three
test profile names, preserving the five other records.

Packaged the final UI fix into the repository's `bin/wireguide.app`, verified
its ad-hoc signature, and launched it from that path. Native authorization
completed and the GUI logged `helper ready` at 14:08:45. GUI PID 26776 and
helper PID 26939 were running, with empty active tunnel status. The app and
installed helper both had SHA-256
`4cc870591fb23c809b5dd8c4388803ff59470030313d789a6bad07531730cf57`.
Repeated settings/profile, DNS/default-route and test-route cleanup checks
after this final launch passed. The app was left running with no VPN connected.

## Limits

These tests exercise split routes against controlled local peers. They do not
establish behavior over a remote WAN, every full-tunnel configuration, Wi-Fi
SSID roaming, reboot, or a long sleep. The machine's primary link was Ethernet;
SSID lookup remained unavailable under its current macOS location permissions.
Native Windows/Linux execution remains separate work.
