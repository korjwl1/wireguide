# WireGuard Official macOS App Issues Analysis

This document summarizes the known issues with the official WireGuard macOS client and explains why WireGuide was created as an alternative.

## Background

The official WireGuard macOS app (wireguard-apple) has not been updated since **February 2023**. As macOS has progressed through Sonoma (14), Sequoia (15), and Tahoe (26), numerous issues have accumulated.

WireGuide was born from a specific incident: on an M1 MacBook Air running macOS Tahoe, the official client caused CPU throttling and complete network loss upon tunnel activation, while the same configuration worked fine on an M4 Mac mini.

---

## Reported Issues on r/WireGuard

### macOS Tahoe (26.x)

| Issue | Score | Comments | Date | URL |
|-------|-------|----------|------|-----|
| WireGuard stopped working after updating to Tahoe 26.0.1/26.1 | 7 | 22 | 2025-11-10 | https://www.reddit.com/r/WireGuard/comments/1oto85i/ |
| Wireguard not working on macOS Tahoe 26.2 | 6 | 10 | 2026-01-10 | https://www.reddit.com/r/WireGuard/comments/1q8xi8h/ |
| macOS update wiped my WireGuard client configs | 8 | 7 | 2026-01-18 | https://www.reddit.com/r/WireGuard/comments/1qg9ku6/ |
| WireGuard doesn't show in macOS menu bar, can't open GUI | 6 | 7 | 2025-12-17 | https://www.reddit.com/r/WireGuard/comments/1pokpoo/ |
| Wireguard stopped respecting On Demand SSID exceptions | 4 | 3 | 2025-08-05 | https://www.reddit.com/r/WireGuard/comments/1miert6/ |
| Mac lost all DNS while WireGuard was on | 5 | 0 | 2025-10-09 | https://www.reddit.com/r/WireGuard/comments/1o2826e/ |
| Outdated/expired Apple signing certificate | 3 | 2 | 2025-10-30 | https://www.reddit.com/r/WireGuard/comments/1ojseqq/ |
| Wireguard Client not working in macOS | 2 | 7 | 2026-04-06 | https://www.reddit.com/r/WireGuard/comments/1sdz23w/ |
| WireGuard on Mac — stuck process issue and confusing close behavior | 4 | 2 | 2026-03-27 | https://www.reddit.com/r/WireGuard/comments/1s56ym0/ |

### macOS Sequoia (15.x)

| Issue | Score | Comments | Date | URL |
|-------|-------|----------|------|-----|
| Wireguard on Mac Sequoia — connects but no data | 2 | 14 | 2024-11-06 | https://www.reddit.com/r/WireGuard/comments/1gkzqkq/ |
| Any known macOS Sequoia Issues? | 2 | 4 | 2024-10-03 | https://www.reddit.com/r/WireGuard/comments/1fv8vw3/ |
| WG on macOS Sequoia won't load websites on private subnet | 2 | 11 | 2025-05-20 | https://www.reddit.com/r/WireGuard/comments/1krhtof/ |
| Local DNS issues with macOS 15.2 Sequoia | 1 | 8 | 2025-01-03 | https://www.reddit.com/r/WireGuard/comments/1hsukab/ |
| Wireguard on Mac leaking traffic outside VPN | 16 | 38 | 2024-10-09 | https://www.reddit.com/r/WireGuard/comments/1fzvrvc/ |

### macOS Sonoma (14.x)

| Issue | Score | Comments | Date | URL |
|-------|-------|----------|------|-----|
| WireGuard on Sonoma — connects but no traffic | 1 | 6 | 2023-12-25 | https://www.reddit.com/r/WireGuard/comments/18qm5yw/ |
| Wireguard macOS Sonoma 14.2.1 GUI not launching | 2 | 1 | 2024-01-06 | https://www.reddit.com/r/WireGuard/comments/190aain/ |

### General

| Issue | Score | Comments | Date | URL |
|-------|-------|----------|------|-----|
| Why no iOS/macOS updates? Android gets updates all the time | 23 | 12 | 2026-01-04 | https://www.reddit.com/r/WireGuard/comments/1q3tahy/ |

### Common Symptom Patterns

1. **"Connects but no traffic"** — Most frequently reported. UI shows connected, handshake succeeds, but zero data flows.
2. **Config wipe on macOS update** — Tunnel configurations deleted after macOS point updates (especially 26.1 → 26.2).
3. **DNS breakage** — DNS resolution fails while WireGuard is active.
4. **Menu bar / GUI issues** — App not showing in menu bar, GUI won't launch, process gets stuck.
5. **No kill switch** — Traffic leaks outside the VPN tunnel with no built-in kill switch.
6. **MTU issues** — Multiple posts solved by lowering MTU to 1280.
7. **Signing certificate expired** — The app's Apple signing certificate expired August 2024 with no update.

---

## Root Cause Analysis: M1 MacBook Air CPU Throttling

The CPU throttling and network loss observed on M1 MacBook Air is most likely caused by a convergence of three factors:

### 1. macOS Tahoe NetworkExtension Changes

macOS Tahoe introduced significant changes to the NetworkExtension framework:

- Stricter configuration size limits causing provider activation failures
- Provider attachment failures (OS accepts config but never launches provider, no visible error)
- System extension unloading bugs (zombie extensions consuming resources)
- ESET documented 100% CPU from their NetworkExtension process on Tahoe 26.4
- Multiple major VPN vendors (FortiClient, Cisco, Palo Alto, SonicWall, AWS VPN) reported Tahoe compatibility issues

Sources:
- https://github.com/objective-see/LuLu/issues/825
- https://mjtsai.com/blog/2025/10/20/tahoe-wont-unload-network-extensions/
- https://forum.eset.com/topic/48629-tahoe-264-and-eset-cyber-security-9053000-100-cpu-comesetnetwork/
- https://discussions.apple.com/thread/256150327

### 2. Outdated wireguard-go (66 Missing Commits)

The official wireguard-apple client pins wireguard-go at `2023-02-09`. Since then, 66 commits have been made with critical fixes:

| Commit | Bug | Impact |
|--------|-----|--------|
| `113c8f1340` (2025-05-04) | **sync.Cond wake-up miss** | Goroutines spin or stall → CPU waste + packet processing delays |
| `867a4c4a3f` (2025-05-04) | **Send path memory leak** | QueueOutboundElementsContainer not returned → GC pressure → CPU spikes |
| `436f7fdc16` (2025-05-05) | **rwcancel poll flag error** | Wrong poll event on TUN cancel FD (macOS-specific) → event loop spin or missed events |
| `12269c2761` (2023-12-11) | **Close() deadlock** | Lock ordering inversion → tunnel restart deadlocks entire device → complete network loss |
| `4ffa9c2032` (2023-12-11) | **Endpoint lock contention** | Coarse-grained RWMutex → throughput reduction, amplified on efficiency cores |
| `ec8f6f82c2` (2023-10-10) | **ForceMTU crash after close** | TUN device panic |
| `c7b76d3d9e` (2023-02-16) | **ECDH zero output** | Security: key exchange missing degenerate output check |
| `bc30fee374` (2025-05-05) | **Darwin TUN if_msghdr** | macOS-specific: changed how TUN reads interface flags and MTU |

Performance improvements also missed by the official app:

| Commit | Improvement |
|--------|-------------|
| `9e7529c3d2` (2025-05-15) | Handshake unmarshalling: 1.508μs → 12.66ns (**119x faster**) |
| `264889f0bb` (2025-05-20) | Message encoding: 1.337μs → 53.05ns (**25x faster**) |
| `b82c016264` (2025-05-05) | Checksum computation: **30-80% faster** |
| `7c20311b3d` (2023-12-11) | RX path overhead reduction: **~10% throughput improvement** |

### 3. M1 MacBook Air Fanless Design

- M1 MacBook Air has **no fan** — purely passive cooling
- Under sustained CPU load, chip reaches 97-98°C before macOS throttles down to as low as **4W**
- The combination of (1) + (2) increases baseline CPU usage of the WireGuard process
- On M1 Air: elevated CPU → thermal limit → throttling → packet processing falls behind → retransmission storms → **cascading network failure**
- On M4 Mac mini: active cooling + higher efficiency → same workload runs without throttling

Sources:
- https://forums.macrumors.com/threads/how-i-fixed-my-m1-macbook-air-throttle.2280634/
- https://www.sysorchestra.com/reduce-thermal-throttling-on-your-apple-m1-macbook-air-to-increase-performance/

---

## WireGuide vs Official App: Version Comparison

| | Official wireguard-apple | WireGuide |
|---|---|---|
| wireguard-go version | `2023-02-09` (`1e2c3e5a3c14`) | **`2025-05-21`** (`f333402bd9cb`) |
| Missing critical fixes | 66 commits | **All included** |
| NetworkExtension dependency | Yes (affected by Tahoe changes) | **No** (uses wireguard-go directly) |
| Handshake performance | 1.508μs | **12.66ns** (119x faster) |
| Known deadlock bugs | Yes | **Fixed** |
| Known memory leaks | Yes | **Fixed** |
| macOS TUN poll bug | Yes | **Fixed** |
| Apple signing certificate | Expired (Aug 2024) | N/A (direct distribution) |
| Last update | February 2023 | Active development |

---

## Conclusion

The official WireGuard macOS client's issues stem from its abandonment (no updates since Feb 2023) combined with Apple's continuous changes to macOS networking APIs. The M1 MacBook Air CPU throttling incident was not an isolated edge case — it was a predictable consequence of running outdated software with known CPU-related bugs on thermally constrained hardware under an OS version that introduced breaking changes to the VPN framework.

WireGuide addresses these issues by:
1. Using the latest wireguard-go with all 66 fixes included
2. Bypassing NetworkExtension entirely (using wireguard-go directly)
3. Implementing proper sleep/wake recovery and kill switch functionality
