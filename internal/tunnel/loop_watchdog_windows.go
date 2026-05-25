//go:build windows

package tunnel

// Runaway-TX watchdog — final defense-in-depth against the routing loop
// class of bug ([issue #14]). The primary defenses are:
//
//   1. iphlpapi-based bypass /32 host route with fail-fast preflight
//      (internal/network/windows.go).
//   2. WFP BLOCK filter that drops UDP-to-endpoint when the local
//      interface LUID is the tunnel adapter (internal/firewall/
//      endpoint_protection_windows.go).
//
// This watchdog catches the residual case where neither defense fired —
// hypothetical kernel bug, a third-party WFP sublayer overriding ours,
// or some future routing-table mutation we didn't anticipate. It samples
// the tunnel adapter's OutOctets at a slow cadence and forces a
// disconnect when sustained TX exceeds a "no plausible user workload"
// ceiling.
//
// Threshold rationale:
//   - 50 MiB/s ≈ 400 Mbps. Above what consumer connections can sustain
//     for VPN traffic indefinitely, and well below the kernel-line-rate
//     numbers a loop produces (gigabit link saturates at ~120 MiB/s).
//   - Three consecutive samples at the 5 s sample interval = 15 s of
//     sustained over-threshold before we trip. Defeats bursty downloads
//     and brief speed-tests; trips on the steady-state loop signature.

import (
	"context"
	"log/slog"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/korjwl1/wireguide/internal/network"
)

// MIB_IF_ROW2 byte-offsets for the two counters we need on 64-bit
// Windows. We read the row into a fixed byte buffer and pick the
// counters out by offset rather than declaring a full Go-side struct
// — the struct has 30+ fields, several enums and a packed bitfield,
// and matching the exact C layout in Go is fragile across SDK
// revisions. The byte-offset path only depends on the position of
// InOctets and OutOctets, both of which have been stable since the
// API was introduced in Windows 8.
//
// Derivation (cross-checked against netioapi.h):
//
//	NET_LUID InterfaceLuid                        8 bytes @   0
//	NET_IFINDEX InterfaceIndex                    4 bytes @   8
//	GUID InterfaceGuid                           16 bytes @  12 (align 4)
//	WCHAR Alias[257]                            514 bytes @  28 (align 2)
//	WCHAR Description[257]                      514 bytes @ 542
//	ULONG PhysicalAddressLength                   4 bytes @1056 (align 4, no pad)
//	UCHAR PhysicalAddress[32]                    32 bytes @1060
//	UCHAR PermanentPhysicalAddress[32]           32 bytes @1092
//	ULONG Mtu                                     4 bytes @1124
//	6 × enum (Type/TunnelType/MediaType/PhysicalMediumType/
//	         AccessType/DirectionType)         24 bytes @1128
//	bitfield byte + 3 pad                         4 bytes @1152
//	3 × enum (OperStatus/AdminStatus/MediaConnectState)
//	                                              12 bytes @1156
//	NET_IF_NETWORK_GUID NetworkGuid              16 bytes @1168
//	NET_IF_CONNECTION_TYPE ConnectionType         4 bytes @1184
//	4 bytes pad to ULONG64 alignment              4 bytes @1188
//	ULONG64 TransmitLinkSpeed                     8 bytes @1192
//	ULONG64 ReceiveLinkSpeed                      8 bytes @1200
//	ULONG64 InOctets                              8 bytes @1208 ← TARGET
//	ULONG64 InUcastPkts                           8 bytes @1216
//	ULONG64 InNUcastPkts                          8 bytes @1224
//	ULONG64 InDiscards                            8 bytes @1232
//	ULONG64 InErrors                              8 bytes @1240
//	ULONG64 InUnknownProtos                       8 bytes @1248
//	ULONG64 InUcastOctets                         8 bytes @1256
//	ULONG64 InMulticastOctets                     8 bytes @1264
//	ULONG64 InBroadcastOctets                     8 bytes @1272
//	ULONG64 OutOctets                             8 bytes @1280 ← TARGET
//
// The struct's total size is ~1352 bytes on x64. A 1500-byte buffer
// safely accommodates the full row even if Microsoft extends the
// struct in a future SDK revision (added fields are appended at the
// end; In/Out octet offsets are stable).
const (
	mibIfRow2BufSize         = 1500
	mibIfRow2OffsetOctetsIn  = 1208
	mibIfRow2OffsetOctetsOut = 1280
)

var (
	procGetIfEntry2 = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetIfEntry2")
)

const (
	// loopWatchdogSampleInterval is the cadence at which we poll the
	// adapter's In/Out octet counters. 5 s is slow enough that the
	// per-sample cost (one syscall) is invisible against any reasonable
	// system load, and fast enough that a sustained-loop trip lands
	// within 15-20 s of the loop starting.
	loopWatchdogSampleInterval = 5 * time.Second

	// loopWatchdogThresholdBytesPerSec — 50 MiB/s. Sustained TX above
	// this is implausible for organic VPN workload but trivially
	// exceeded by a routing loop (saturates the underlay link's line
	// rate, typically ~120 MiB/s on gigabit).
	loopWatchdogThresholdBytesPerSec uint64 = 50 * 1024 * 1024

	// loopWatchdogTxToRxRatio — the ratio of OutBps to InBps that
	// distinguishes a loop (TX vastly exceeds RX because handshake
	// responses never arrive) from a legitimate heavy upload-skewed
	// workload (e.g. iperf3 -R, Resilio share). A loop sees TX:RX of
	// effectively infinity; a healthy ackful upload settles around
	// 50:1 because TCP ACKs / WireGuard keepalives flow back. 10:1
	// is the conservative split: it tolerates any plausible legit
	// workload and still trips on a real loop.
	loopWatchdogTxToRxRatio uint64 = 10

	// loopWatchdogSustainedSamples — consecutive over-threshold samples
	// required to trip. 3 × 5 s = 15 s of sustained over-threshold.
	loopWatchdogSustainedSamples = 3
)

// startLoopWatchdog spawns a goroutine that watches the named tunnel
// interface's OutOctets. ctx cancellation stops it; onTrip is invoked
// at most once when sustained runaway TX is detected. The goroutine
// returns immediately after onTrip so a follow-up disconnect from the
// caller side doesn't have to coordinate with this code path.
//
// Returns nil when the LUID can't be resolved (interface might already
// be gone) — the caller can ignore the failure; the loop class this
// guards against requires a live wintun adapter to manifest, so
// "interface gone" is a degenerate state, not one that needs watching.
func startLoopWatchdog(ctx context.Context, ifaceName string, onTrip func(bytesPerSec uint64)) {
	luid, ok := network.LuidFromInterfaceAlias(ifaceName)
	if !ok || luid == 0 {
		slog.Warn("loop watchdog: cannot resolve interface LUID; watchdog disabled",
			"interface", ifaceName)
		return
	}
	go loopWatchdogPoll(ctx, ifaceName, luid, onTrip)
}

func loopWatchdogPoll(ctx context.Context, ifaceName string, luid uint64, onTrip func(uint64)) {
	t := time.NewTicker(loopWatchdogSampleInterval)
	defer t.Stop()
	var prevOut, prevIn uint64
	have := false
	consecutiveOver := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		curIn, curOut, ok := readInterfaceOctets(luid)
		if !ok {
			// Adapter likely gone (disconnect in progress on the other
			// goroutine, or it crashed). One missed sample is OK; we
			// neither trip nor leak state.
			consecutiveOver = 0
			have = false
			continue
		}
		if !have {
			prevOut = curOut
			prevIn = curIn
			have = true
			continue
		}
		var dOut, dIn uint64
		if curOut >= prevOut {
			dOut = curOut - prevOut
		}
		if curIn >= prevIn {
			dIn = curIn - prevIn
		}
		prevOut = curOut
		prevIn = curIn
		seconds := uint64(loopWatchdogSampleInterval / time.Second)
		outRate := dOut / seconds
		inRate := dIn / seconds

		// Trip condition: high absolute TX rate AND grossly asymmetric
		// TX:RX. A routing loop has effectively no RX (handshake
		// responses never arrive because the encrypted packets never
		// escape the local kernel). A heavy upload — even a maxed-out
		// iperf3 -R — has TCP ACKs flowing back that keep the ratio
		// well under 10:1. See loopWatchdogTxToRxRatio for the
		// rationale on the chosen factor.
		highOut := outRate >= loopWatchdogThresholdBytesPerSec
		// "inRate == 0" tripping at high TX is the canonical loop
		// signature (no inbound at all). Avoid divide-by-zero by
		// special-casing inRate == 0.
		asymmetric := inRate == 0 || outRate/maxU64(inRate, 1) >= loopWatchdogTxToRxRatio
		if highOut && asymmetric {
			consecutiveOver++
			slog.Warn("loop watchdog: high TX rate with asymmetric RX",
				"interface", ifaceName,
				"out_bytes_per_sec", outRate,
				"in_bytes_per_sec", inRate,
				"consecutive_samples", consecutiveOver,
				"threshold_bytes_per_sec", loopWatchdogThresholdBytesPerSec,
				"min_tx_to_rx_ratio", loopWatchdogTxToRxRatio)
			if consecutiveOver >= loopWatchdogSustainedSamples {
				slog.Error("loop watchdog: sustained runaway TX with asymmetric RX — forcing disconnect to break the loop",
					"interface", ifaceName,
					"out_bytes_per_sec", outRate,
					"in_bytes_per_sec", inRate,
					"samples", consecutiveOver,
					"window_seconds", int(loopWatchdogSampleInterval.Seconds())*consecutiveOver)
				if onTrip != nil {
					onTrip(outRate)
				}
				return
			}
		} else {
			consecutiveOver = 0
		}
	}
}

// maxU64 returns the larger of two uint64 values. Used to avoid a
// divide-by-zero when computing the TX:RX ratio at idle.
func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// readInterfaceOctets reads MIB_IF_ROW2.InOctets + OutOctets for the
// given LUID via a single GetIfEntry2 syscall. Returns (in, out, true)
// on success, (0, 0, false) on any failure (typically ERROR_NOT_FOUND
// when the adapter is in the middle of being torn down). One syscall
// returns both counters — the previous OutOctets-only path needed two
// snapshots to compute a delta, two syscalls per sample to capture
// asymmetry; this is one.
func readInterfaceOctets(luid uint64) (in uint64, out uint64, ok bool) {
	var buf [mibIfRow2BufSize]byte
	// Set InterfaceLuid at the start of the row. The kernel uses LUID
	// as the lookup key when InterfaceIndex is zero (which it is in
	// our zeroed buffer).
	*(*uint64)(unsafe.Pointer(&buf[0])) = luid
	ret, _, _ := procGetIfEntry2.Call(uintptr(unsafe.Pointer(&buf[0])))
	if ret != 0 {
		return 0, 0, false
	}
	in = *(*uint64)(unsafe.Pointer(&buf[mibIfRow2OffsetOctetsIn]))
	out = *(*uint64)(unsafe.Pointer(&buf[mibIfRow2OffsetOctetsOut]))
	return in, out, true
}
