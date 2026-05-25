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

// MIB_IF_ROW2 layout offset for OutOctets on 64-bit Windows.
//
// The struct's fields up to OutOctets (per netioapi.h):
//
//	NET_LUID InterfaceLuid                        8
//	NET_IFINDEX InterfaceIndex                    4
//	GUID InterfaceGuid                           16 (offset 12 + GUID alignment)
//	WCHAR Alias[257]                            514 (offset 28; 514 bytes; 2-byte aligned)
//	WCHAR Description[257]                      514 (offset 542)
//	ULONG PhysicalAddressLength                   4 (offset 1056; ULONG aligned)
//	UCHAR PhysicalAddress[32]                    32 (offset 1060)
//	UCHAR PermanentPhysicalAddress[32]           32 (offset 1092)
//	ULONG Mtu                                     4 (offset 1124)
//	IFTYPE Type                                   4 (offset 1128)
//	TUNNEL_TYPE TunnelType                        4 (offset 1132)
//	NDIS_MEDIUM MediaType                         4 (offset 1136)
//	NDIS_PHYSICAL_MEDIUM PhysicalMediumType       4 (offset 1140)
//	NET_IF_ACCESS_TYPE AccessType                 4 (offset 1144)
//	NET_IF_DIRECTION_TYPE DirectionType           4 (offset 1148)
//	<bitfield byte>                               1 (offset 1152)
//	<3 bytes pad to align next ULONG>             3
//	IF_OPER_STATUS OperStatus                     4 (offset 1156)
//	NET_IF_ADMIN_STATUS AdminStatus               4 (offset 1160)
//	NET_IF_MEDIA_CONNECT_STATE MediaConnectState  4 (offset 1164)
//	NET_IF_NETWORK_GUID NetworkGuid              16 (offset 1168)
//	NET_IF_CONNECTION_TYPE ConnectionType         4 (offset 1184)
//	<4 bytes pad to align ULONG64>                4 (offset 1188)
//	ULONG64 TransmitLinkSpeed                     8 (offset 1192)
//	ULONG64 ReceiveLinkSpeed                      8 (offset 1200)
//	ULONG64 InOctets                              8 (offset 1208)
//	ULONG64 InUcastPkts                           8 (offset 1216)
//	ULONG64 InNUcastPkts                          8 (offset 1224)
//	ULONG64 InDiscards                            8 (offset 1232)
//	ULONG64 InErrors                              8 (offset 1240)
//	ULONG64 InUnknownProtos                       8 (offset 1248)
//	ULONG64 InUcastOctets                         8 (offset 1256)
//	ULONG64 InMulticastOctets                     8 (offset 1264)
//	ULONG64 InBroadcastOctets                     8 (offset 1272)
//	ULONG64 OutOctets                             8 (offset 1280) ← TARGET
//
// The struct's total size is ~1352 bytes on x64. A 1500-byte buffer
// safely accommodates the full row even if Microsoft extends the
// struct in a future SDK revision (added fields are appended at the
// end; OutOctets offset is stable).
const (
	mibIfRow2BufSize         = 1500
	mibIfRow2OffsetOctetsOut = 1280
)

var (
	procGetIfEntry2 = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetIfEntry2")
)

const (
	// loopWatchdogSampleInterval is the cadence at which we poll the
	// adapter's OutOctets counter. 5 s is slow enough that the per-sample
	// cost (one syscall) is invisible against any reasonable system
	// load, and fast enough that a sustained-loop trip lands within
	// 15-20 s of the loop starting.
	loopWatchdogSampleInterval = 5 * time.Second

	// loopWatchdogThresholdBytesPerSec — 50 MiB/s, see file header.
	loopWatchdogThresholdBytesPerSec uint64 = 50 * 1024 * 1024

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
	var prev uint64
	have := false
	consecutiveOver := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cur, ok := readInterfaceOutOctets(luid)
		if !ok {
			// Adapter likely gone (disconnect in progress on the other
			// goroutine, or it crashed). One missed sample is OK; we
			// neither trip nor leak state.
			consecutiveOver = 0
			have = false
			continue
		}
		if !have {
			prev = cur
			have = true
			continue
		}
		var delta uint64
		if cur >= prev {
			delta = cur - prev
		}
		prev = cur
		ratePerSec := delta / uint64(loopWatchdogSampleInterval/time.Second)
		if ratePerSec >= loopWatchdogThresholdBytesPerSec {
			consecutiveOver++
			slog.Warn("loop watchdog: high TX rate observed",
				"interface", ifaceName,
				"bytes_per_sec", ratePerSec,
				"consecutive_samples", consecutiveOver,
				"threshold_bytes_per_sec", loopWatchdogThresholdBytesPerSec)
			if consecutiveOver >= loopWatchdogSustainedSamples {
				slog.Error("loop watchdog: sustained runaway TX — forcing disconnect to break the loop",
					"interface", ifaceName,
					"bytes_per_sec", ratePerSec,
					"samples", consecutiveOver,
					"window_seconds", int(loopWatchdogSampleInterval.Seconds())*consecutiveOver)
				if onTrip != nil {
					onTrip(ratePerSec)
				}
				return
			}
		} else {
			consecutiveOver = 0
		}
	}
}

// readInterfaceOutOctets reads MIB_IF_ROW2.OutOctets for the given LUID
// via GetIfEntry2. Returns (count, true) on success, (0, false) on any
// syscall failure (typically ERROR_NOT_FOUND when the adapter is in the
// middle of being torn down).
func readInterfaceOutOctets(luid uint64) (uint64, bool) {
	var buf [mibIfRow2BufSize]byte
	// Set InterfaceLuid at the start of the row. The kernel uses LUID
	// as the lookup key when InterfaceIndex is zero (which it is in
	// our zeroed buffer).
	*(*uint64)(unsafe.Pointer(&buf[0])) = luid
	ret, _, _ := procGetIfEntry2.Call(uintptr(unsafe.Pointer(&buf[0])))
	if ret != 0 {
		return 0, false
	}
	return *(*uint64)(unsafe.Pointer(&buf[mibIfRow2OffsetOctetsOut])), true
}
