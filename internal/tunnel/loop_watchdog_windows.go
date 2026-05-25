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

// mibIfRow2 mirrors the C MIB_IF_ROW2 struct so we can use
// unsafe.Offsetof to locate the two counters we need (InOctets,
// OutOctets) instead of hardcoding numeric byte offsets. Hardcoded
// offsets would be a silent ABI break if Microsoft ever inserts a field
// in a future SDK; the offsetof path moves with the struct definition.
//
// Microsoft does NOT publicly document byte offsets in this struct —
// they're a consequence of C layout rules on the declared fields. The
// definition below matches netioapi.h exactly for both x64 and ARM64,
// where every member is naturally aligned and there are no pointers.
//
// Fields we don't read are kept as fixed-size byte arrays / padding —
// this saves the boilerplate of importing GUID and several enum types
// while preserving the C struct's overall size and field-offset layout.
type mibIfRow2 struct {
	InterfaceLuid              uint64
	InterfaceIndex             uint32
	InterfaceGuid              [16]byte // GUID
	Alias                      [257]uint16
	Description                [257]uint16
	PhysicalAddressLength      uint32
	PhysicalAddress            [32]byte
	PermanentPhysicalAddress   [32]byte
	Mtu                        uint32
	Type                       uint32
	TunnelType                 uint32
	MediaType                  uint32
	PhysicalMediumType         uint32
	AccessType                 uint32
	DirectionType              uint32
	InterfaceAndOperStatusFlags uint8
	_padFlags                  [3]uint8
	OperStatus                 uint32
	AdminStatus                uint32
	MediaConnectState          uint32
	NetworkGuid                [16]byte
	ConnectionType             uint32
	_padToU64                  [4]byte
	TransmitLinkSpeed          uint64
	ReceiveLinkSpeed           uint64
	InOctets                   uint64
	InUcastPkts                uint64
	InNUcastPkts               uint64
	InDiscards                 uint64
	InErrors                   uint64
	InUnknownProtos            uint64
	InUcastOctets              uint64
	InMulticastOctets          uint64
	InBroadcastOctets          uint64
	OutOctets                  uint64
	OutUcastPkts               uint64
	OutNUcastPkts              uint64
	OutDiscards                uint64
	OutErrors                  uint64
	OutUcastOctets             uint64
	OutMulticastOctets         uint64
	OutBroadcastOctets         uint64
	OutQLen                    uint64
}


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
	var row mibIfRow2
	// Kernel uses InterfaceLuid as the lookup key when InterfaceIndex is
	// zero — set the LUID and leave the rest of the struct zeroed.
	row.InterfaceLuid = luid
	ret, _, _ := procGetIfEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if ret != 0 {
		return 0, 0, false
	}
	return row.InOctets, row.OutOctets, true
}
