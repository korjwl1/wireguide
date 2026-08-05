//go:build darwin

package tunnel

// Runaway-TX watchdog — final defense-in-depth against the routing loop
// class of bug on macOS. The primary defenses are:
//
//   1. /32 bypass host route installed BEFORE the /1 split routes, with
//      fail-fast preflight on missing default gateway
//      (internal/network/darwin.go).
//   2. reapply() blackhole fallback on network-change events when the
//      upstream gateway briefly disappears — keeps the loop class
//      contained at the cost of breaking the tunnel until the next
//      RTM event delivers a real gateway.
//
// This watchdog catches the residual case where neither defense fired —
// third-party software ripping our /32 bypass out from under us, a kernel
// route-table mutation we didn't anticipate, or the brief delete-then-add
// window inside reapply() when the gateway changes. It samples the tunnel
// interface's Obytes/Ibytes at a slow cadence via `netstat -ibn` and
// forces a disconnect when sustained TX exceeds a "no plausible user
// workload" ceiling with grossly asymmetric RX (the canonical loop
// signature: encrypted UDP loops through utun and never reaches the
// peer, so no handshake response ever arrives).
//
// Threshold rationale matches the Windows watchdog exactly — see
// loop_watchdog_windows.go for the full derivation. In short:
//   - 50 MiB/s ≈ 400 Mbps: above sustained organic VPN workload, well
//     below the kernel-line-rate a loop produces (gigabit physical link
//     saturates at ~120 MiB/s).
//   - 10:1 TX:RX ratio: tolerates upload-heavy workloads (iperf3 -R,
//     Resilio share) which settle around 50:1 thanks to TCP ACKs /
//     WireGuard keepalives; trips on the effectively-infinite ratio a
//     real loop produces.
//   - 3 × 5 s = 15 s sustained: defeats bursty downloads and brief
//     speed-tests, trips on the steady-state loop signature.

/*
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_mib.h>

// iface_octets fetches the 64-bit interface byte counters via the IFMIB
// sysctl — the same source netstat prints. Two approaches that look right
// are wrong (both verified empirically against netstat on live traffic):
//   - NET_RT_IFLIST2's if_msghdr2.ifm_data.ifi_ibytes WRAPS AT 32 BITS on
//     modern macOS even though the field is declared u_int64_t; only the
//     IFMIB ifmd_data carries true 64-bit counters.
//   - Reading pack(4) structs through cgo's generated Go types misreads
//     fields — cgo lays them out with natural alignment. So the struct
//     access stays here in C, compiled by clang against the real headers.
static int iface_octets(int ifindex, unsigned long long *ibytes, unsigned long long *obytes) {
	struct ifmibdata md;
	size_t len = sizeof(md);
	int mib[6] = {CTL_NET, PF_LINK, NETLINK_GENERIC, IFMIB_IFDATA, ifindex, IFDATA_GENERAL};
	if (sysctl(mib, 6, &md, &len, NULL, 0) != 0) {
		return 0;
	}
	*ibytes = md.ifmd_data.ifi_ibytes;
	*obytes = md.ifmd_data.ifi_obytes;
	return 1;
}
*/
import "C"
import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	loopWatchdogSampleInterval               = 5 * time.Second
	loopWatchdogThresholdBytesPerSec  uint64 = 50 * 1024 * 1024
	loopWatchdogTxToRxRatio           uint64 = 10
	loopWatchdogSustainedSamples             = 3
	// netstatCmdTimeout bounds each netstat invocation. The Mac
	// network manager already uses 30 s for the heavier route-table
	// commands, but netstat -ibnI <iface> is a tight kernel query
	// that should complete in well under a second. 5 s is generous
	// without holding the watchdog goroutine if a stuck netstat
	// happens to hit a deadlock.
	netstatCmdTimeout = 5 * time.Second
)

// startLoopWatchdog spawns a goroutine that watches the named tunnel
// interface's Obytes/Ibytes. ctx cancellation stops it; onTrip is invoked
// at most once when sustained runaway TX with asymmetric RX is detected.
// The goroutine returns immediately after onTrip so a follow-up disconnect
// from the caller side doesn't have to coordinate with this code path.
func startLoopWatchdog(ctx context.Context, ifaceName string, onTrip func(bytesPerSec uint64)) {
	slog.Debug("loop watchdog: starting", "interface", ifaceName,
		"sample_interval", loopWatchdogSampleInterval,
		"threshold_bytes_per_sec", loopWatchdogThresholdBytesPerSec,
		"sustained_samples", loopWatchdogSustainedSamples)
	go loopWatchdogPoll(ctx, ifaceName, onTrip)
}

func loopWatchdogPoll(ctx context.Context, ifaceName string, onTrip func(uint64)) {
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
		curIn, curOut, ok := readInterfaceOctets(ifaceName)
		if !ok {
			// Interface likely gone (disconnect already in flight on
			// another goroutine). One missed sample is fine; reset the
			// baseline so the next reading isn't compared against a
			// stale snapshot from before the interface bounced.
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

// readInterfaceOctets reads the kernel's input/output byte counters for
// the named interface. Primary path is a NET_RT_IFLIST2 sysctl — a plain
// syscall, matching the Windows watchdog's GetIfEntry2 approach — because
// the previous `netstat -ibnI` implementation fork/exec'd a subprocess
// every 5 s for the life of every full-tunnel connection (~17k spawns/day,
// keeping laptops out of deep idle). netstat is kept as a fallback should
// the sysctl ever fail.
func readInterfaceOctets(ifaceName string) (uint64, uint64, bool) {
	if in, out, ok := readInterfaceOctetsSysctl(ifaceName); ok {
		return in, out, ok
	}
	return readInterfaceOctetsNetstat(ifaceName)
}

// readInterfaceOctetsSysctl queries NET_RT_IFLIST2 filtered by interface
// index and reads if_data64.ifi_ibytes/ifi_obytes from the RTM_IFINFO2
// message. The buffer walk and struct access live in the cgo preamble's
// iface_octets — see the comment there for why the C side must do it.
func readInterfaceOctetsSysctl(ifaceName string) (uint64, uint64, bool) {
	ifi, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return 0, 0, false
	}
	var ibytes, obytes C.ulonglong
	if C.iface_octets(C.int(ifi.Index), &ibytes, &obytes) == 0 {
		return 0, 0, false
	}
	return uint64(ibytes), uint64(obytes), true
}

// readInterfaceOctetsNetstat is the subprocess fallback: `netstat -ibnI
// <iface>`. The first data row is the AF_LINK (aggregate) entry whose
// Ibytes/Obytes are the totals across all address families on the
// interface — the per-address-family rows that follow carry the same
// totals (they're aliases of the link entry, not partitions), so taking
// the first data row is correct and avoids double-counting on multihomed
// interfaces.
//
// Column positions are resolved from the header row dynamically rather
// than hardcoded. Apple has shipped layout-different netstat versions
// across macOS releases (e.g. an added Drop column on more recent
// builds); positional parsing would silently misread on newer versions
// while the header-driven approach is forward-compatible.
//
// LC_ALL=C forces English headers ("Ibytes"/"Obytes") on non-English
// macOS installs, mirroring what the rest of the darwin network code
// does for its netstat parsers.
func readInterfaceOctetsNetstat(ifaceName string) (uint64, uint64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), netstatCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "netstat", "-ibnI", ifaceName)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	output, err := cmd.Output()
	if err != nil {
		return 0, 0, false
	}
	return parseNetstatIB(output, ifaceName)
}

// parseNetstatIB extracts Ibytes/Obytes for the named interface from
// `netstat -ib`-style output. Split from readInterfaceOctets so the
// parsing logic — the only piece that can silently misread on future
// netstat layout drift — is unit-testable without invoking netstat.
//
// Tokenization quirk: header positions don't work directly on data rows.
// For a TUN/utun interface, the Address column is empty (no MAC), so
// `strings.Fields` collapses adjacent whitespace and the data row has
// one fewer field than the header. We instead measure how many columns
// FOLLOW Obytes in the header (always 1 for Coll, or 2 if a Drop column
// is present on newer macOS) and use that fixed trailer width to locate
// Obytes in the data row from the right edge. Ibytes is always exactly
// 3 columns before Obytes (Ibytes/Opkts/Oerrs/Obytes is fixed in the
// netstat source).
func parseNetstatIB(output []byte, ifaceName string) (uint64, uint64, bool) {
	scanner := bufio.NewScanner(bytes.NewReader(output))
	headerLen := -1
	headerObytesIdx := -1
	headerNameIdx := -1
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if headerLen < 0 {
			// Header row. Locate Obytes and Name to derive their
			// positions-from-right in subsequent data rows.
			for i, f := range fields {
				switch f {
				case "Name":
					headerNameIdx = i
				case "Obytes":
					headerObytesIdx = i
				}
			}
			if headerObytesIdx < 0 {
				return 0, 0, false
			}
			headerLen = len(fields)
			continue
		}
		// Derive data-row indices from the fixed trailer width.
		// data_obytes_idx counts back from the right by the same number
		// of fields that followed Obytes in the header.
		trailerWidth := headerLen - headerObytesIdx - 1
		dataObytesIdx := len(fields) - trailerWidth - 1
		dataIbytesIdx := dataObytesIdx - 3
		if dataIbytesIdx < 0 || dataObytesIdx < 0 {
			continue
		}
		// Verify the row matches the interface we asked about. `netstat
		// -I` filters server-side, but defending against the no-filter
		// future and against parsing-the-wrong-row bugs costs nothing.
		if headerNameIdx >= 0 && headerNameIdx < len(fields) && fields[headerNameIdx] != ifaceName {
			continue
		}
		in, err1 := strconv.ParseUint(fields[dataIbytesIdx], 10, 64)
		out, err2 := strconv.ParseUint(fields[dataObytesIdx], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		return in, out, true
	}
	return 0, 0, false
}
