//go:build windows

package tunnel

// Socket-level loop protection — IP_UNICAST_IF binding for the WireGuard
// UDP sockets, mirroring what the official wireguard-windows client does
// in tunnel/defaultroutemonitor.go.
//
// Why this exists ALONGSIDE the WFP block + iphlpapi bypass routes the
// rest of this branch added:
//
//   - The /32 bypass + WFP BLOCK protect against the loop AT THE ROUTING
//     TABLE / FILTERING LAYER. Both depend on the kernel making a routing
//     decision and either (a) finding the /32 first or (b) hitting our
//     filter when it doesn't. Both have correctness invariants we have to
//     defend continuously (route ordering on install, filter ordering on
//     network state changes, etc.).
//
//   - IP_UNICAST_IF tells the WG UDP socket "regardless of the route
//     table, send through THIS specific interface index." It moves the
//     decision OUT of the route table entirely — the kernel skips its
//     routing lookup for traffic on the bound socket. The wintun adapter
//     can be the longest-prefix match for the peer endpoint and our WG
//     send still goes out the physical NIC. That's the same trick the
//     official client uses as its PRIMARY anti-loop measure.
//
// We keep all three defenses because they fail differently:
//
//   bind miss → routing decision picks wintun → /32 bypass catches it
//   /32 bypass missing or stale → WFP BLOCK at OUTBOUND_TRANSPORT drops it
//   WFP layer disabled by a third-party security driver → watchdog trips
//
// Three layers in series. The official client gets away with one mostly
// because Donenfeld owns the BFE filter weight space; we're an uncertified
// app, so belt-and-suspenders is the right call.
//
// What this file does NOT yet do: NotifyRouteChange2-based push
// notification. We poll the route table every 5s instead. The latency
// difference (push: ~10 ms; poll: up to 5 s) matters in theory but in
// practice WG's own UDP send retry handles the 5 s gap on a network
// transition — handshakes are exponential-backoff, payload is rate-
// limited by congestion control. If we ever see field reports of "WG
// stuck for 5 s after Wi-Fi → Ethernet handoff", upgrade to
// NotifyRouteChange2 via syscall.NewCallback. Not before.

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/korjwl1/wireguide/internal/network"
)

// socketBindPollInterval is the cadence at which we re-check the
// upstream default route and (re)pin the WG socket if it has moved.
// 5 s is fast enough that a Wi-Fi → Ethernet handoff settles into the
// new physical interface well before the WG handshake retry budget
// runs out, and slow enough that the per-poll cost (one
// GetIpForwardTable2 syscall) is invisible against system idle.
const socketBindPollInterval = 5 * time.Second

// pinSocketToPhysical finds the current best non-tunnel default route
// and binds the WG UDP socket(s) to that interface index. Called once
// at connect-time AFTER engine.Start has opened the sockets (otherwise
// BindSocketToInterface4/6 has nothing to bind to).
//
// Returns the (ifIndexV4, ifIndexV6) pair that was bound, or 0/0 if
// the bind type doesn't support interface binding (a no-op platform).
// The returned pair is what the route monitor compares against to
// decide whether re-pinning is needed.
//
// blackhole=true means "no usable default route found"; in that case
// we still call BindSocketToInterface with index 0 and blackhole=true,
// which directs the bind to drop sends rather than fall back to the
// route table (and risk picking up wintun as the longest-prefix match).
// The drop is recoverable — the next poll will repin once a real
// default reappears.
func pinSocketToPhysical(bind conn.Bind, tunnelInterfaceName string) (uint32, uint32) {
	binder, ok := bind.(conn.BindSocketToInterface)
	if !ok {
		// StdNetBind on non-Windows platforms doesn't implement this
		// interface; nothing to pin. The wireguard-go conn package only
		// exposes BindSocketToInterface on Windows (and the WinRingBind
		// + StdNetBind on Windows both implement it). We're built with
		// //go:build windows, so this path means the bind is some
		// stub/mock (tests).
		return 0, 0
	}
	v4 := pinFamily(binder, tunnelInterfaceName, false)
	v6 := pinFamily(binder, tunnelInterfaceName, true)
	return v4, v6
}

// pinFamily resolves one address family's best non-tunnel default route
// and binds the corresponding socket. Returns the bound ifIndex (0 if
// no usable underlay was found and blackhole was applied).
func pinFamily(binder conn.BindSocketToInterface, tunnelInterfaceName string, ipv6 bool) uint32 {
	excludedAliases := []string{tunnelInterfaceName}
	var (
		ifIndex uint32
		ok      bool
	)
	if ipv6 {
		_, ifIndex, _ = network.DefaultRouteV6LuidAndIndex(excludedAliases)
		ok = ifIndex != 0
	} else {
		_, ifIndex, _ = network.DefaultRouteV4LuidAndIndex(excludedAliases)
		ok = ifIndex != 0
	}
	blackhole := !ok
	if ipv6 {
		if err := binder.BindSocketToInterface6(ifIndex, blackhole); err != nil {
			slog.Warn("socket pin v6 failed", "ifIndex", ifIndex, "blackhole", blackhole, "error", err)
			return 0
		}
	} else {
		if err := binder.BindSocketToInterface4(ifIndex, blackhole); err != nil {
			slog.Warn("socket pin v4 failed", "ifIndex", ifIndex, "blackhole", blackhole, "error", err)
			return 0
		}
	}
	slog.Info("WG socket pinned to underlay",
		"family", familyName(ipv6),
		"ifIndex", ifIndex,
		"blackhole", blackhole,
		"tunnel_excluded", tunnelInterfaceName)
	return ifIndex
}

func familyName(ipv6 bool) string {
	if ipv6 {
		return "v6"
	}
	return "v4"
}

// startSocketBindMonitor spawns a goroutine that periodically re-evaluates
// the best non-tunnel default route and re-pins the WG socket(s) when it
// changes. Stops when ctx is cancelled. Safe to call with a nil bind
// (no-op) or a bind that doesn't implement BindSocketToInterface
// (no-op).
//
// Returns the started state via atomic.Pointer-style: a nil return means
// nothing was started (caller has nothing to clean up); a non-nil return
// is the active monitor's cancel-tracking pointer used internally.
func startSocketBindMonitor(ctx context.Context, bind conn.Bind, tunnelInterfaceName string, initialV4, initialV6 uint32) {
	if bind == nil {
		return
	}
	binder, ok := bind.(conn.BindSocketToInterface)
	if !ok {
		return
	}
	// atomic so the goroutine's "previous" values are visible to the
	// caller path (not needed today; futureproofing for status RPC).
	var lastV4 atomic.Uint32
	var lastV6 atomic.Uint32
	lastV4.Store(initialV4)
	lastV6.Store(initialV6)

	go func() {
		t := time.NewTicker(socketBindPollInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				slog.Info("WG socket bind monitor stopped", "tunnel", tunnelInterfaceName)
				return
			case <-t.C:
			}
			newV4 := evaluateAndMaybeRepin(binder, tunnelInterfaceName, false, lastV4.Load())
			if newV4 != 0 || newV4 != lastV4.Load() {
				lastV4.Store(newV4)
			}
			newV6 := evaluateAndMaybeRepin(binder, tunnelInterfaceName, true, lastV6.Load())
			if newV6 != 0 || newV6 != lastV6.Load() {
				lastV6.Store(newV6)
			}
		}
	}()
}

// evaluateAndMaybeRepin checks the current best non-tunnel default for
// one address family. If it differs from `previous`, re-pins the socket
// and returns the new ifIndex. Otherwise returns `previous` unchanged.
//
// The "no default route found" case is special: we re-pin to
// (0, blackhole=true) so a transient underlay loss DOESN'T silently
// fall back through the route table (where wintun could now be the
// longest match for the peer endpoint, depending on bypass-route
// state at that exact moment).
func evaluateAndMaybeRepin(binder conn.BindSocketToInterface, tunnelInterfaceName string, ipv6 bool, previous uint32) uint32 {
	excludedAliases := []string{tunnelInterfaceName}
	var ifIndex uint32
	if ipv6 {
		_, ifIndex, _ = network.DefaultRouteV6LuidAndIndex(excludedAliases)
	} else {
		_, ifIndex, _ = network.DefaultRouteV4LuidAndIndex(excludedAliases)
	}
	if ifIndex == previous {
		return previous
	}
	blackhole := ifIndex == 0
	var err error
	if ipv6 {
		err = binder.BindSocketToInterface6(ifIndex, blackhole)
	} else {
		err = binder.BindSocketToInterface4(ifIndex, blackhole)
	}
	if err != nil {
		slog.Warn("socket re-pin failed",
			"family", familyName(ipv6),
			"new_ifIndex", ifIndex,
			"previous_ifIndex", previous,
			"blackhole", blackhole,
			"error", err)
		return previous
	}
	slog.Info("WG socket re-pinned (underlay changed)",
		"family", familyName(ipv6),
		"previous_ifIndex", previous,
		"new_ifIndex", ifIndex,
		"blackhole", blackhole)
	return ifIndex
}
