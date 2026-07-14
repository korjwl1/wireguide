//go:build windows

package reconnect

import (
	"log/slog"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/network"
)

// On Windows the reconnect detector watches the IPv4 default-route owner
// (the LUID of the interface that wins 0.0.0.0/0) and fires on change.
// It is a deliberate departure from a naïve `NotifyIpInterfaceChange`
// subscription: that callback fires on adapter add/remove, IP bind, and
// metric changes — including the changes our OWN Wintun adapter causes
// every time it comes up. Subscribing to it produced a suicide reconnect
// loop where every Connect triggered a change → reconnect → tear-down →
// another change.
//
// Polling the default-route owner avoids the loop because:
//  1. Our Wintun adapter is filtered out of the candidate set (see
//     network.BestNonExcludedDefaultRouteLUIDv4 — it excludes any
//     interface alias in vpnAdapterAliases).
//  2. The non-VPN default route only flips when the user actually
//     changes upstream (Wi-Fi → Ethernet, captive portal hop, etc).
//  3. Connect / Disconnect of the VPN itself never changes the
//     non-excluded LUID, so the monitor never reconnects in response
//     to its own actions.
//
// We poll at 1Hz to match the darwin detector and to keep CPU near
// zero (one GetIpForwardTable2 syscall per second; <1ms on a typical
// machine).

// vpnAdapterAliases aliases network.VPNAdapterAliases — the single
// source of truth for which adapter names are ours (and thus excluded
// from underlay-route detection).
var vpnAdapterAliases = network.VPNAdapterAliases

const (
	// networkPollIntervalWindows mirrors darwin's networkPollInterval —
	// fast enough to feel responsive after a real Wi-Fi handover, slow
	// enough that the polling cost is invisible (~one syscall/sec).
	networkPollIntervalWindows = 1 * time.Second

	// fireCooldownWindows mirrors darwin's fireCooldown. During a Wi-Fi
	// flap (en0 → none → en0 in <2s) we want exactly one reconnect,
	// not two stacking backoffs. Also gives the Connect path itself a
	// quiet window for its own transient route-table edits to settle
	// before the detector starts judging "did the upstream change?".
	fireCooldownWindows = 2 * time.Second
)

// windowsNetworkChangeDetector polls the IPv4 default-route owner and
// emits one signal on ChangeChan() each time it switches to a different
// non-VPN interface.
type windowsNetworkChangeDetector struct {
	mu       sync.Mutex
	changeCh chan struct{}
	stopCh   chan struct{}
	wg       sync.WaitGroup
	running  bool
}

func NewNetworkChangeDetector() NetworkChangeDetector {
	return &windowsNetworkChangeDetector{
		changeCh: make(chan struct{}, 1),
	}
}

func (d *windowsNetworkChangeDetector) Start() {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return
	}
	d.running = true
	d.stopCh = make(chan struct{})
	// wg.Add MUST be inside the lock — same reason documented on the
	// darwin detector: Stop() must not observe a zero counter racing
	// against Start()'s Add.
	d.wg.Add(1)
	d.mu.Unlock()

	go d.poll()
}

func (d *windowsNetworkChangeDetector) Stop() {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return
	}
	d.running = false
	close(d.stopCh)
	d.mu.Unlock()
	d.wg.Wait()
}

func (d *windowsNetworkChangeDetector) ChangeChan() <-chan struct{} {
	return d.changeCh
}

func (d *windowsNetworkChangeDetector) sendChange() {
	select {
	case d.changeCh <- struct{}{}:
	default:
		// A signal is already pending; the consumer hasn't drained it
		// yet. Collapse into the existing one.
	}
}

func (d *windowsNetworkChangeDetector) poll() {
	defer d.wg.Done()

	slog.Info("network change detector started (windows poll)",
		"poll_interval", networkPollIntervalWindows,
		"excluded_aliases", vpnAdapterAliases)

	ticker := time.NewTicker(networkPollIntervalWindows)
	defer ticker.Stop()

	var lastLuid uint64
	var hasInitial bool
	var heartbeat int
	var lastFire time.Time

	for {
		select {
		case <-d.stopCh:
			slog.Info("network change detector stopped (windows poll)")
			return
		case <-ticker.C:
			luid := network.BestNonExcludedDefaultRouteLUIDv4(vpnAdapterAliases)
			if !hasInitial {
				hasInitial = true
				lastLuid = luid
				slog.Info("network primary upstream interface initial", "luid", luid)
				continue
			}
			heartbeat++
			if heartbeat%30 == 0 {
				slog.Debug("network polling heartbeat", "luid", luid)
			}
			if luid == lastLuid {
				continue
			}
			prev := lastLuid
			lastLuid = luid

			if !lastFire.IsZero() && time.Since(lastFire) < fireCooldownWindows {
				slog.Info("network primary upstream changed (suppressed by cooldown)",
					"prev_luid", prev, "now_luid", luid,
					"since_last_fire", time.Since(lastFire).Round(time.Millisecond))
				continue
			}

			lastFire = time.Now()
			slog.Info("network primary upstream changed",
				"prev_luid", prev, "now_luid", luid)
			d.sendChange()
		}
	}
}
