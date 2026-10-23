package helper

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
)

// rememberEnabledKillSwitch imports an existing backend state once. It must
// never overwrite an explicit Off that failed to apply. Caller holds connectMu.
func (h *Helper) rememberEnabledKillSwitch() {
	if !h.firewall.IsKillSwitchEnabled() {
		return
	}
	h.mu.Lock()
	if !h.ksIntentKnown {
		h.killSwitchWanted = true
		h.ksIntentKnown = true
	}
	h.mu.Unlock()
}

// reconcileKillSwitch is the retryable wanted -> applied transition. It also
// detects connected-interface changes made outside helper handlers. Caller
// holds connectMu; DNS keeps its own journal and lock.
func (h *Helper) reconcileKillSwitch(force bool, now time.Time) error {
	select {
	case <-h.done:
		return nil
	default:
	}
	if h.fwSuspendDepth > 0 {
		return nil
	}
	h.rememberEnabledKillSwitch()
	h.mu.Lock()
	wanted := h.killSwitchWanted
	cfgs := h.copyActiveCfgs()
	h.mu.Unlock()
	type permit struct {
		Name, Interface string
		Addresses       []string
	}
	var permits []permit
	if wanted {
		for _, st := range tunnelStatuses(h) {
			if st == nil || st.State != domain.StateConnected || st.InterfaceName == "" {
				continue
			}
			var addresses []string
			if cfg := cfgs[st.TunnelName]; cfg != nil {
				addresses = cfg.Interface.Address
			}
			permits = append(permits, permit{st.TunnelName, st.InterfaceName, addresses})
		}
	}
	sort.Slice(permits, func(i, j int) bool { return permits[i].Name < permits[j].Name })
	var endpoints []string
	if wanted {
		endpoints = h.manager.ResolvedEndpoints()
		sort.Strings(endpoints)
	}
	encoded, _ := json.Marshal(struct {
		Wanted    bool
		Permits   []permit
		Endpoints []string
	}{wanted, permits, endpoints})
	signature := string(encoded)
	if signature != h.ksPending {
		h.ksPending = signature
		h.ksRetryDelay = 0
		h.ksRetryAt = time.Time{}
	}
	if !force && (now.Before(h.ksRetryAt) || (signature == h.ksApplied && wanted == h.firewall.IsKillSwitchEnabled())) {
		return nil
	}
	var err error
	if wanted {
		err = h.enableKillSwitchForActiveTunnels()
	} else if h.firewall.IsKillSwitchEnabled() {
		err = h.firewall.DisableKillSwitch()
		if err == nil {
			clear(h.ksIfaces)
		}
	}
	if err != nil {
		h.ksApplied = ""
		h.ksRetryDelay = min(30*time.Second, max(time.Second, h.ksRetryDelay*2))
		h.ksRetryAt = now.Add(h.ksRetryDelay)
		return err
	}
	h.ksApplied = signature
	h.ksRetryDelay = 0
	h.ksRetryAt = time.Time{}
	return nil
}
