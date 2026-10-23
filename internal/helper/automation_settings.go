package helper

import (
	"encoding/json"
	"log/slog"

	"github.com/korjwl1/wireguide/internal/automation"
	"github.com/korjwl1/wireguide/internal/domain"
)

// anyNegatedRules reports whether any tunnel has a negated automation rule.
func (h *Helper) anyNegatedRules() bool {
	settings, err := h.loadUserSettings()
	if err != nil {
		return false
	}
	settings.EnsureAutomation()
	if settings.Automation == nil {
		return false
	}
	for _, rules := range settings.Automation.PerTunnel {
		if automation.HasNegated(rules) {
			return true
		}
	}
	return false
}

// automationRules returns tunnel name's automation rules (nil when settings
// can't be read).
func (h *Helper) automationRules(name string) []automation.Rule {
	settings, err := h.loadUserSettings()
	if err != nil {
		return nil
	}
	settings.EnsureAutomation()
	if settings.Automation == nil {
		return nil
	}
	return settings.Automation.PerTunnel[name]
}

// automationRuleTunnels returns the set of tunnels that have automation
// rules (empty when settings can't be read).
func (h *Helper) automationRuleTunnels() map[string]bool {
	out := map[string]bool{}
	settings, err := h.loadUserSettings()
	if err != nil {
		return out
	}
	settings.EnsureAutomation()
	if settings.Automation == nil {
		return out
	}
	for name, rules := range settings.Automation.PerTunnel {
		if len(rules) > 0 {
			out[name] = true
		}
	}
	return out
}

// Only automatically established intent uses the LAN conflict guard. A
// manual On override keeps the user's explicitly imported route policy.
func (h *Helper) automaticLANConflict(cfg *domain.WireGuardConfig) bool {
	if l, ok := h.manualLatchFor(cfg.Name); ok && !l.disconnected {
		return false
	}
	h.wifiMu.Lock()
	_, owned := h.autoConnectedBy[cfg.Name]
	h.wifiMu.Unlock()
	if !owned {
		return false
	}
	cidr, addr, conflict := overlapsLocalNetwork(cfg)
	if conflict {
		h.reportAutomationOverlap(cfg.Name, cidr, addr)
	} else {
		h.clearAutomationSkip(cfg.Name)
	}
	return conflict
}

func (h *Helper) restoreUserSettings() {
	if settings, err := h.loadUserSettings(); err == nil {
		// Defaults are not user intent. Only fields actually present in a
		// readable config can supersede the crash journal. In particular,
		// DNSProtection=false is the Windows default, not an explicit veto
		// of full-tunnel automatic DNS protection.
		var persisted struct {
			DNSProtection *bool `json:"dns_protection"`
			KillSwitch    *bool `json:"kill_switch"`
		}
		if raw, err := h.readUserSettingsBytes(); err == nil && json.Unmarshal(raw, &persisted) == nil {
			h.mu.Lock()
			if persisted.DNSProtection != nil {
				h.dnsProtectionWanted = *persisted.DNSProtection
				h.dnsIntentKnown = true
			}
			if persisted.KillSwitch != nil {
				h.ksRestoreOn = *persisted.KillSwitch
				if !*persisted.KillSwitch {
					h.killSwitchWanted = false
					h.ksIntentKnown = true
				}
			}
			h.mu.Unlock()
		}
		h.monitor.SetHealthCheck(settings.HealthCheck)
		if settings.PinInterface {
			if err := h.manager.SetPinInterface(true); err != nil {
				slog.Warn("restore pin-interface failed", "error", err)
			}
		}
		if settings.LogLevel != "" {
			h.logLevel.Set(parseLevel(settings.LogLevel))
		}
		slog.Info("restored persisted helper settings",
			"health_check", settings.HealthCheck,
			"pin_interface", settings.PinInterface,
			"log_level", settings.LogLevel)
	}
}
