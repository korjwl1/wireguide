package helper

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/reconnect"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

func reviewSettingsHelper(t *testing.T, cfgJSON *string, intent desiredStateJSON) *Helper {
	h := newPendingTestHelper(t, "alpha")
	h.userAppSupport = t.TempDir()
	h.logLevel = new(slog.LevelVar)
	h.monitor = reconnect.NewMonitor(h.manager, nil, nil, reconnect.DefaultConfig())
	if cfgJSON != nil {
		if err := os.WriteFile(filepath.Join(h.userAppSupport, "config.json"), []byte(*cfgJSON), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveDesiredIntent(h.dataDir, intent); err != nil {
		t.Fatal(err)
	}
	restoreBootTimeStub(t, func() (time.Time, error) { return time.Now().Add(-time.Hour), nil })
	stubRuleSaysOff(t)
	stubRestoreConnect(t)
	return h
}

// G1-A1: config.json kill_switch=false must win over journal KillSwitch=true.
func TestFirewallRecovery_ConfigKillSwitchOffVsJournal(t *testing.T) {
	c := `{"kill_switch":false,"dns_protection":false}`
	h := reviewSettingsHelper(t, &c, desiredStateJSON{Tunnels: []string{"alpha"}, KillSwitch: true})
	h.restoreUserSettings()
	h.restoreDesiredTunnels()
	if h.killSwitchWanted || h.firewall.IsKillSwitchEnabled() || loadDesiredIntent(h.dataDir).KillSwitch {
		t.Errorf("DEFECT: config kill_switch=false ignored; wanted=%v fw=%v journal=%v",
			h.killSwitchWanted, h.firewall.IsKillSwitchEnabled(), loadDesiredIntent(h.dataDir).KillSwitch)
	}
}

// G1-A2: config.json absent (defaults) is treated as a known DNS Off and
// drops the journal's DNS On.
func TestFirewallRecovery_MissingConfigDropsJournalDNSOn(t *testing.T) {
	h := reviewSettingsHelper(t, nil, desiredStateJSON{Tunnels: []string{"alpha"}, DNSProtection: true})
	h.restoreUserSettings()
	h.restoreDesiredTunnels()
	if !h.dnsProtectionWanted {
		t.Errorf("FINDING: config.json absent -> dnsIntentKnown=%v; journal DNS On dropped (journal now %v)",
			h.dnsIntentKnown, loadDesiredIntent(h.dataDir).DNSProtection)
	}
}

// G1-A3: Windows, default config (dns_protection false, never explicitly
// turned off). A crash-restored full tunnel should keep the automatic DNS
// protection a normal connect gets.
func TestFirewallRecovery_WindowsRestoredFullTunnelLosesAutoDNS(t *testing.T) {
	prevF := fullTunnelForcesDNSProtection
	fullTunnelForcesDNSProtection = true
	t.Cleanup(func() { fullTunnelForcesDNSProtection = prevF })
	c := `{"dns_protection":false}`
	h := reviewSettingsHelper(t, &c, desiredStateJSON{Tunnels: []string{"alpha"}})
	h.restoreUserSettings()
	cfg := &domain.WireGuardConfig{Name: "full"}
	cfg.Interface.DNS = []string{"1.1.1.1"}
	cfg.Peers = []domain.PeerConfig{{AllowedIPs: []string{"0.0.0.0/0"}}}
	h.mu.Lock()
	h.activeCfgs["full"] = cfg
	h.mu.Unlock()
	prev := tunnelStatuses
	tunnelStatuses = func(*Helper) []*tunnel.ConnectionStatus {
		return []*tunnel.ConnectionStatus{{TunnelName: "full", InterfaceName: "wg0", State: domain.StateConnected}}
	}
	t.Cleanup(func() { tunnelStatuses = prev })
	h.applyConnectedFirewall(cfg, false) // restore / pending-retry path
	restored := h.dnsProtectionNeeded()
	h.applyPostConnectFirewall(cfg) // new user connect
	fresh := h.dnsProtectionNeeded()
	t.Logf("restored needs DNS protection=%v, fresh connect=%v", restored, fresh)
	if restored != fresh {
		t.Errorf("DEFECT: Windows restored full tunnel (default config, no explicit Off) gets no auto DNS protection; fresh connect does")
	}
}

func TestFirewallRecovery_DNSAutoOffJournalAndLiveUpdate(t *testing.T) {
	for _, liveOn := range []bool{false, true} {
		t.Run(fmt.Sprintf("liveOn=%t", liveOn), func(t *testing.T) {
			c := `{"dns_protection":false}`
			h := reviewSettingsHelper(t, &c, desiredStateJSON{Tunnels: []string{"alpha"}, DNSAutoOff: true})
			h.restoreUserSettings()
			if liveOn {
				prev := restoreRuleSaysOff
				restoreRuleSaysOff = func(hh *Helper, _ string) bool {
					if _, err := hh.handleSetDNSProtection(json.RawMessage(`{"enabled":true}`)); err != nil {
						t.Error(err)
					}
					return false
				}
				t.Cleanup(func() { restoreRuleSaysOff = prev })
			}
			h.restoreDesiredTunnels()
			if h.dnsAutoOff == liveOn || loadDesiredIntent(h.dataDir).DNSAutoOff == liveOn {
				t.Fatal("automatic DNS Off was lost or overrode live On")
			}
			if !liveOn {
				cfg := h.activeCfgs["alpha"]
				cfg.Peers = []domain.PeerConfig{{AllowedIPs: []string{"0.0.0.0/0"}}}
				h.applyPostConnectFirewall(cfg)
				if h.dnsAutoOff || loadDesiredIntent(h.dataDir).DNSAutoOff {
					t.Fatal("fresh full connect did not persist override reset")
				}
			}
		})
	}
}

func TestFirewallRecovery_PersistsExplicitDNSOffSeparatelyFromDefault(t *testing.T) {
	h := newPendingTestHelper(t)
	h.activeCfgs["alpha"] = &domain.WireGuardConfig{Name: "alpha"}
	if _, err := h.handleSetDNSProtection(json.RawMessage(`{"enabled":false}`)); err != nil {
		t.Fatal(err)
	}
	if got := loadDesiredIntent(h.dataDir); !got.DNSAutoOff || got.DNSProtection {
		t.Fatalf("explicit Off journal=%+v", got)
	}
}

func TestFirewallRecovery_ConfigKillSwitchOnProtectsBeforeRestoreConnect(t *testing.T) {
	c := `{"kill_switch":true}`
	h := reviewSettingsHelper(t, &c, desiredStateJSON{Tunnels: []string{"alpha"}})
	h.restoreUserSettings()
	prev := restoreConnect
	restoreConnect = func(hh *Helper, _ *domain.WireGuardConfig) error {
		if !hh.firewall.IsKillSwitchEnabled() {
			t.Error("config KS On was not enforced before restore connect")
		}
		return errors.New("offline")
	}
	t.Cleanup(func() { restoreConnect = prev })
	h.restoreDesiredTunnels()
	if !h.firewall.IsKillSwitchEnabled() {
		t.Fatal("failed restore lost configured blockade")
	}
}

func TestFirewallRecovery_MissingFieldsDoNotOverrideJournal(t *testing.T) {
	c := `{"theme":"dark"}`
	h := reviewSettingsHelper(t, &c, desiredStateJSON{Tunnels: []string{"alpha"}, DNSProtection: true, KillSwitch: true})
	h.restoreUserSettings()
	h.restoreDesiredTunnels()
	if !h.dnsProtectionWanted || !h.killSwitchWanted {
		t.Fatal("absent settings fields were mistaken for Off")
	}
}

func TestFirewallRecovery_NewFullConnectWinsOverSnapshottedAutoOff(t *testing.T) {
	c := `{"dns_protection":false}`
	h := reviewSettingsHelper(t, &c, desiredStateJSON{Tunnels: []string{"alpha"}, DNSAutoOff: true})
	h.restoreUserSettings()
	prev := restoreRuleSaysOff
	restoreRuleSaysOff = func(hh *Helper, _ string) bool {
		cfg := &domain.WireGuardConfig{Name: "alpha", Peers: []domain.PeerConfig{{AllowedIPs: []string{"0.0.0.0/0"}}}}
		hh.activeCfgs["alpha"] = cfg
		hh.applyPostConnectFirewall(cfg)
		return false
	}
	t.Cleanup(func() { restoreRuleSaysOff = prev })
	h.restoreDesiredTunnels()
	if h.dnsAutoOff || loadDesiredIntent(h.dataDir).DNSAutoOff {
		t.Fatal("stale auto-Off overrode new full-tunnel connect")
	}
}

func TestFirewallRecovery_SavedKillSwitchDoesNotBlockIdleStartup(t *testing.T) {
	for _, restoreOnStart := range []bool{false, true} {
		t.Run(fmt.Sprintf("restore=%t", restoreOnStart), func(t *testing.T) {
			c := `{"kill_switch":true}`
			h := reviewSettingsHelper(t, &c, desiredStateJSON{})
			h.restoreOnStart = restoreOnStart
			h.restoreUserSettings()
			h.restoreDesiredTunnels()
			if err := h.reconcileKillSwitch(false, time.Now()); err != nil {
				t.Fatal(err)
			}
			if h.killSwitchWanted || h.firewall.IsKillSwitchEnabled() {
				t.Fatal("saved preference blocked idle startup with no recoverable tunnels")
			}
		})
	}
}
