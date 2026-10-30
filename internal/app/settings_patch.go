package app

import (
	"errors"
	"fmt"
	"os"

	"github.com/korjwl1/wireguide/internal/autostart"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// SettingsPatch owns only explicitly changed preferences. Automation has its
// own per-tunnel API and cannot be resurrected by a stale settings window.
type SettingsPatch struct {
	Language        *string `json:"language,omitempty"`
	Theme           *string `json:"theme,omitempty"`
	TrayIconStyle   *string `json:"tray_icon_style,omitempty"`
	AutoStart       *bool   `json:"auto_start,omitempty"`
	KillSwitch      *bool   `json:"kill_switch,omitempty"`
	DNSProtection   *bool   `json:"dns_protection,omitempty"`
	HealthCheck     *bool   `json:"health_check,omitempty"`
	PinInterface    *bool   `json:"pin_interface,omitempty"`
	LogLevel        *string `json:"log_level,omitempty"`
	TunnelBackend   *string `json:"tunnel_backend,omitempty"`
	AutoUpdateCheck *bool   `json:"auto_update_check,omitempty"`
	CompactList     *bool   `json:"compact_list,omitempty"`
	ListSort        *string `json:"list_sort,omitempty"`
	ListActiveOnTop *bool   `json:"list_active_on_top,omitempty"`
	ListPaneWidth   *int    `json:"list_pane_width,omitempty"`
	// NotifyAutoChanges is GUI-only: no helper side effect to apply.
	NotifyAutoChanges *bool `json:"notify_auto_changes,omitempty"`
}

func (p SettingsPatch) apply(s *storage.Settings) {
	assignSetting(&s.Language, p.Language)
	assignSetting(&s.Theme, p.Theme)
	assignSetting(&s.TrayIconStyle, p.TrayIconStyle)
	assignSetting(&s.AutoStart, p.AutoStart)
	assignSetting(&s.KillSwitch, p.KillSwitch)
	assignSetting(&s.DNSProtection, p.DNSProtection)
	assignSetting(&s.HealthCheck, p.HealthCheck)
	assignSetting(&s.PinInterface, p.PinInterface)
	assignSetting(&s.LogLevel, p.LogLevel)
	assignSetting(&s.TunnelBackend, p.TunnelBackend)
	assignSetting(&s.CompactList, p.CompactList)
	assignSetting(&s.ListSort, p.ListSort)
	assignSetting(&s.ListActiveOnTop, p.ListActiveOnTop)
	assignSetting(&s.ListPaneWidth, p.ListPaneWidth)
	assignSetting(&s.NotifyAutoChanges, p.NotifyAutoChanges)
	if p.AutoUpdateCheck != nil {
		value := *p.AutoUpdateCheck
		s.AutoUpdateCheck = &value
	}
}

func assignSetting[T any](target *T, value *T) {
	if value != nil {
		*target = *value
	}
}

// UpdateSettings persists intent under the process lock, then applies only
// requested side effects. Apply failures are explicit; stored intent remains
// available for retry/recovery, matching the helper's wanted/applied model.
func (s *TunnelService) UpdateSettings(p SettingsPatch) error {
	// Reject an unsupported data plane before persisting it. Storing "kernel"
	// on a platform that cannot use it would leave the UI showing a backend
	// the helper silently replaces with userspace on the next connect.
	if p.TunnelBackend != nil {
		kind := tunnel.ParseBackendKind(*p.TunnelBackend)
		if !kind.Supported() {
			return fmt.Errorf("tunnel backend %q is not supported on this platform", *p.TunnelBackend)
		}
		normalized := kind.String()
		p.TunnelBackend = &normalized
	}
	var previous, current storage.Settings
	if err := s.settingsStore.Update(func(settings *storage.Settings) error {
		previous = *settings
		p.apply(settings)
		current = *settings
		return nil
	}); err != nil {
		return err
	}
	notifyGUIPreferencesChanged()
	var failures []error
	apply := func(name string, action func() error) {
		if err := action(); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
		}
	}
	if p.AutoStart != nil {
		apply("autostart", func() error {
			if !current.AutoStart {
				err := autostart.RemoveAutostart()
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			return autostart.InstallAutostart(exe)
		})
	}
	if p.KillSwitch != nil {
		apply("kill switch", func() error { return s.SetKillSwitch(current.KillSwitch) })
	}
	if p.DNSProtection != nil {
		apply("DNS protection", func() error { return s.SetDNSProtection(current.DNSProtection) })
	}
	if p.HealthCheck != nil {
		apply("health check", func() error { return s.SetHealthCheck(current.HealthCheck) })
	}
	if p.PinInterface != nil {
		apply("interface pinning", func() error { return s.SetPinInterface(current.PinInterface) })
	}
	if p.LogLevel != nil {
		apply("log level", func() error { return s.SetLogLevel(current.LogLevel) })
	}
	if p.TunnelBackend != nil {
		apply("tunnel backend", func() error { return s.SetTunnelBackend(current.TunnelBackend) })
	}
	if p.AutoUpdateCheck != nil && !previous.AutoUpdateCheckEnabled() && current.AutoUpdateCheckEnabled() && s.updateScheduler != nil {
		s.updateScheduler.Kick(true)
	}
	if err := errors.Join(failures...); err != nil {
		return fmt.Errorf("settings saved; live apply failed: %w", err)
	}
	return nil
}
