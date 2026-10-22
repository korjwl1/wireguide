package app

import (
	"testing"

	"github.com/korjwl1/wireguide/internal/automation"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

func TestSettingsPatchPreservesConcurrentChangesAndDeletedRules(t *testing.T) {
	store := storage.NewSettingsStore(t.TempDir())
	settings := storage.DefaultSettings()
	settings.Automation = &automation.Automation{PerTunnel: map[string][]automation.Rule{"removed": {{When: automation.Condition{Type: automation.CondNoneMatch}, Do: automation.ActionConnect}}}}
	if err := store.Save(settings); err != nil {
		t.Fatal(err)
	}
	s := &TunnelService{settingsStore: store}
	if err := store.Update(func(current *storage.Settings) error {
		current.DeleteTunnelRules("removed")
		current.KillSwitch = true // a concurrent CLI edit
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	theme := "dark"
	if err := s.UpdateSettings(SettingsPatch{Theme: &theme}); err != nil {
		t.Fatal(err)
	}
	current, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if current.Theme != "dark" || !current.KillSwitch || len(current.Automation.PerTunnel) != 0 {
		t.Fatalf("view patch overwrote external settings: %+v", current)
	}
}

func TestSettingsPatchReportsUnconfirmedLiveApplyAndKeepsIntent(t *testing.T) {
	store := storage.NewSettingsStore(t.TempDir())
	s := &TunnelService{settingsStore: store}
	wanted := true
	if err := s.UpdateSettings(SettingsPatch{KillSwitch: &wanted}); err == nil {
		t.Fatal("unavailable helper was reported as applied protection")
	}
	settings, err := store.Load()
	if err != nil || !settings.KillSwitch {
		t.Fatalf("failed apply lost wanted intent: %+v, %v", settings, err)
	}
}

func TestSettingsPatchRejectsUnsupportedTunnelBackend(t *testing.T) {
	if tunnel.BackendKernel.Supported() {
		t.Skip("kernel backend is available on this platform")
	}
	store := storage.NewSettingsStore(t.TempDir())
	s := &TunnelService{settingsStore: store}
	backend := "kernel"
	if err := s.UpdateSettings(SettingsPatch{TunnelBackend: &backend}); err == nil {
		t.Fatal("unsupported kernel backend was accepted")
	}
	settings, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if settings.TunnelBackend == "kernel" {
		t.Fatal("unsupported backend was persisted")
	}
}
