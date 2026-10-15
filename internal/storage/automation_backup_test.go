package storage

import (
	"encoding/json"
	"github.com/korjwl1/wireguide/internal/automation"
	"os"
	"path/filepath"
	"testing"
)

func TestDowngradeCannotEraseNegatedRuleBackup(t *testing.T) {
	store := NewSettingsStore(t.TempDir())
	s := DefaultSettings()
	s.Automation = &automation.Automation{PerTunnel: map[string][]automation.Rule{"work": {{When: automation.Condition{Type: automation.CondSSID, SSID: "Home", Negate: true}, Do: automation.ActionConnect}}}}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	// Simulate an old binary rewriting only the legacy settings representation.
	if err := os.WriteFile(store.path, []byte(`{"automation":{"per_tunnel_rules":{}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(store.path + ".automation-v2-backup")
	if err != nil {
		t.Fatal(err)
	}
	var backup automation.Automation
	if err := json.Unmarshal(data, &backup); err != nil {
		t.Fatal(err)
	}
	if !automation.HasNegated(backup.PerTunnel["work"]) {
		t.Fatal("old rewrite lost recovery copy")
	}
	active, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(active.Automation.PerTunnel) != 0 {
		t.Fatal("backup rules unexpectedly executed after downgrade")
	}
	if err := store.Save(active); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.path + ".automation-v2-backup"); err != nil {
		t.Fatal("unrelated save after downgrade erased backup")
	}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(active); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.path + ".automation-v2-backup"); !os.IsNotExist(err) {
		t.Fatal("explicit current-version rule removal retained stale backup")
	}
}

func TestUnrelatedSettingsSaveDoesNotRequireWritableAutomationBackup(t *testing.T) {
	store := NewSettingsStore(t.TempDir())
	s := DefaultSettings()
	s.Automation = &automation.Automation{PerTunnel: map[string][]automation.Rule{"work": {{When: automation.Condition{Type: automation.CondSSID, SSID: "Home", Negate: true}, Do: automation.ActionConnect}}}}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	backupPath := store.path + automationBackupSuffix
	if err := os.Remove(backupPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(backupPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(s *Settings) error { s.Theme = "dark"; return nil }); err != nil {
		t.Fatalf("unrelated settings blocked by backup failure: %v", err)
	}
	active, err := store.Load()
	if err != nil || active.Theme != "dark" || !automation.HasNegated(active.Automation.PerTunnel["work"]) {
		t.Fatal("unrelated save changed existing automation")
	}
	if status := store.AutomationBackupStatus(); status.Error == "" {
		t.Fatal("backup failure was not visible to the UI")
	}
	active.Automation.PerTunnel["work"] = nil
	if err := store.Save(active); err == nil {
		t.Fatal("automation edit ignored its failed backup transition")
	}
}

func TestReupgradePreservesEarlierRulesBeforeWritingNewBackup(t *testing.T) {
	store := NewSettingsStore(t.TempDir())
	s := DefaultSettings()
	s.Automation = &automation.Automation{PerTunnel: map[string][]automation.Rule{"work": {{When: automation.Condition{Type: automation.CondSSID, SSID: "Home", Negate: true}, Do: automation.ActionConnect}}}}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(store.path + automationBackupSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.path, []byte(`{"automation":{"per_tunnel_rules":{}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	s.Automation.PerTunnel["work"][0].When.SSID = "New network"
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	archives, err := filepath.Glob(store.path + automationBackupSuffix + ".recovery-*")
	if err != nil || len(archives) != 1 {
		t.Fatalf("recovery copies=%v err=%v", archives, err)
	}
	preserved, err := os.ReadFile(archives[0])
	if err != nil || string(preserved) != string(original) {
		t.Fatal("reupgrade erased earlier negated rules")
	}
	status := store.AutomationBackupStatus()
	if !status.Available || status.Different || status.RecoveryCopies != 1 || status.Error != "" {
		t.Fatalf("backup status=%+v", status)
	}
	active, err := store.Load()
	if err != nil || active.Automation.PerTunnel["work"][0].When.SSID != "New network" {
		t.Fatal("recovery rules were executed instead of the newly saved rules")
	}
}
