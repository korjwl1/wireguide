package storage

import (
	"encoding/json"
	"github.com/korjwl1/wireguide/internal/wifi"
	"os"
	"testing"
)

func TestDowngradeCannotEraseNegatedRuleBackup(t *testing.T) {
	store := NewSettingsStore(t.TempDir())
	s := DefaultSettings()
	s.Automation = &wifi.Automation{PerTunnel: map[string][]wifi.Rule{"work": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "Home", Negate: true}, Do: wifi.ActionConnect}}}}
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
	var backup wifi.Automation
	if err := json.Unmarshal(data, &backup); err != nil {
		t.Fatal(err)
	}
	if !wifi.HasNegated(backup.PerTunnel["work"]) {
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
