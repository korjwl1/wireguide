package helper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
)

func TestScriptFingerprint_Empty(t *testing.T) {
	cfg := &domain.WireGuardConfig{Name: "test"}
	fp := ScriptFingerprint(cfg)
	if fp != "" {
		t.Errorf("expected empty fingerprint for config with no scripts, got %q", fp)
	}
}

func TestScriptFingerprint_Deterministic(t *testing.T) {
	cfg := &domain.WireGuardConfig{
		Name: "vpn",
		Interface: domain.InterfaceConfig{
			PreUp:    "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
			PostDown: "iptables -D INPUT -p tcp --dport 22 -j ACCEPT",
		},
	}
	fp1 := ScriptFingerprint(cfg)
	fp2 := ScriptFingerprint(cfg)
	if fp1 != fp2 {
		t.Errorf("fingerprint not deterministic: %q != %q", fp1, fp2)
	}
	if fp1 == "" {
		t.Error("expected non-empty fingerprint")
	}
}

func TestScriptFingerprint_DifferentName(t *testing.T) {
	base := domain.InterfaceConfig{
		PostUp: "echo hello",
	}
	cfg1 := &domain.WireGuardConfig{Name: "tunnel-a", Interface: base}
	cfg2 := &domain.WireGuardConfig{Name: "tunnel-b", Interface: base}

	fp1 := ScriptFingerprint(cfg1)
	fp2 := ScriptFingerprint(cfg2)
	if fp1 == fp2 {
		t.Error("fingerprints should differ when tunnel name differs")
	}
}

func TestScriptFingerprint_DifferentCommand(t *testing.T) {
	cfg1 := &domain.WireGuardConfig{
		Name:      "vpn",
		Interface: domain.InterfaceConfig{PostUp: "echo safe"},
	}
	cfg2 := &domain.WireGuardConfig{
		Name:      "vpn",
		Interface: domain.InterfaceConfig{PostUp: "rm -rf /"},
	}
	if ScriptFingerprint(cfg1) == ScriptFingerprint(cfg2) {
		t.Error("fingerprints should differ when commands differ")
	}
}

func TestAllowlist_ApproveAndCheck(t *testing.T) {
	dir := t.TempDir()
	al := NewScriptAllowlist(dir)

	cfg := &domain.WireGuardConfig{
		Name:      "test",
		Interface: domain.InterfaceConfig{PostUp: "echo up"},
	}

	if al.IsApproved(cfg) {
		t.Error("should not be approved before Approve()")
	}

	if err := al.Approve(cfg); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	if !al.IsApproved(cfg) {
		t.Error("should be approved after Approve()")
	}

	// Verify persistence: create a new allowlist from the same dir.
	al2 := NewScriptAllowlist(dir)
	if !al2.IsApproved(cfg) {
		t.Error("approval should persist across reload")
	}
}

func TestAllowlist_Revoke(t *testing.T) {
	dir := t.TempDir()
	al := NewScriptAllowlist(dir)

	cfg := &domain.WireGuardConfig{
		Name:      "test",
		Interface: domain.InterfaceConfig{PreUp: "echo pre"},
	}

	_ = al.Approve(cfg)
	if !al.IsApproved(cfg) {
		t.Fatal("should be approved")
	}

	if err := al.Revoke(cfg); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if al.IsApproved(cfg) {
		t.Error("should not be approved after Revoke()")
	}
}

func TestAllowlist_NoScriptsAutoApproved(t *testing.T) {
	dir := t.TempDir()
	al := NewScriptAllowlist(dir)

	cfg := &domain.WireGuardConfig{Name: "plain"}
	if !al.IsApproved(cfg) {
		t.Error("config with no scripts should always be approved")
	}
}

func TestAllowlist_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	// Write garbage to the allowlist file.
	if err := os.WriteFile(filepath.Join(dir, allowlistFile), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}

	al := NewScriptAllowlist(dir)
	// Should start with empty allowlist, not panic.
	cfg := &domain.WireGuardConfig{
		Name:      "test",
		Interface: domain.InterfaceConfig{PostUp: "echo x"},
	}
	if al.IsApproved(cfg) {
		t.Error("corrupt file should result in empty allowlist")
	}
}

func TestAllowlist_ModifiedScript(t *testing.T) {
	dir := t.TempDir()
	al := NewScriptAllowlist(dir)

	cfg := &domain.WireGuardConfig{
		Name:      "vpn",
		Interface: domain.InterfaceConfig{PostUp: "echo safe"},
	}
	_ = al.Approve(cfg)

	// Modify the script — should NOT be approved.
	modified := &domain.WireGuardConfig{
		Name:      "vpn",
		Interface: domain.InterfaceConfig{PostUp: "echo safe; rm -rf /"},
	}
	if al.IsApproved(modified) {
		t.Error("modified script should not be approved")
	}
}
