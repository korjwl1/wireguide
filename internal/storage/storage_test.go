package storage

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/korjwl1/wireguide/internal/config"
)

func testConfig() *config.WireGuardConfig {
	return &config.WireGuardConfig{
		Name: "test-vpn",
		Interface: config.InterfaceConfig{
			PrivateKey: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
			Address:    []string{"10.0.0.2/24"},
			DNS:        []string{"1.1.1.1"},
		},
		Peers: []config.PeerConfig{
			{
				PublicKey:   "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
				Endpoint:   "vpn.example.com:51820",
				AllowedIPs: []string{"0.0.0.0/0"},
			},
		},
	}
}

// --- TunnelStore tests ---

func TestTunnelStoreSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	store := NewTunnelStore(dir)
	cfg := testConfig()

	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := store.Load("test-vpn")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Interface.PrivateKey != cfg.Interface.PrivateKey {
		t.Error("PrivateKey mismatch")
	}
	if loaded.Name != "test-vpn" {
		t.Errorf("Name mismatch: %s", loaded.Name)
	}
	if len(loaded.Peers) != 1 {
		t.Errorf("expected 1 peer, got %d", len(loaded.Peers))
	}
}

func TestTunnelStoreFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permissions not applicable on Windows")
	}
	dir := t.TempDir()
	store := NewTunnelStore(dir)

	if err := store.Save(testConfig()); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "test-vpn.conf"))
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected 0600 permissions, got %o", perm)
	}
}

func TestTunnelStoreDelete(t *testing.T) {
	dir := t.TempDir()
	store := NewTunnelStore(dir)

	store.Save(testConfig())
	if !store.Exists("test-vpn") {
		t.Fatal("tunnel should exist after save")
	}

	if err := store.Delete("test-vpn"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if store.Exists("test-vpn") {
		t.Error("tunnel should not exist after delete")
	}
}

func TestTunnelStoreList(t *testing.T) {
	dir := t.TempDir()
	store := NewTunnelStore(dir)

	// Empty list
	names, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("expected 0 tunnels, got %d", len(names))
	}

	// Add two tunnels
	cfg1 := testConfig()
	cfg1.Name = "vpn-office"
	store.Save(cfg1)

	cfg2 := testConfig()
	cfg2.Name = "vpn-home"
	store.Save(cfg2)

	names, err = store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("expected 2 tunnels, got %d", len(names))
	}
}

func TestTunnelStoreListNonExistentDir(t *testing.T) {
	store := NewTunnelStore("/nonexistent/path")
	names, err := store.List()
	if err != nil {
		t.Fatalf("List should not error for nonexistent dir: %v", err)
	}
	if names != nil {
		t.Errorf("expected nil, got %v", names)
	}
}

func TestTunnelStoreExists(t *testing.T) {
	dir := t.TempDir()
	store := NewTunnelStore(dir)

	if store.Exists("nonexistent") {
		t.Error("should not exist")
	}

	store.Save(testConfig())
	if !store.Exists("test-vpn") {
		t.Error("should exist after save")
	}
}

func TestTunnelStoreSaveEmptyName(t *testing.T) {
	dir := t.TempDir()
	store := NewTunnelStore(dir)

	cfg := testConfig()
	cfg.Name = ""
	err := store.Save(cfg)
	if err == nil {
		t.Error("expected error for empty name")
	}
}

func TestTunnelStoreImportFromContent(t *testing.T) {
	dir := t.TempDir()
	store := NewTunnelStore(dir)

	content := `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0
`
	cfg, err := store.ImportFromContent("imported-vpn", content)
	if err != nil {
		t.Fatalf("ImportFromContent failed: %v", err)
	}
	if cfg.Name != "imported-vpn" {
		t.Errorf("name mismatch: %s", cfg.Name)
	}
	if !store.Exists("imported-vpn") {
		t.Error("imported tunnel should exist on disk")
	}
}

func TestTunnelStoreImportInvalidContent(t *testing.T) {
	dir := t.TempDir()
	store := NewTunnelStore(dir)

	_, err := store.ImportFromContent("bad", "[Interface]\nAddress = 10.0.0.2/24\n")
	if err == nil {
		t.Error("expected validation error for missing PrivateKey")
	}
}

// --- SettingsStore tests ---

func TestSettingsStoreDefaultsOnMissing(t *testing.T) {
	dir := t.TempDir()
	store := NewSettingsStore(dir)

	settings, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if settings.Language != "auto" {
		t.Errorf("expected default language 'auto', got %s", settings.Language)
	}
	if settings.Theme != "dark" {
		t.Errorf("expected default theme 'dark', got %s", settings.Theme)
	}
	if !settings.AutoReconnect {
		t.Error("expected AutoReconnect to be true by default")
	}
}

func TestSettingsStoreSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	store := NewSettingsStore(dir)

	settings := DefaultSettings()
	settings.Language = "ko"
	settings.Theme = "light"

	if err := store.Save(settings); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.Language != "ko" {
		t.Errorf("language mismatch: %s", loaded.Language)
	}
	if loaded.Theme != "light" {
		t.Errorf("theme mismatch: %s", loaded.Theme)
	}
}

// --- Paths tests ---

func TestGetPaths(t *testing.T) {
	paths, err := GetPaths()
	if err != nil {
		t.Fatalf("GetPaths failed: %v", err)
	}
	if paths.ConfigDir == "" {
		t.Error("ConfigDir should not be empty")
	}
	if paths.TunnelsDir == "" {
		t.Error("TunnelsDir should not be empty")
	}
	if paths.LogsDir == "" {
		t.Error("LogsDir should not be empty")
	}
}

func TestEnsureDirs(t *testing.T) {
	dir := t.TempDir()
	paths := &Paths{
		ConfigDir:  filepath.Join(dir, "config"),
		TunnelsDir: filepath.Join(dir, "tunnels"),
		LogsDir:    filepath.Join(dir, "logs"),
	}
	if err := paths.EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs failed: %v", err)
	}
	for _, d := range []string{paths.ConfigDir, paths.TunnelsDir, paths.LogsDir} {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			t.Errorf("directory should exist: %s", d)
		}
	}
}
