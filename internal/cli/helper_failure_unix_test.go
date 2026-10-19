//go:build !windows

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

func TestCLIIncompatibleHelperDoesNotAuthorizeOfflineMutations(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "wgf-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	addr := filepath.Join(dir, "s")
	l, err := ipc.Listen(addr, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	server := ipc.NewServer(l)
	server.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
		return ipc.PingResponse{Version: "99.0"}, nil
	})
	go server.Serve()
	defer server.Shutdown()
	oldSocket, oldPaths := helperSocketPath, userPaths
	helperSocketPath = func() string { return addr }
	root := t.TempDir()
	paths := &storage.Paths{ConfigDir: root, TunnelsDir: filepath.Join(root, "tunnels"), LogsDir: filepath.Join(root, "logs")}
	userPaths = func() (*storage.Paths, error) { return paths, nil }
	defer func() { helperSocketPath, userPaths = oldSocket, oldPaths }()
	if err := paths.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	store := storage.NewTunnelStore(paths.TunnelsDir)
	cfg := &config.WireGuardConfig{Name: "alpha"}
	cfg.Interface.PrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if rc := cmdRename([]string{"alpha", "beta"}); rc != 1 {
		t.Fatalf("rename bypassed incompatible live helper: exit %d", rc)
	}
	if !store.Exists("alpha") || store.Exists("beta") {
		t.Fatal("rename changed local files after an ambiguous helper failure")
	}
	if rc := cmdSet([]string{"killswitch", "on"}); rc != 1 {
		t.Fatalf("set claimed live firewall protection: exit %d", rc)
	}
	settings, err := storage.NewSettingsStore(paths.ConfigDir).Load()
	if err != nil || !settings.KillSwitch {
		t.Fatalf("failed live apply lost persisted user intent: %+v, %v", settings, err)
	}
}
