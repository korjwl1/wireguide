package tunnel

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSaveActiveStateReplacesSnapshot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not allow replacing a file opened without delete sharing")
	}
	dir := t.TempDir()
	before := &ActiveTunnelState{TunnelName: "vpn", InterfaceName: "utun1"}
	if err := SaveActiveState(dir, before); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, tunnelStatesDir, stateFileName("vpn"))
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveActiveState(dir, &ActiveTunnelState{TunnelName: "vpn", InterfaceName: "utun2"}); err != nil {
		t.Fatal(err)
	}
	oldSnapshot, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(oldSnapshot) != string(original) {
		t.Fatal("save changed the existing inode; a concurrent reader or crash can observe a torn journal")
	}
	states := LoadActiveState(dir)
	if len(states) != 1 || states[0].InterfaceName != "utun2" {
		t.Fatalf("new snapshot not published: %+v", states)
	}
}
