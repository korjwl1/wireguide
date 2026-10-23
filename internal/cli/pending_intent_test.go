package cli

import (
	"github.com/korjwl1/wireguide/internal/ipc"
	"testing"
)

func TestPendingIntentCountsAsWorkButNotAsGUI(t *testing.T) {
	p := ipc.PingResponse{Version: "1.3", WantedTunnels: []string{"work"}}
	if appRunning(p) {
		t.Fatal("headless recovery must not stop ctl start from opening the GUI")
	}
	if !helperWorking(p) || quitComplete(p, 0) {
		t.Fatal("pending restore is invisible to stop/status/disconnect")
	}
	p.WantedTunnels = nil
	if helperWorking(p) || !quitComplete(p, 0) {
		t.Fatal("idle activated helper must still be treated as idle")
	}
}
