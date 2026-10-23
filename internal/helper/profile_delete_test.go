package helper

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
)

func TestDeleteWithdrawsCachedRecoveryAndPreservesSibling(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h := newPendingTestHelper(t, "alpha", "beta")
	cfg, err := h.userTunnelStore.Load("alpha")
	if err != nil {
		t.Fatal(err)
	}
	h.activeCfgs["alpha"] = cfg // down in reconnect backoff
	h.pendingDesired["beta"] = struct{}{}
	h.autoConnectedBy = map[string]string{"alpha": "old-rule"}
	h.persistDesiredState()
	params, _ := json.Marshal(ipc.DeleteRequest{TunnelName: "alpha"})
	if _, err := h.handleDelete(params); err != nil {
		t.Fatal(err)
	}
	if h.userTunnelStore.Exists("alpha") || !h.userTunnelStore.Exists("beta") {
		t.Fatal("deletion affected the wrong stored profile")
	}
	if _, ok := h.activeCfgs["alpha"]; ok {
		t.Fatal("deleted profile remained wanted by reconnect")
	}
	if _, ok := h.autoConnectedBy["alpha"]; ok {
		t.Fatal("deleted profile retained automatic ownership")
	}
	assertDesiredState(t, h, "beta")
}

func TestDeleteWaitsForConnectionTransition(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h := newPendingTestHelper(t, "alpha")
	h.connectMu.Lock()
	params, _ := json.Marshal(ipc.DeleteRequest{TunnelName: "alpha"})
	done := make(chan error, 1)
	go func() { _, err := h.handleDelete(params); done <- err }()
	select {
	case err := <-done:
		h.connectMu.Unlock()
		t.Fatalf("delete bypassed an active connection transition: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if !h.userTunnelStore.Exists("alpha") {
		t.Error("profile removed while connection transition held the lock")
	}
	h.connectMu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("delete did not finish after the connection transition")
	}
}
