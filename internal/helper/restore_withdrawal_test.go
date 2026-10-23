package helper

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDisconnectDuringRestorePreflightVetoesOriginalSnapshot(t *testing.T) {
	for _, params := range []json.RawMessage{json.RawMessage(`{"tunnel_name":"alpha"}`), nil} {
		t.Run(string(params), func(t *testing.T) {
			stubNetwork(t, wifiProbe())
			h := newPendingTestHelper(t, "alpha")
			if err := saveDesiredState(h.dataDir, []string{"alpha"}); err != nil {
				t.Fatal(err)
			}
			restoreBootTimeStub(t, func() (time.Time, error) { return time.Now().Add(-time.Hour), nil })
			stubRestoreConnect(t)
			ready, proceed, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			previous := restoreRuleSaysOff
			restoreRuleSaysOff = func(*Helper, string) bool { close(ready); <-proceed; return false }
			t.Cleanup(func() { restoreRuleSaysOff = previous })
			go func() { h.restoreDesiredTunnels(); close(done) }()
			<-ready
			_, disconnectErr := h.handleDisconnect(params)
			close(proceed)
			<-done
			if disconnectErr != nil {
				t.Fatalf("wanted startup intent was not disconnectable: %v", disconnectErr)
			}
			if len(h.activeCfgs) != 0 || len(h.pendingDesired) != 0 || len(loadDesiredState(h.dataDir)) != 0 {
				t.Fatal("stale startup snapshot undid manual Off")
			}
		})
	}
}

func TestRestoreWithoutStoreRetainsWantedLifetime(t *testing.T) {
	h := newPendingTestHelper(t)
	h.userTunnelStore = nil
	if err := saveDesiredState(h.dataDir, []string{"temporarily-unavailable"}); err != nil {
		t.Fatal(err)
	}
	restoreBootTimeStub(t, func() (time.Time, error) { return time.Now().Add(-time.Hour), nil })
	h.restoreDesiredTunnels()
	if _, pending := h.pendingDesired["temporarily-unavailable"]; !pending || h.shutdownTimer != nil {
		t.Fatal("unavailable store let idle shutdown erase wanted startup intent")
	}
}
