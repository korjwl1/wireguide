package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
)

func TestDisconnectTimeoutStillCancelsSlowConnect(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	mgr := newTestManagerWithDir(&mockNetworkManager{}, func(*domain.WireGuardConfig) (*Engine, error) {
		close(entered)
		<-release // model a native call that cannot be interrupted
		return fakeEngine("utun42"), nil
	}, t.TempDir())
	connected := make(chan error, 1)
	go func() { connected <- mgr.Connect(testConfig("slow")) }()
	<-entered
	// Use the actual public shutdown deadline; the timeout must retain Off.
	mgr.DisconnectAll()
	close(release)
	select {
	case err := <-connected:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("slow Connect committed after shutdown timeout: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled connect did not roll back after native call returned")
	}
	if mgr.IsConnected() || len(mgr.ActiveTunnels()) != 0 {
		t.Fatal("shutdown left a late connected tunnel")
	}
}
