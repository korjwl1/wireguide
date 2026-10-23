package helper

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/reconnect"
)

func TestAutomaticOwnershipSurvivesCrashAndGuardsPendingRestore(t *testing.T) {
	stubNetwork(t, wifiProbe())
	localOverlapProbe = func([]string) (string, net.IP, bool) {
		return "10.0.0.0/24", net.ParseIP("10.0.0.50"), true
	}
	h := newPendingTestHelper(t, "automatic", "manual")
	if err := saveDesiredIntent(h.dataDir, desiredStateJSON{
		Tunnels: []string{"automatic", "manual"}, Automatic: []string{"automatic"},
	}); err != nil {
		t.Fatal(err)
	}
	restoreBootTimeStub(t, func() (time.Time, error) { return time.Now().Add(-time.Hour), nil })
	stubRestoreConnect(t)
	h.restoreDesiredTunnels()
	if h.activeCfgs["automatic"] != nil || h.activeCfgs["manual"] == nil {
		t.Fatal("restore must defer only automatic intent on an overlapping LAN")
	}
	if _, pending := h.pendingDesired["automatic"]; !pending {
		t.Fatal("deferred intent was lost instead of retained for a later network")
	}
	if !slices.Equal(loadDesiredIntent(h.dataDir).Automatic, []string{"automatic"}) {
		t.Fatal("pending ownership was not persisted")
	}
	cfg, err := h.userTunnelStore.Load("automatic")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.connectPendingDesired(context.Background(), cfg); !errors.Is(err, reconnect.ErrNothingToReconnect) {
		t.Fatalf("pending retry ignored the overlap: %v", err)
	}
	localOverlapProbe = func([]string) (string, net.IP, bool) { return "", nil, false }
	if err := h.connectPendingDesired(context.Background(), cfg); err != nil || h.activeCfgs["automatic"] == nil {
		t.Fatalf("network change failed to resume automatic intent: %v", err)
	}
}

func TestDesiredOwnershipIgnoresOrphansAndIsRemovedWithIntent(t *testing.T) {
	h := newPendingTestHelper(t)
	h.pendingDesired["automatic"] = struct{}{}
	h.autoConnectedBy = map[string]string{"automatic": "", "orphan": ""}
	h.persistDesiredState()
	if !slices.Equal(loadDesiredIntent(h.dataDir).Automatic, []string{"automatic"}) {
		t.Fatal("orphan ownership entered the restore journal")
	}
	h.withdrawPendingDesired("automatic")
	if len(h.autoConnectedBy) != 1 || len(loadDesiredIntent(h.dataDir).Automatic) != 0 {
		t.Fatal("withdrawn automatic ownership survived")
	}
}

func TestAutomationOverlapNotificationIsDeduplicatedUntilCleared(t *testing.T) {
	h := newPendingTestHelper(t)
	logs := captureLogs(t)
	h.reportAutomationOverlap("work", "10.0.0.0/24", net.ParseIP("10.0.0.5"))
	first := len(logs.String())
	if first == 0 {
		t.Fatal("first skipped connection had no explanation")
	}
	h.reportAutomationOverlap("work", "10.0.0.0/24", net.ParseIP("10.0.0.5"))
	if len(logs.String()) != first {
		t.Fatal("unchanged retry repeated the notification")
	}
	h.clearAutomationSkip("work")
	h.reportAutomationOverlap("work", "10.0.0.0/24", net.ParseIP("10.0.0.5"))
	if len(logs.String()) <= first {
		t.Fatal("a new overlap occurrence was not reported")
	}
}
