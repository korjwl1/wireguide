package app

import (
	"testing"

	"github.com/korjwl1/wireguide/internal/storage"
)

func TestClosedHistoryIgnoresLateStatus(t *testing.T) {
	h := storage.NewHistoryStore(t.TempDir())
	defer h.Flush()
	s := &TunnelService{historyStore: h}
	s.CloseHistorySessions("app_quit")
	s.ReconcileHistoryFromStatus([]string{"late-status"}, nil, nil, "")
	if rows := h.GetAll(); len(rows) != 0 {
		t.Fatalf("status received during shutdown reopened history: %+v", rows)
	}
}
