package gui

import (
	"context"
	"log/slog"
	"sync"
	"time"

	wgapp "github.com/korjwl1/wireguide/internal/app"
	"github.com/korjwl1/wireguide/internal/guiinstance"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

// guiShutdown owns the shared native-quit, tray-quit and startup-error teardown.
type guiShutdown struct {
	once       sync.Once
	instance   *guiinstance.Instance
	indicator  *connectionIcon
	stopHealth func()
	service    *wgapp.TunnelService
	history    *storage.HistoryStore
	clients    *ipc.ClientHolder
}

func (s *guiShutdown) run() {
	s.once.Do(func() {
		s.instance.BeginShutdown()
		appQuitting.Store(true)
		if s.indicator != nil {
			s.indicator.Close()
		}
		s.stopHealth()
		slog.Info("shutting down GUI + helper")
		// Close any in-flight history sessions BEFORE the helper goes
		// away — snapshotActiveStats needs the helper alive to fetch
		// last-known rx/tx counters.
		s.service.CloseHistorySessions("app_quit")
		// Flush any deferred history writes synchronously. The
		// debounced writer would otherwise lose the last 100ms of
		// records when the GUI process exits.
		s.history.Flush()
		c := s.clients.Get()
		if c != nil {
			// Bounded timeouts so a hung helper can't keep the GUI
			// alive forever — user clicked Quit, they expect the app
			// to die. 2s is generous for a local Unix-socket RPC that
			// just kicks off async teardown.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if err := c.CallWithContext(ctx, ipc.MethodDisconnect, nil, nil); err != nil {
				slog.Warn("shutdown: Disconnect RPC failed", "error", err)
			}
			cancel()
			ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
			if err := c.CallWithContext(ctx, ipc.MethodShutdown, nil, nil); err != nil {
				slog.Warn("shutdown: Shutdown RPC failed", "error", err)
			}
			cancel()
		}
		// Close in a goroutine with a short delay so the helper has
		// time to process the shutdown command without blocking the
		// macOS main thread (AppKit requires the main thread to stay
		// responsive during termination).
		go func() {
			time.Sleep(50 * time.Millisecond)
			s.clients.Close()
		}()
	})
}
