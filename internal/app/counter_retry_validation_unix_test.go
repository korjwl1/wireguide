//go:build !windows

package app

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
)

func swapService(t *testing.T, live ConnectionStatus, newStatus ConnectionStatus, retryErr error) (*TunnelService, *TunnelService) {
	replacement := epochRPCServiceWithStatus(t, func() ConnectionStatus { return newStatus }, func(json.RawMessage) (interface{}, error) { return nil, retryErr })
	var s *TunnelService
	s = epochRPCServiceWithStatus(t, func() ConnectionStatus { return live }, func(json.RawMessage) (interface{}, error) {
		go s.clients.Set(replacement.clients.Get())
		for s.clients.Get() != replacement.clients.Get() {
			time.Sleep(time.Millisecond)
		}
		return ipc.Empty{}, nil
	})
	return s, replacement
}

func TestClaudeNoSuppressNotConnectedButStillActive(t *testing.T) {
	e1 := domain.NewCounterEpoch()
	live := ConnectionStatus{TunnelName: "a", CounterEpoch: e1, RxBytes: 10, ActiveTunnels: []string{"a"}}
	s, _ := swapService(t, live, live, &ipc.CodedError{Code: ipc.ErrCodeNotConnected, Message: `tunnel "a" is not connected`})
	ObserveHistoryStatus(s, live, s.clients.Get())
	if err := s.DisconnectTunnel("a"); err == nil {
		t.Fatal("NotConnected suppressed while fresh status still lists the tunnel")
	}
}

func TestClaudeNoSuppressGenericAppError(t *testing.T) {
	e1 := domain.NewCounterEpoch()
	live := ConnectionStatus{TunnelName: "a", CounterEpoch: e1, RxBytes: 10, ActiveTunnels: []string{"a"}}
	for _, e := range []error{errors.New(`tunnel "a" is not connected: boom`), errors.New(`tunnel "b" is not connected`), &ipc.CodedError{Code: ipc.ErrCodeInternalError, Message: `tunnel "a" is not connected`}} {
		s, _ := swapService(t, live, ConnectionStatus{}, e)
		ObserveHistoryStatus(s, live, s.clients.Get())
		if err := s.DisconnectTunnel("a"); err == nil {
			t.Fatalf("non-canonical error %q suppressed", e)
		}
	}
}

func TestClaudeCanonicalOldHelperAcceptedKeepsUser(t *testing.T) {
	e1 := domain.NewCounterEpoch()
	live := ConnectionStatus{TunnelName: "a", CounterEpoch: e1, RxBytes: 10, ActiveTunnels: []string{"a"}}
	s, rep := swapService(t, live, ConnectionStatus{}, errors.New(`tunnel "a" is not connected`))
	ObserveHistoryStatus(s, live, s.clients.Get())
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}
	ObserveHistoryStatus(s, ConnectionStatus{}, rep.clients.Get())
	if got := lastSession(t, s); got.DisconnectReason != "user" || got.EndTime == nil {
		t.Fatalf("%+v", got)
	}
}
