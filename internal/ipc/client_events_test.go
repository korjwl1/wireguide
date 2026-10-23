package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

func eventTestClient(t *testing.T) (*Client, *Server) {
	t.Helper()
	addr := testSocketPath(t)
	l, err := Listen(addr, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(l)
	registerTestPing(s)
	go s.Serve()
	t.Cleanup(func() { s.Shutdown() })
	c, err := NewClient(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, s
}

func waitForEventCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("event stream did not reach expected state")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSubscribeAfterCloseDoesNotOpenConnection(t *testing.T) {
	c, s := eventTestClient(t)
	c.Close()
	if err := c.Subscribe(nil); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("Subscribe after Close = %v", err)
	}
	if s.HasSubscribers() {
		t.Fatal("closed client acquired an event connection")
	}
}

func TestSubscribeReplacementClosesPreviousStream(t *testing.T) {
	c, s := eventTestClient(t)
	if err := c.Subscribe(nil); err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 1)
	if err := c.Subscribe(func(method string, _ json.RawMessage) { received <- method }); err != nil {
		t.Fatal(err)
	}
	waitForEventCondition(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.eventSubs) == 1
	})
	s.Broadcast("replacement", Empty{})
	select {
	case method := <-received:
		if method != "replacement" {
			t.Fatalf("unexpected event %q", method)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement stream did not receive events")
	}
}

func TestEventOnlyDisconnectCanResubscribe(t *testing.T) {
	c, s := eventTestClient(t)
	if err := c.Subscribe(nil); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	for sub := range s.eventSubs {
		sub.conn.Close()
	}
	s.mu.Unlock()
	waitForEventCondition(t, func() bool { return !c.HasSubscription() })
	if err := c.Call(MethodPing, nil, nil); err != nil {
		t.Fatalf("event failure broke control RPC: %v", err)
	}
	if err := c.Subscribe(nil); err != nil {
		t.Fatal(err)
	}
	if !c.HasSubscription() {
		t.Fatal("event stream was not restored")
	}
}

func TestSubscribeSetupCancellationAndClose(t *testing.T) {
	for _, closeClient := range []bool{false, true} {
		t.Run(map[bool]string{false: "context", true: "client"}[closeClient], func(t *testing.T) {
			addr := testSocketPath(t)
			l, err := Listen(addr, -1, "")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			accepted := make(chan net.Conn, 1)
			requestRead := make(chan struct{})
			go func() {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				accepted <- conn
				var req Request
				_ = ReadFrame(conn, &req)
				close(requestRead) // deliberately never acknowledge
			}()
			c := &Client{addr: addr, subscribeGate: make(chan struct{}, 1), closed: make(chan struct{})}
			defer c.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- c.SubscribeContext(ctx, nil) }()
			conn := <-accepted
			defer conn.Close()
			<-requestRead
			want := error(context.Canceled)
			if closeClient {
				c.Close()
				want = ErrClientClosed
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatalf("Subscribe = %v, want %v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("subscription acknowledgement blocked cancellation")
			}
			if c.HasSubscription() {
				t.Fatal("failed setup retained an event stream")
			}
		})
	}
}
