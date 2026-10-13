package ipc

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type observedWriteConn struct {
	net.Conn
	once    sync.Once
	started chan struct{}
}

func (c *observedWriteConn) Write(data []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(data)
}

func stalledWriteClient(t *testing.T) (*Client, <-chan struct{}) {
	t.Helper()
	local, remote := net.Pipe()
	t.Cleanup(func() { _ = remote.Close() })
	conn := &observedWriteConn{Conn: local, started: make(chan struct{})}
	c := &Client{controlConn: conn, controlGate: make(chan struct{}, 1), pending: make(map[uint64]chan *Response), closed: make(chan struct{})}
	t.Cleanup(func() { _ = c.Close() })
	return c, conn.started
}

func TestCallContextBoundsStalledRequestWrite(t *testing.T) {
	c, _ := stalledWriteClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.CallWithContext(ctx, MethodPing, nil, nil) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("write timeout = %v", err)
		}
	case <-time.After(time.Second):
		_ = c.Close()
		<-done
		t.Fatal("RPC deadline did not interrupt a blocked socket write")
	}
}

func TestCallContextBoundsWaitingForAnotherWriter(t *testing.T) {
	c, started := stalledWriteClient(t)
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	first := make(chan error, 1)
	go func() { first <- c.CallWithContext(firstCtx, MethodPing, nil, nil) }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	second := make(chan error, 1)
	go func() { second <- c.CallWithContext(ctx, MethodPing, nil, nil) }()
	select {
	case err := <-second:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("queued timeout = %v", err)
		}
	case <-time.After(time.Second):
		_ = c.Close()
		<-first
		<-second
		t.Fatal("RPC deadline did not bound the write serialization wait")
	}
	cancelFirst()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("write cancellation = %v", err)
		}
	case <-time.After(time.Second):
		_ = c.Close()
		<-first
		t.Fatal("cancellation did not interrupt the socket write")
	}
}
