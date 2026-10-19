package ipc

import (
	"testing"
	"time"
)

func TestHolderCannotBeReopenedAfterClose(t *testing.T) {
	h := NewClientHolder(nil)
	h.Close()
	client := newClosedTestClient()
	h.Set(client)
	if h.Get() != nil || !client.IsClosed() {
		t.Fatal("closed holder accepted a replacement")
	}
}

func TestHolderCloseInterruptsDrain(t *testing.T) {
	old := newClosedTestClient()
	next := newClosedTestClient()
	h := NewClientHolder(old)
	h.MarkInflight()
	done := make(chan struct{})
	go func() { h.Set(next); close(done) }()
	deadline := time.Now().Add(time.Second)
	for h.Get() != next && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	h.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close left Set draining for 20 seconds")
	}
	h.UnmarkInflight()
}

// A real control transport is unnecessary for the holder ownership contract.
func newClosedTestClient() *Client { return &Client{closed: make(chan struct{})} }
