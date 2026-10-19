package ipc

import (
	"net"
	"testing"
	"time"
)

func TestQuietSubscriberDisconnectReleasesConnection(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	s := NewServer(nil)
	defer close(s.shutdownCh)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleSubscribe(serverConn, 1)
	}()
	var ack Response
	if err := ReadFrame(clientConn, &ack); err != nil {
		t.Fatal(err)
	}
	clientConn.Close()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("closed subscriber retained its connection slot while no events were broadcast")
	}
	if s.HasSubscribers() {
		t.Fatal("closed subscriber is still registered")
	}
}
