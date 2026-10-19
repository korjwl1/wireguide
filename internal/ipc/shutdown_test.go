package ipc

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

type countedShutdownListener struct {
	net.Listener
	closes atomic.Int32
}

func (l *countedShutdownListener) Close() error {
	l.closes.Add(1)
	return l.Listener.Close()
}

func TestConcurrentServerShutdownClosesListenerOnce(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	counted := &countedShutdownListener{Listener: ln}
	server := NewServer(counted)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; server.Shutdown() }()
	}
	close(start)
	wg.Wait()
	if count := counted.closes.Load(); count != 1 {
		t.Fatalf("listener closed %d times by concurrent signal/RPC shutdowns", count)
	}
}
