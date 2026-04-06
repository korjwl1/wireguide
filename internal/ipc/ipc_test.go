package ipc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func testSocketPath(t *testing.T) string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\wireguide-test-` + t.Name()
	}
	return filepath.Join(os.TempDir(), "wireguide-test-"+t.Name()+".sock")
}

// registerTestPing registers a Helper.Ping handler that returns the current
// protocol version, which NewClient requires for its handshake.
func registerTestPing(s *Server) {
	s.Handle(MethodPing, func(params json.RawMessage) (interface{}, error) {
		return PingResponse{Version: ProtocolVersion, PID: os.Getpid()}, nil
	})
}

func TestClientServerRPC(t *testing.T) {
	addr := testSocketPath(t)
	listener, err := Listen(addr, -1)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	server := NewServer(listener)
	registerTestPing(server)
	server.Handle("Test.Echo", func(params json.RawMessage) (interface{}, error) {
		var s string
		json.Unmarshal(params, &s)
		return s + "!", nil
	})
	go server.Serve()
	defer server.Shutdown()

	// Wait for listener to be ready
	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(addr)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	var result string
	if err := client.Call("Test.Echo", "hello", &result); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if result != "hello!" {
		t.Errorf("expected 'hello!', got %q", result)
	}
}

func TestEventBroadcast(t *testing.T) {
	addr := testSocketPath(t)
	listener, err := Listen(addr, -1)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	server := NewServer(listener)
	registerTestPing(server)
	go server.Serve()
	defer server.Shutdown()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(addr)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	received := make(chan string, 1)
	if err := client.Subscribe(func(method string, params json.RawMessage) {
		if method == "event.test" {
			var s string
			json.Unmarshal(params, &s)
			received <- s
		}
	}); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Give subscription time to register
	time.Sleep(100 * time.Millisecond)

	server.Broadcast("event.test", "hello from server")

	select {
	case msg := <-received:
		if msg != "hello from server" {
			t.Errorf("got %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("event not received")
	}
}

func TestMethodNotFound(t *testing.T) {
	addr := testSocketPath(t)
	listener, err := Listen(addr, -1)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	server := NewServer(listener)
	registerTestPing(server)
	go server.Serve()
	defer server.Shutdown()

	time.Sleep(100 * time.Millisecond)

	client, _ := NewClient(addr)
	defer client.Close()

	err = client.Call("Does.NotExist", nil, nil)
	if err == nil {
		t.Error("expected error for missing method")
	}
}
