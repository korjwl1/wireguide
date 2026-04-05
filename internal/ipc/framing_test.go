package ipc

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	orig := Request{JSONRPC: "2.0", ID: 42, Method: "Test.Method"}
	if err := WriteFrame(&buf, orig); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	var got Request
	if err := ReadFrame(&buf, &got); err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.ID != 42 || got.Method != "Test.Method" {
		t.Errorf("mismatch: %+v", got)
	}
}

func TestMultipleFrames(t *testing.T) {
	var buf bytes.Buffer
	for i := uint64(1); i <= 5; i++ {
		req := Request{JSONRPC: "2.0", ID: i, Method: "M"}
		if err := WriteFrame(&buf, req); err != nil {
			t.Fatal(err)
		}
	}
	for i := uint64(1); i <= 5; i++ {
		var got Request
		if err := ReadFrame(&buf, &got); err != nil {
			t.Fatal(err)
		}
		if got.ID != i {
			t.Errorf("expected id %d, got %d", i, got.ID)
		}
	}
}

func TestNewRequest(t *testing.T) {
	req, err := NewRequest(1, MethodConnect, ConnectRequest{ScriptsAllowed: true})
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != MethodConnect || req.ID != 1 {
		t.Errorf("bad request: %+v", req)
	}
	if len(req.Params) == 0 {
		t.Error("params not serialized")
	}
}

func TestIsNotification(t *testing.T) {
	req := Request{ID: 0}
	if !req.IsNotification() {
		t.Error("ID=0 should be notification")
	}
	req.ID = 5
	if req.IsNotification() {
		t.Error("ID=5 should not be notification")
	}
}
