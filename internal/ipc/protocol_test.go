package ipc

import (
	"encoding/json"
	"testing"
)

func TestNewRequestCreatesValidJSONRPC(t *testing.T) {
	params := map[string]string{"key": "value"}
	req, err := NewRequest(42, MethodPing, params)
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	if req.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %q, want %q", req.JSONRPC, "2.0")
	}
	if req.ID != 42 {
		t.Errorf("ID = %d, want 42", req.ID)
	}
	if req.Method != MethodPing {
		t.Errorf("Method = %q, want %q", req.Method, MethodPing)
	}
	if req.Params == nil {
		t.Fatal("Params is nil, want non-nil")
	}

	var got map[string]string
	if err := json.Unmarshal(req.Params, &got); err != nil {
		t.Fatalf("unmarshal params: %v", err)
	}
	if got["key"] != "value" {
		t.Errorf("params[key] = %q, want %q", got["key"], "value")
	}
}

func TestNewRequestNilParams(t *testing.T) {
	req, err := NewRequest(1, MethodPing, nil)
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	if req.Params != nil {
		t.Errorf("Params = %s, want nil", req.Params)
	}
}

func TestNewNotification(t *testing.T) {
	req, err := NewNotification(EventStatus, map[string]string{"state": "up"})
	if err != nil {
		t.Fatalf("NewNotification returned error: %v", err)
	}
	if req.ID != 0 {
		t.Errorf("ID = %d, want 0 for notification", req.ID)
	}
	if req.Method != EventStatus {
		t.Errorf("Method = %q, want %q", req.Method, EventStatus)
	}
}

func TestNewResponse(t *testing.T) {
	resp, err := NewResponse(7, "ok")
	if err != nil {
		t.Fatalf("NewResponse returned error: %v", err)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %q, want %q", resp.JSONRPC, "2.0")
	}
	if resp.ID != 7 {
		t.Errorf("ID = %d, want 7", resp.ID)
	}
	if resp.Error != nil {
		t.Errorf("Error = %v, want nil", resp.Error)
	}

	var result string
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result != "ok" {
		t.Errorf("result = %q, want %q", result, "ok")
	}
}

func TestNewErrorResponse(t *testing.T) {
	resp := NewErrorResponse(5, ErrCodeMethodNotFound, "method not found")
	if resp.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %q, want %q", resp.JSONRPC, "2.0")
	}
	if resp.ID != 5 {
		t.Errorf("ID = %d, want 5", resp.ID)
	}
	if resp.Error == nil {
		t.Fatal("Error is nil, want non-nil")
	}
	if resp.Error.Code != ErrCodeMethodNotFound {
		t.Errorf("Error.Code = %d, want %d", resp.Error.Code, ErrCodeMethodNotFound)
	}
	if resp.Error.Message != "method not found" {
		t.Errorf("Error.Message = %q, want %q", resp.Error.Message, "method not found")
	}
	if resp.Result != nil {
		t.Errorf("Result = %s, want nil", resp.Result)
	}
}

func TestCodedErrorError(t *testing.T) {
	ce := &CodedError{Code: ErrCodeAppError, Message: "something broke"}
	if ce.Error() != "something broke" {
		t.Errorf("Error() = %q, want %q", ce.Error(), "something broke")
	}
}

func TestErrorError(t *testing.T) {
	e := &Error{Code: ErrCodeInternalError, Message: "internal"}
	if e.Error() != "internal" {
		t.Errorf("Error() = %q, want %q", e.Error(), "internal")
	}
}

func TestIsNotificationReturnsCorrectly(t *testing.T) {
	notif, _ := NewNotification(EventLog, nil)
	if !notif.IsNotification() {
		t.Error("IsNotification() = false for ID=0, want true")
	}

	req, _ := NewRequest(1, MethodPing, nil)
	if req.IsNotification() {
		t.Error("IsNotification() = true for ID=1, want false")
	}
}

func TestRequestJSONRoundtrip(t *testing.T) {
	original, err := NewRequest(99, MethodConnect, map[string]int{"port": 51820})
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded Request
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.JSONRPC != original.JSONRPC {
		t.Errorf("JSONRPC = %q, want %q", decoded.JSONRPC, original.JSONRPC)
	}
	if decoded.ID != original.ID {
		t.Errorf("ID = %d, want %d", decoded.ID, original.ID)
	}
	if decoded.Method != original.Method {
		t.Errorf("Method = %q, want %q", decoded.Method, original.Method)
	}
	if string(decoded.Params) != string(original.Params) {
		t.Errorf("Params = %s, want %s", decoded.Params, original.Params)
	}
}

func TestResponseJSONRoundtrip(t *testing.T) {
	original, err := NewResponse(10, map[string]bool{"connected": true})
	if err != nil {
		t.Fatalf("NewResponse: %v", err)
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded Response
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.JSONRPC != original.JSONRPC {
		t.Errorf("JSONRPC = %q, want %q", decoded.JSONRPC, original.JSONRPC)
	}
	if decoded.ID != original.ID {
		t.Errorf("ID = %d, want %d", decoded.ID, original.ID)
	}
	if string(decoded.Result) != string(original.Result) {
		t.Errorf("Result = %s, want %s", decoded.Result, original.Result)
	}
	if decoded.Error != nil {
		t.Errorf("Error = %v, want nil", decoded.Error)
	}
}

func TestErrorResponseJSONRoundtrip(t *testing.T) {
	original := NewErrorResponse(3, ErrCodeParseError, "parse error")

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded Response
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.Error == nil {
		t.Fatal("Error is nil after roundtrip")
	}
	if decoded.Error.Code != ErrCodeParseError {
		t.Errorf("Error.Code = %d, want %d", decoded.Error.Code, ErrCodeParseError)
	}
	if decoded.Error.Message != "parse error" {
		t.Errorf("Error.Message = %q, want %q", decoded.Error.Message, "parse error")
	}
}
