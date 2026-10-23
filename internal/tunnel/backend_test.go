package tunnel

import (
	"testing"
	"time"
)

func TestParseBackendKind(t *testing.T) {
	tests := map[string]BackendKind{
		"":          BackendUserspace,
		"userspace": BackendUserspace,
		"kernel":    BackendKernel,
		"garbage":   BackendUserspace,
	}
	for input, want := range tests {
		if got := ParseBackendKind(input); got != want {
			t.Errorf("ParseBackendKind(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestBackendKindSupported(t *testing.T) {
	if !BackendUserspace.Supported() {
		t.Fatal("userspace backend must always be supported")
	}
	if BackendKernel.Supported() != kernelBackendSupported() {
		t.Fatal("kernel support does not match the platform implementation")
	}
}

func TestManagerSetBackendFallsBack(t *testing.T) {
	m := NewManager(t.TempDir())
	if got := m.backendKind(); got != BackendUserspace {
		t.Fatalf("default backend = %q, want userspace", got)
	}
	m.SetBackend(BackendKernel)
	want := BackendKernel
	if !BackendKernel.Supported() {
		want = BackendUserspace
	}
	if got := m.backendKind(); got != want {
		t.Fatalf("backend after SetBackend = %q, want %q", got, want)
	}
	m.SetBackend(BackendKind("bogus"))
	if got := m.backendKind(); got != BackendUserspace {
		t.Fatalf("unknown backend = %q, want userspace", got)
	}
}

// fakeKernelBackend exercises the Engine dispatch without a driver.
type fakeKernelBackend struct {
	started   bool
	closed    bool
	endpoints []string
}

func (f *fakeKernelBackend) Start() error { f.started = true; return nil }
func (f *fakeKernelBackend) Close() error { f.closed = true; return nil }
func (f *fakeKernelBackend) Status(string, time.Time) (*ConnectionStatus, error) {
	return &ConnectionStatus{State: StateConnected}, nil
}
func (f *fakeKernelBackend) CurrentEndpointIPs() ([]string, error) { return f.endpoints, nil }

func TestEngineKernelDispatch(t *testing.T) {
	backend := &fakeKernelBackend{endpoints: []string{"203.0.113.7"}}
	engine := &Engine{kernel: backend, ifaceName: "test0"}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	if !backend.started {
		t.Fatal("Start did not reach the kernel backend")
	}
	endpoints, err := engine.CurrentEndpointIPs()
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 1 || endpoints[0] != "203.0.113.7" {
		t.Fatalf("endpoints = %v", endpoints)
	}
	if _, err := engine.IpcGet(); err == nil {
		t.Fatal("IpcGet should be unavailable on the kernel backend")
	}
	engine.Close()
	if !backend.closed {
		t.Fatal("Close did not reach the kernel backend")
	}
}
