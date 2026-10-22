//go:build windows

package tunnel

import "testing"

func TestKernelAdapterGUIDStable(t *testing.T) {
	first := kernelAdapterGUID("office")
	second := kernelAdapterGUID("office")
	other := kernelAdapterGUID("home")
	if first != second {
		t.Fatal("GUID is not deterministic for the same tunnel name")
	}
	if first == other {
		t.Fatal("different tunnel names produced the same GUID")
	}
	if first.Data3>>12 != 5 {
		t.Fatalf("GUID version = %d, want 5", first.Data3>>12)
	}
	if first.Data4[0]&0xc0 != 0x80 {
		t.Fatalf("GUID variant bits = %#x, want RFC 4122", first.Data4[0])
	}
}
