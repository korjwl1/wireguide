//go:build windows

package firewall

import (
	"testing"
	"unsafe"
)

// SDK-documented sizes (from fwpmtypes.h on x64 Windows 11 23H2).
// If these mismatch, the kernel will read garbage from our structs.
// A failing test here is far better than a silent firewall malfunction.

func TestFwpmAction0Size(t *testing.T) {
	// FWPM_ACTION0 = FWP_ACTION_TYPE(uint32, 4) + GUID(16, align 4)
	// = 20 bytes natural; no trailing pad because GUID alignment is 4.
	got := unsafe.Sizeof(fwpmAction0{})
	if got != 20 {
		t.Fatalf("fwpmAction0 size = %d, want 20 (a stray pad will misalign filterType)", got)
	}
}

func TestFwpmFilterCondition0Size(t *testing.T) {
	// FWPM_FILTER_CONDITION0 = GUID(16) + FWP_MATCH_TYPE(uint32, 4)
	// + FWP_CONDITION_VALUE0(16, align 8). Compiler inserts 4 bytes pad
	// before the value. Total = 40.
	got := unsafe.Sizeof(fwpmFilterCondition0{})
	if got != 40 {
		t.Fatalf("fwpmFilterCondition0 size = %d, want 40", got)
	}
}

func TestFwpValue0Size(t *testing.T) {
	// FWP_VALUE0 = FWP_DATA_TYPE(uint32, 4) + union(uint64/ptr, 8, align 8).
	// 4 + 4 pad + 8 = 16.
	got := unsafe.Sizeof(fwpValue0{})
	if got != 16 {
		t.Fatalf("fwpValue0 size = %d, want 16", got)
	}
}

func TestFwpByteBlobSize(t *testing.T) {
	// FWP_BYTE_BLOB = UINT32 size + UINT8 *data → 4 + 4 pad + 8 on x64.
	got := unsafe.Sizeof(fwpByteBlob{})
	if got != 16 {
		t.Fatalf("fwpByteBlob size = %d, want 16", got)
	}
}

func TestFwpmDisplayData0Size(t *testing.T) {
	// FWPM_DISPLAY_DATA0 = wchar_t *name + wchar_t *description = 16 on x64.
	got := unsafe.Sizeof(fwpmDisplayData0{})
	if got != 16 {
		t.Fatalf("fwpmDisplayData0 size = %d, want 16", got)
	}
}

func TestFwpmSubLayer0Size(t *testing.T) {
	// FWPM_SUBLAYER0 = GUID(16) + DISPLAY_DATA(16) + UINT32(4)+pad(4)
	// + GUID*(8) + FWP_BYTE_BLOB(16) + UINT16(2) + pad(6) = 72.
	got := unsafe.Sizeof(fwpmSubLayer0{})
	if got != 72 {
		t.Fatalf("fwpmSubLayer0 size = %d, want 72", got)
	}
}

func TestFwpmProvider0Size(t *testing.T) {
	// FWPM_PROVIDER0 = GUID(16) + DISPLAY_DATA(16) + UINT32(4)+pad(4)
	// + FWP_BYTE_BLOB(16) + wchar_t*(8) = 64.
	got := unsafe.Sizeof(fwpmProvider0{})
	if got != 64 {
		t.Fatalf("fwpmProvider0 size = %d, want 64", got)
	}
}

func TestFwpmSession0Size(t *testing.T) {
	// FWPM_SESSION0 = GUID(16) + DISPLAY_DATA(16) + UINT32 flags(4)
	// + UINT32 txnWaitTimeout(4) + DWORD processId(4) + pad(4)
	// + SID*(8) + wchar_t*(8) + BOOL kernelMode(4) + tail-pad(4) = 72.
	// The tail pad exists because struct alignment is 8 (pointer).
	got := unsafe.Sizeof(fwpmSession0{})
	if got != 72 {
		t.Fatalf("fwpmSession0 size = %d, want 72 (kernelMode must be uint32, not uint8)", got)
	}
}

func TestFwpmFilter0Size(t *testing.T) {
	// FWPM_FILTER0 on x64 — see fwpmtypes.h. Total = 200 bytes.
	// Breakdown:
	//   filterKey GUID            16
	//   displayData               16
	//   flags+pad                  8
	//   providerKey *GUID          8
	//   providerData FWP_BYTE_BLOB 16
	//   layerKey GUID             16
	//   subLayerKey GUID          16
	//   weight FWP_VALUE0         16
	//   numFilterConditions+pad    8
	//   filterCondition *cond      8
	//   action FWPM_ACTION0       20
	//   pad before union           4
	//   providerContext union     16
	//   reserved *GUID             8
	//   filterId UINT64            8
	//   effectiveWeight           16
	//   ───────────────────────── 200
	got := unsafe.Sizeof(fwpmFilter0{})
	if got != 200 {
		t.Fatalf("fwpmFilter0 size = %d, want 200 (layout drift will break every filter)", got)
	}
}
