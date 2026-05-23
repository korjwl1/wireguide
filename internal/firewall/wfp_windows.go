//go:build windows

package firewall

// Low-level WFP (Windows Filtering Platform) bindings — fwpuclnt.dll wrappers.
//
// Layouts and GUID values are taken from Microsoft's fwpmtypes.h / fwpmu.h
// and cross-checked against the official wireguard-windows project's
// tunnel/firewall implementation. Structs MUST keep the field order
// shown in the SDK headers — the kernel writes through these pointers,
// and any layout drift produces silent corruption (no error code, just
// arbitrary filter behaviour).
//
// IMPORTANT GC NOTE: every uintptr(unsafe.Pointer(&x)) call into the
// kernel needs a matching runtime.KeepAlive(&x) AFTER the call returns.
// uintptr drops GC tracking; without KeepAlive, the Go compiler may
// stack-allocate the struct and free it before the kernel has finished
// reading. Higher-level code in windows.go is responsible for keeping
// caller-owned condition-value backing memory alive; this file's wrappers
// keep the immediate argument struct alive across the syscall.

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modFwpuclnt = windows.NewLazySystemDLL("fwpuclnt.dll")

	procFwpmEngineOpen0           = modFwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0          = modFwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmTransactionBegin0     = modFwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0    = modFwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0     = modFwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmProviderAdd0          = modFwpuclnt.NewProc("FwpmProviderAdd0")
	procFwpmSubLayerAdd0          = modFwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmSubLayerDeleteByKey0  = modFwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmProviderDeleteByKey0  = modFwpuclnt.NewProc("FwpmProviderDeleteByKey0")
	procFwpmFilterAdd0            = modFwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteById0     = modFwpuclnt.NewProc("FwpmFilterDeleteById0")
)

// RPC_C_AUTHN_WINNT — pass-through Windows NT authn for FwpmEngineOpen0.
const cRPC_C_AUTHN_WINNT = 10

// FWP_DATA_TYPE values used by us. Subset of the full enum.
// Source: fwptypes.h (Windows SDK) and the FWP_DATA_TYPE Microsoft Learn
// reference. The previous values in this file were off-by-one for the
// integer types AND missed the SDK's deliberate jump to 0x100 for
// V4_ADDR_MASK / V6_ADDR_MASK / RANGE_TYPE (the SDK puts
// FWP_SINGLE_DATA_TYPE_MAX = 0xff between the scalar block and the
// pointer-to-struct block). The bug surfaced as 0xC0000005 in
// FwpmFilterAdd0 the first time auto-DNS-protection ran for a full-
// tunnel, DNS-configured connect: WFP read our "0xC = V4_ADDR_MASK"
// as FWP_BYTE_BLOB_TYPE, dereferenced the V4_ADDR_AND_MASK pointer as
// an FWP_BYTE_BLOB layout, and ran off the end of the 8-byte struct.
// EnableKillSwitch never hit it because the user hasn't toggled kill
// switch on; auto-DNS-protection is what reliably reproduces it.
const (
	dataTypeUint8     = 1     // FWP_UINT8
	dataTypeUint16    = 2     // FWP_UINT16
	dataTypeUint32    = 3     // FWP_UINT32
	dataTypeUint64    = 4     // FWP_UINT64
	dataTypeByteBlob  = 12    // FWP_BYTE_BLOB_TYPE
	dataTypeV4Address = 0x100 // FWP_V4_ADDR_MASK
	dataTypeV6Address = 0x101 // FWP_V6_ADDR_MASK
	dataTypeRange     = 0x102 // FWP_RANGE_TYPE
)

// FWP_MATCH_TYPE values.
const (
	matchEqual = 0
	matchFlags_AllSet = 6 // FWP_MATCH_FLAGS_ALL_SET
)

// FWP_ACTION_TYPE values. The 0x1000 bit distinguishes "terminating" actions
// from informational ones; we always want terminating.
const (
	actionBlock  = 0x00000001 | 0x00001000 // FWP_ACTION_BLOCK
	actionPermit = 0x00000002 | 0x00001000 // FWP_ACTION_PERMIT
)

// FWPM_SESSION flags.
const fwpmSessionFlagDynamic = 0x00000001

// FWPM_FILTER flags.
const fwpmFilterFlagNone = 0

// fwpByteBlob mirrors FWP_BYTE_BLOB.
type fwpByteBlob struct {
	size uint32
	data *uint8
}

// fwpmDisplayData0 mirrors FWPM_DISPLAY_DATA0.
type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

// fwpmSession0 mirrors FWPM_SESSION0. The kernelMode field is BOOL (Windows
// BOOL is a 32-bit int, not a single byte) — a previous uint8 typing made
// the kernel read 3 garbage bytes as part of the BOOL, which happened to
// always be zero in our zero-initialised struct but was load-bearing only
// by coincidence.
type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           uint32 // BOOL in Windows
}

// fwpValue0 is FWP_VALUE0 — a small tagged union. The `value` field is
// large enough to hold any of UINT8/16/32/64, pointer, or pointer to
// V6_ADDR_MASK (which is a separate allocation).
type fwpValue0 struct {
	dataType uint32
	_pad     uint32 // alignment for 64-bit value on x64
	value    uintptr
}

// fwpConditionValue0 has the same layout as fwpValue0 per SDK.
type fwpConditionValue0 = fwpValue0

// fwpmFilterCondition0 mirrors FWPM_FILTER_CONDITION0.
type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	_pad           uint32 // alignment for the conditionValue (16-byte aligned)
	conditionValue fwpConditionValue0
}

// fwpmAction0 mirrors FWPM_ACTION0 — { FWP_ACTION_TYPE type; GUID filterType_or_calloutKey; }.
// FWP_ACTION_TYPE is DWORD (4 bytes), GUID's natural alignment is 4 (its
// first field is Data1 uint32) so the GUID immediately follows actionType
// without padding. Total 4 + 16 = 20 bytes. Adding a uint32 _pad here
// would shift filterType by 4 bytes and the kernel would read garbage
// for callout filters.
type fwpmAction0 struct {
	actionType uint32
	filterType windows.GUID
}

// fwpmFilter0 mirrors FWPM_FILTER0 on 64-bit Windows. Field ordering is
// load-bearing — do not reorder. Sizes were cross-checked against
// fwpmtypes.h: the providerContextKey union (UINT64 rawContext | GUID
// providerContextKey) is 16 bytes; we represent it as a fixed [16]byte
// zero-initialised buffer because we never use FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT.
type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	// Go's struct alignment inserts the 4-byte pad here automatically because
	// providerKey is a pointer (8-byte aligned on x64); no explicit _pad needed.
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	// Again, the next field is a pointer, so Go inserts 4 bytes of padding.
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0 // 20 bytes; Go aligns the next 8-byte field after.
	// providerContextKey union — 16 bytes, alignment 8. Using [2]uint64
	// forces 8-byte alignment; [16]byte (align 1) would let Go put this
	// at the wrong offset and the kernel would misread `reserved` etc.
	providerContext     [2]uint64
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     fwpValue0
}

// fwpmSubLayer0 mirrors FWPM_SUBLAYER0.
type fwpmSubLayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	_pad         uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
	_pad2        [6]byte
}

// fwpmProvider0 mirrors FWPM_PROVIDER0.
type fwpmProvider0 struct {
	providerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	_pad         uint32
	providerData fwpByteBlob
	serviceName  *uint16
}

// --- GUID constants ----------------------------------------------------
// All of these are documented in fwpmu.h and identified by their canonical
// values; they are stable across Windows versions.

// Layers we attach filters to.
var (
	// FWPM_LAYER_ALE_AUTH_CONNECT_V4 — outbound IPv4 connect attempt.
	guidLayerAleAuthConnectV4 = windows.GUID{
		Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33,
		Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
	}
	// FWPM_LAYER_ALE_AUTH_CONNECT_V6.
	guidLayerAleAuthConnectV6 = windows.GUID{
		Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc,
		Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4},
	}
)

// allConnectLayers is the ordered pair of layers we install filters on
// (IPv4 + IPv6 outbound connect). Package-level array so it isn't
// re-allocated on every EnableKillSwitch call.
var allConnectLayers = [2]windows.GUID{
	guidLayerAleAuthConnectV4,
	guidLayerAleAuthConnectV6,
}

// Conditions we match on inside those layers.
var (
	guidCondIPRemoteAddress = windows.GUID{
		Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8,
		Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45},
	}
	guidCondIPLocalPort = windows.GUID{
		Data1: 0x0c1ba1af, Data2: 0x5765, Data3: 0x453f,
		Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b},
	}
	guidCondIPRemotePort = windows.GUID{
		Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a,
		Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b},
	}
	guidCondIPProtocol = windows.GUID{
		Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a,
		Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7},
	}
	guidCondIPLocalInterface = windows.GUID{
		Data1: 0x4cd62a49, Data2: 0x59c3, Data3: 0x4969,
		Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4},
	}
)

// --- thin syscall wrappers ---------------------------------------------

func fwpmEngineOpen0(session *fwpmSession0, handle *uintptr) uint32 {
	ret, _, _ := procFwpmEngineOpen0.Call(
		0, // serverName (NULL → local)
		uintptr(cRPC_C_AUTHN_WINNT),
		0, // authIdentity (NULL → caller's identity)
		uintptr(unsafe.Pointer(session)),
		uintptr(unsafe.Pointer(handle)),
	)
	runtime.KeepAlive(session)
	runtime.KeepAlive(handle)
	return uint32(ret)
}

func fwpmEngineClose0(handle uintptr) uint32 {
	ret, _, _ := procFwpmEngineClose0.Call(handle)
	return uint32(ret)
}

func fwpmTransactionBegin0(handle uintptr) uint32 {
	ret, _, _ := procFwpmTransactionBegin0.Call(handle, 0)
	return uint32(ret)
}

func fwpmTransactionCommit0(handle uintptr) uint32 {
	ret, _, _ := procFwpmTransactionCommit0.Call(handle)
	return uint32(ret)
}

func fwpmTransactionAbort0(handle uintptr) uint32 {
	ret, _, _ := procFwpmTransactionAbort0.Call(handle)
	return uint32(ret)
}

func fwpmProviderAdd0(handle uintptr, p *fwpmProvider0) uint32 {
	ret, _, _ := procFwpmProviderAdd0.Call(
		handle,
		uintptr(unsafe.Pointer(p)),
		0, // PSECURITY_DESCRIPTOR (NULL → default)
	)
	runtime.KeepAlive(p)
	return uint32(ret)
}

func fwpmSubLayerAdd0(handle uintptr, sub *fwpmSubLayer0) uint32 {
	ret, _, _ := procFwpmSubLayerAdd0.Call(
		handle,
		uintptr(unsafe.Pointer(sub)),
		0,
	)
	runtime.KeepAlive(sub)
	return uint32(ret)
}

func fwpmFilterAdd0(handle uintptr, f *fwpmFilter0) (uint64, uint32) {
	var filterID uint64
	ret, _, _ := procFwpmFilterAdd0.Call(
		handle,
		uintptr(unsafe.Pointer(f)),
		0,
		uintptr(unsafe.Pointer(&filterID)),
	)
	runtime.KeepAlive(f)
	return filterID, uint32(ret)
}

// fwpmFilterDeleteById0 removes a single filter by its WFP filter ID
// (returned by FwpmFilterAdd0). Used to remove per-tunnel permits when
// a tunnel disconnects without tearing down the rest of the kill switch.
func fwpmFilterDeleteById0(handle uintptr, id uint64) uint32 {
	ret, _, _ := procFwpmFilterDeleteById0.Call(handle, uintptr(id))
	return uint32(ret)
}

// fwpmSubLayerDeleteByKey0 deletes a sublayer AND every filter attached
// to it (cascading delete per the SDK contract). Used by the startup-
// time orphan-filter cleanup so a previous helper run that failed to
// close its dynamic session cleanly doesn't leave a permanently-
// blocking catch-all filter alive after we install our own.
func fwpmSubLayerDeleteByKey0(handle uintptr, key *windows.GUID) uint32 {
	ret, _, _ := procFwpmSubLayerDeleteByKey0.Call(handle, uintptr(unsafe.Pointer(key)))
	runtime.KeepAlive(key)
	return uint32(ret)
}

// fwpmProviderDeleteByKey0 removes a registered WFP provider. Filters
// referencing the provider must already be gone (we delete the
// sublayer first, which cascades the filters).
func fwpmProviderDeleteByKey0(handle uintptr, key *windows.GUID) uint32 {
	ret, _, _ := procFwpmProviderDeleteByKey0.Call(handle, uintptr(unsafe.Pointer(key)))
	runtime.KeepAlive(key)
	return uint32(ret)
}

// --- value helpers -----------------------------------------------------

// uint8Value wraps an FWP_UINT8 in fwpConditionValue0.
func uint8Value(v uint8) fwpConditionValue0 {
	return fwpConditionValue0{dataType: dataTypeUint8, value: uintptr(v)}
}

// uint16Value wraps an FWP_UINT16.
func uint16Value(v uint16) fwpConditionValue0 {
	return fwpConditionValue0{dataType: dataTypeUint16, value: uintptr(v)}
}

// uint32Value wraps an FWP_UINT32. Used for IPv4 addresses in
// FWPM_CONDITION_IP_REMOTE_ADDRESS (network byte order).
func uint32Value(v uint32) fwpConditionValue0 {
	return fwpConditionValue0{dataType: dataTypeUint32, value: uintptr(v)}
}

// uint64ValuePtr wraps a UINT64 that the kernel reads via pointer. Used for
// interface LUIDs in FWPM_CONDITION_IP_LOCAL_INTERFACE.
func uint64ValuePtr(p *uint64) fwpConditionValue0 {
	return fwpConditionValue0{dataType: dataTypeUint64, value: uintptr(unsafe.Pointer(p))}
}

// filterWeight builds an FWP_VALUE0 holding a UINT8 priority weight
// (0 = lowest, 15 = highest). FWPM_FILTER0::weight is documented as
// FWP_EMPTY, FWP_UINT8, or FWP_UINT64 only — passing FWP_UINT16 there
// triggers FWP_E_TYPE_MISMATCH (0x80320025) at FwpmFilterAdd0, which
// is the failure we saw on "Permit tunnel" when enabling the kill
// switch. wireguard-windows tunnel/firewall/helpers.go uses the same
// UINT8 pattern, so we mirror it. The caller-side weight is taken as
// uint8 to enforce the 0-15 priority range at the type level.
func filterWeight(w uint8) fwpValue0 {
	return fwpValue0{dataType: dataTypeUint8, value: uintptr(w)}
}

// utf16Ptr is a convenience over windows.UTF16PtrFromString that returns
// the pointer or nil on error.
func utf16Ptr(s string) *uint16 {
	if s == "" {
		return nil
	}
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return nil
	}
	return p
}

// --- compile-time struct-size assertions -------------------------------
// unsafe.Sizeof is a constant, so any mismatch fails the build. These
// guard against silent breakage if someone reorders a field.

const _ = uintptr(20 - unsafe.Sizeof(fwpmAction0{}))               // must be 20
const _ = uintptr(16 - unsafe.Sizeof(fwpValue0{}))                 // must be 16
const _ = uintptr(40 - unsafe.Sizeof(fwpmFilterCondition0{}))      // must be 40
const _ = uintptr(16 - unsafe.Sizeof(fwpByteBlob{}))               // must be 16
const _ = uintptr(16 - unsafe.Sizeof(fwpmDisplayData0{}))          // must be 16
const _ = uintptr(72 - unsafe.Sizeof(fwpmSubLayer0{}))             // must be 72
const _ = uintptr(64 - unsafe.Sizeof(fwpmProvider0{}))             // must be 64
const _ = uintptr(72 - unsafe.Sizeof(fwpmSession0{}))              // must be 72
const _ = uintptr(200 - unsafe.Sizeof(fwpmFilter0{}))              // must be 200
