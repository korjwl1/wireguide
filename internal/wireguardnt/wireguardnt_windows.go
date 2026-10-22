//go:build windows

// Package wireguardnt binds the official WireGuardNT user-mode API exported
// by wireguard.dll. The DLL is the supported embedding surface for the
// in-kernel WireGuard driver; callers must load it from the application
// directory and talk to it only through these exported functions.
package wireguardnt

import (
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	afInet  uint16 = 2
	afInet6 uint16 = 23

	interfaceHasPrivateKey = 1 << 1
	interfaceHasListenPort = 1 << 2
	interfaceReplacePeers  = 1 << 3

	peerHasPublicKey           = 1 << 0
	peerHasPresharedKey        = 1 << 1
	peerHasPersistentKeepalive = 1 << 2
	peerHasEndpoint            = 1 << 3
	peerReplaceAllowedIPs      = 1 << 5

	adapterStateDown = 0
	adapterStateUp   = 1

	adapterLogOff = 0
	adapterLogOn  = 1
)

// windowsEpochOffset is the number of 100ns intervals between the Windows
// FILETIME epoch (1601-01-01) and the Unix epoch (1970-01-01).
const windowsEpochOffset = 116444736000000000

// GUID is the Windows adapter GUID requested at creation time. A stable GUID
// keeps the NLA network profile (and therefore the user's Public/Private
// choice) attached across reconnects.
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// Peer is one WireGuard peer in a configuration snapshot.
type Peer struct {
	PublicKey           [32]byte
	PresharedKey        [32]byte
	HasPresharedKey     bool
	Endpoint            netip.AddrPort
	PersistentKeepalive uint16
	AllowedIPs          []netip.Prefix
}

// Configuration is the subset of WireGuard settings the driver needs when a
// tunnel is created. Endpoints must already be literal IP:port pairs.
type Configuration struct {
	PrivateKey [32]byte
	ListenPort uint16
	Peers      []Peer
}

// PeerState is the live state the driver reports for one peer.
type PeerState struct {
	PublicKey     [32]byte
	Endpoint      netip.AddrPort
	TxBytes       uint64
	RxBytes       uint64
	LastHandshake time.Time
	AllowedIPs    []netip.Prefix
}

// Snapshot is the live adapter configuration returned by the driver.
type Snapshot struct {
	InterfacePublicKey [32]byte
	Peers              []PeerState
}

// C layout mirrors. These are only used behind unsafe.Pointer, never
// serialized directly. The compile-time assertions below pin the sizes to the
// sizes from wireguard.h; the explicit padding is part of that contract.
type wireguardInterface struct {
	Flags      uint32
	ListenPort uint16
	PrivateKey [32]byte
	PublicKey  [32]byte
	PeersCount uint32
	_          [4]byte
}

type sockaddrInet struct {
	Family uint16
	Port   uint16
	Data   [24]byte // SOCKADDR_IN6 flowinfo(4)+addr(16)+scope(4); IPv4 uses Data[0:4]
}

type wireguardPeer struct {
	Flags               uint32
	Reserved            uint32
	PublicKey           [32]byte
	PresharedKey        [32]byte
	PersistentKeepalive uint16
	_                   [2]byte
	Endpoint            sockaddrInet
	TxBytes             uint64
	RxBytes             uint64
	LastHandshake       uint64
	AllowedIPsCount     uint32
	_                   [4]byte
}

type wireguardAllowedIP struct {
	Address       [16]byte
	AddressFamily uint16
	Cidr          uint8
	_             [1]byte
	Flags         uint32
}

var (
	_ [unsafe.Sizeof(wireguardInterface{}) - 80]byte
	_ [80 - unsafe.Sizeof(wireguardInterface{})]byte
	_ [unsafe.Sizeof(wireguardPeer{}) - 136]byte
	_ [136 - unsafe.Sizeof(wireguardPeer{})]byte
	_ [unsafe.Sizeof(wireguardAllowedIP{}) - 24]byte
	_ [24 - unsafe.Sizeof(wireguardAllowedIP{})]byte
)

// API owns the loaded wireguard.dll and its exported function pointers.
type API struct {
	dll        *windows.LazyDLL
	create     *windows.LazyProc
	close      *windows.LazyProc
	getLUID    *windows.LazyProc
	setConfig  *windows.LazyProc
	getConfig  *windows.LazyProc
	setState   *windows.LazyProc
	getState   *windows.LazyProc
	setLogger  *windows.LazyProc
	setLogging *windows.LazyProc
	driverVer  *windows.LazyProc
}

// Adapter is one WireGuardNT network adapter owned by this process.
type Adapter struct {
	api    *API
	handle uintptr
}

var (
	defaultOnce sync.Once
	defaultAPI  *API
	defaultErr  error
)

// Default loads wireguard.dll from the directory containing the running
// executable. The helper process and the GUI both run from the install
// directory, so this is the same file shipped next to wireguard.exe.
func Default() (*API, error) {
	defaultOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			defaultErr = fmt.Errorf("locating executable: %w", err)
			return
		}
		defaultAPI, defaultErr = Open(filepath.Join(filepath.Dir(exe), "wireguard.dll"))
	})
	return defaultAPI, defaultErr
}

// Open loads the DLL at dllPath and resolves every exported function used by
// this package. An absolute path is required by callers outside tests; the
// loader deliberately does not search the working directory.
func Open(dllPath string) (*API, error) {
	dll := windows.NewLazyDLL(dllPath)
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("loading %s: %w", dllPath, err)
	}
	api := &API{
		dll:        dll,
		create:     dll.NewProc("WireGuardCreateAdapter"),
		close:      dll.NewProc("WireGuardCloseAdapter"),
		getLUID:    dll.NewProc("WireGuardGetAdapterLUID"),
		setConfig:  dll.NewProc("WireGuardSetConfiguration"),
		getConfig:  dll.NewProc("WireGuardGetConfiguration"),
		setState:   dll.NewProc("WireGuardSetAdapterState"),
		getState:   dll.NewProc("WireGuardGetAdapterState"),
		setLogger:  dll.NewProc("WireGuardSetLogger"),
		setLogging: dll.NewProc("WireGuardSetAdapterLogging"),
		driverVer:  dll.NewProc("WireGuardGetRunningDriverVersion"),
	}
	for name, proc := range map[string]*windows.LazyProc{
		"WireGuardCreateAdapter":           api.create,
		"WireGuardCloseAdapter":            api.close,
		"WireGuardGetAdapterLUID":          api.getLUID,
		"WireGuardSetConfiguration":        api.setConfig,
		"WireGuardGetConfiguration":        api.getConfig,
		"WireGuardSetAdapterState":         api.setState,
		"WireGuardGetAdapterState":         api.getState,
		"WireGuardSetLogger":               api.setLogger,
		"WireGuardSetAdapterLogging":       api.setLogging,
		"WireGuardGetRunningDriverVersion": api.driverVer,
	} {
		if err := proc.Find(); err != nil {
			return nil, fmt.Errorf("resolving %s from %s: %w", name, dllPath, err)
		}
	}
	return api, nil
}

// RunningDriverVersion returns the loaded driver version, or an error when
// the driver is not loaded yet (WireGuardCreateAdapter loads it on demand).
func (a *API) RunningDriverVersion() (uint32, error) {
	version, _, callErr := a.driverVer.Call()
	if version == 0 {
		return 0, callError(callErr)
	}
	return uint32(version), nil
}

// CreateAdapter creates a kernel adapter and loads the driver on first use.
// Creating an adapter requires administrator privileges.
func (a *API) CreateAdapter(name, tunnelType string, guid *GUID) (*Adapter, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("adapter name: %w", err)
	}
	typePtr, err := windows.UTF16PtrFromString(tunnelType)
	if err != nil {
		return nil, fmt.Errorf("tunnel type: %w", err)
	}
	var guidPtr uintptr
	if guid != nil {
		guidPtr = uintptr(unsafe.Pointer(guid))
	}
	handle, _, callErr := a.create.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(typePtr)),
		guidPtr,
	)
	runtime.KeepAlive(namePtr)
	runtime.KeepAlive(typePtr)
	runtime.KeepAlive(guid)
	if handle == 0 {
		return nil, fmt.Errorf("WireGuardCreateAdapter(%q): %w", name, callError(callErr))
	}
	return &Adapter{api: a, handle: handle}, nil
}

// Close releases the adapter. An adapter created by CreateAdapter is removed
// from the system; the driver unloads once the last adapter is gone.
func (a *Adapter) Close() {
	if a == nil || a.handle == 0 {
		return
	}
	a.api.close.Call(a.handle)
	a.handle = 0
}

// LUID returns the adapter's network interface LUID. WireGuide's WFP and
// route code key on this value.
func (a *Adapter) LUID() uint64 {
	if a == nil || a.handle == 0 {
		return 0
	}
	var luid uint64
	a.api.getLUID.Call(a.handle, uintptr(unsafe.Pointer(&luid)))
	return luid
}

// SetConfiguration applies keys, peers, endpoints, and allowed IPs. It does
// not bring the adapter up.
func (a *Adapter) SetConfiguration(cfg *Configuration) error {
	if a == nil || a.handle == 0 {
		return errors.New("WireGuard adapter is closed")
	}
	raw, backing, err := encodeConfiguration(cfg)
	if err != nil {
		return err
	}
	ok, _, callErr := a.api.setConfig.Call(
		a.handle,
		uintptr(unsafe.Pointer(&raw[0])),
		uintptr(len(raw)),
	)
	runtime.KeepAlive(backing)
	if ok == 0 {
		return fmt.Errorf("WireGuardSetConfiguration: %w", callError(callErr))
	}
	return nil
}

// SetUp transitions the adapter between down and up. The driver starts the
// handshake state machine when the adapter goes up.
func (a *Adapter) SetUp(up bool) error {
	if a == nil || a.handle == 0 {
		return errors.New("WireGuard adapter is closed")
	}
	state := uintptr(adapterStateDown)
	if up {
		state = adapterStateUp
	}
	ok, _, callErr := a.api.setState.Call(a.handle, state)
	if ok == 0 {
		return fmt.Errorf("WireGuardSetAdapterState: %w", callError(callErr))
	}
	return nil
}

// Up reports the adapter state from the driver.
func (a *Adapter) Up() (bool, error) {
	if a == nil || a.handle == 0 {
		return false, errors.New("WireGuard adapter is closed")
	}
	var state uint32
	ok, _, callErr := a.api.getState.Call(a.handle, uintptr(unsafe.Pointer(&state)))
	if ok == 0 {
		return false, fmt.Errorf("WireGuardGetAdapterState: %w", callError(callErr))
	}
	return state == adapterStateUp, nil
}

// SetLogging toggles driver-side diagnostic events for this adapter. The
// process-wide callback is installed with SetLogger.
func (a *Adapter) SetLogging(on bool) error {
	if a == nil || a.handle == 0 {
		return errors.New("WireGuard adapter is closed")
	}
	state := uintptr(adapterLogOff)
	if on {
		state = adapterLogOn
	}
	ok, _, callErr := a.api.setLogging.Call(a.handle, state)
	if ok == 0 {
		return fmt.Errorf("WireGuardSetAdapterLogging: %w", callError(callErr))
	}
	return nil
}

// SetLogger installs the process-wide driver logger callback.
func (a *API) SetLogger(callback uintptr) {
	a.setLogger.Call(callback)
}

// Snapshot reads the live peer configuration and counters. The driver
// expects a two-call protocol: first with a nil buffer to learn the required
// size, then with an aligned buffer of that size.
func (a *Adapter) Snapshot() (*Snapshot, error) {
	if a == nil || a.handle == 0 {
		return nil, errors.New("WireGuard adapter is closed")
	}
	var size uint32
	ok, _, callErr := a.api.getConfig.Call(a.handle, 0, uintptr(unsafe.Pointer(&size)))
	if ok == 0 && !errors.Is(callError(callErr), windows.ERROR_MORE_DATA) {
		return nil, fmt.Errorf("WireGuardGetConfiguration size query: %w", callError(callErr))
	}
	if size < uint32(unsafe.Sizeof(wireguardInterface{})) {
		return nil, fmt.Errorf("WireGuardGetConfiguration returned invalid size %d", size)
	}
	raw, backing := alignedBytes(int(size))
	ok, _, callErr = a.api.getConfig.Call(
		a.handle,
		uintptr(unsafe.Pointer(&raw[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	runtime.KeepAlive(backing)
	if ok == 0 {
		return nil, fmt.Errorf("WireGuardGetConfiguration: %w", callError(callErr))
	}
	return decodeConfiguration(raw[:size])
}

func alignedBytes(size int) ([]byte, []uint64) {
	backing := make([]uint64, (size+7)/8)
	return unsafe.Slice((*byte)(unsafe.Pointer(&backing[0])), size), backing
}

func encodeConfiguration(cfg *Configuration) ([]byte, []uint64, error) {
	if cfg == nil {
		return nil, nil, errors.New("nil WireGuard configuration")
	}
	interfaceSize := int(unsafe.Sizeof(wireguardInterface{}))
	peerSize := int(unsafe.Sizeof(wireguardPeer{}))
	allowedSize := int(unsafe.Sizeof(wireguardAllowedIP{}))
	total := interfaceSize
	for _, peer := range cfg.Peers {
		total += peerSize + len(peer.AllowedIPs)*allowedSize
	}
	raw, backing := alignedBytes(total)
	iface := (*wireguardInterface)(unsafe.Pointer(&raw[0]))
	iface.Flags = interfaceHasPrivateKey | interfaceReplacePeers
	iface.PrivateKey = cfg.PrivateKey
	iface.PeersCount = uint32(len(cfg.Peers))
	if cfg.ListenPort != 0 {
		iface.Flags |= interfaceHasListenPort
		iface.ListenPort = cfg.ListenPort
	}

	offset := interfaceSize
	for _, peerCfg := range cfg.Peers {
		peer := (*wireguardPeer)(unsafe.Pointer(&raw[offset]))
		peer.Flags = peerHasPublicKey | peerReplaceAllowedIPs
		peer.PublicKey = peerCfg.PublicKey
		if peerCfg.HasPresharedKey {
			peer.Flags |= peerHasPresharedKey
			peer.PresharedKey = peerCfg.PresharedKey
		}
		if peerCfg.PersistentKeepalive != 0 {
			peer.Flags |= peerHasPersistentKeepalive
			peer.PersistentKeepalive = peerCfg.PersistentKeepalive
		}
		if peerCfg.Endpoint.IsValid() {
			peer.Flags |= peerHasEndpoint
			peer.Endpoint = encodeSockaddr(peerCfg.Endpoint)
		}
		peer.AllowedIPsCount = uint32(len(peerCfg.AllowedIPs))
		offset += peerSize
		for _, prefix := range peerCfg.AllowedIPs {
			if err := writeAllowedIP(raw[offset:offset+allowedSize], prefix); err != nil {
				return nil, nil, err
			}
			offset += allowedSize
		}
	}
	return raw, backing, nil
}

func writeAllowedIP(dst []byte, prefix netip.Prefix) error {
	prefix = prefix.Masked()
	addr := prefix.Addr().Unmap()
	aip := (*wireguardAllowedIP)(unsafe.Pointer(&dst[0]))
	aip.Cidr = uint8(prefix.Bits())
	switch {
	case addr.Is4():
		aip.AddressFamily = afInet
		v4 := addr.As4()
		copy(aip.Address[:4], v4[:])
	case addr.Is6():
		aip.AddressFamily = afInet6
		v6 := addr.As16()
		copy(aip.Address[:], v6[:])
	default:
		return fmt.Errorf("unsupported allowed IP %q", prefix)
	}
	return nil
}

func encodeSockaddr(endpoint netip.AddrPort) sockaddrInet {
	var result sockaddrInet
	result.Port = bits.ReverseBytes16(endpoint.Port())
	addr := endpoint.Addr().Unmap()
	switch {
	case addr.Is4():
		result.Family = afInet
		v4 := addr.As4()
		copy(result.Data[0:4], v4[:])
	case addr.Is6():
		result.Family = afInet6
		v6 := addr.As16()
		copy(result.Data[4:20], v6[:])
	}
	return result
}

func decodeSockaddr(s sockaddrInet) netip.AddrPort {
	port := bits.ReverseBytes16(s.Port)
	switch s.Family {
	case afInet:
		var v4 [4]byte
		copy(v4[:], s.Data[0:4])
		return netip.AddrPortFrom(netip.AddrFrom4(v4), port)
	case afInet6:
		var v6 [16]byte
		copy(v6[:], s.Data[4:20])
		return netip.AddrPortFrom(netip.AddrFrom16(v6), port)
	default:
		return netip.AddrPort{}
	}
}

func decodeConfiguration(raw []byte) (*Snapshot, error) {
	if len(raw) < int(unsafe.Sizeof(wireguardInterface{})) {
		return nil, fmt.Errorf("configuration too short: %d bytes", len(raw))
	}
	iface := (*wireguardInterface)(unsafe.Pointer(&raw[0]))
	snapshot := &Snapshot{InterfacePublicKey: iface.PublicKey}
	peerSize := int(unsafe.Sizeof(wireguardPeer{}))
	allowedSize := int(unsafe.Sizeof(wireguardAllowedIP{}))
	offset := int(unsafe.Sizeof(wireguardInterface{}))
	for i := 0; i < int(iface.PeersCount); i++ {
		if offset+peerSize > len(raw) {
			return nil, fmt.Errorf("peer %d exceeds configuration size", i)
		}
		peer := (*wireguardPeer)(unsafe.Pointer(&raw[offset]))
		offset += peerSize
		state := PeerState{
			PublicKey: peer.PublicKey,
			Endpoint:  decodeSockaddr(peer.Endpoint),
			TxBytes:   peer.TxBytes,
			RxBytes:   peer.RxBytes,
		}
		if peer.LastHandshake > windowsEpochOffset {
			ns := int64(peer.LastHandshake-windowsEpochOffset) * 100
			state.LastHandshake = time.Unix(0, ns)
		}
		for j := 0; j < int(peer.AllowedIPsCount); j++ {
			if offset+allowedSize > len(raw) {
				return nil, fmt.Errorf("peer %d allowed IP %d exceeds configuration size", i, j)
			}
			aip := (*wireguardAllowedIP)(unsafe.Pointer(&raw[offset]))
			offset += allowedSize
			prefix, ok := decodeAllowedIP(aip)
			if ok {
				state.AllowedIPs = append(state.AllowedIPs, prefix)
			}
		}
		snapshot.Peers = append(snapshot.Peers, state)
	}
	return snapshot, nil
}

func decodeAllowedIP(aip *wireguardAllowedIP) (netip.Prefix, bool) {
	switch aip.AddressFamily {
	case afInet:
		var v4 [4]byte
		copy(v4[:], aip.Address[:4])
		if aip.Cidr > 32 {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(netip.AddrFrom4(v4), int(aip.Cidr)).Masked(), true
	case afInet6:
		var v6 [16]byte
		copy(v6[:], aip.Address[:])
		if aip.Cidr > 128 {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(netip.AddrFrom16(v6), int(aip.Cidr)).Masked(), true
	default:
		return netip.Prefix{}, false
	}
}

// callError normalizes the Win32 last-error value returned by LazyProc.Call.
func callError(err error) error {
	if err == nil {
		return nil
	}
	if errno, ok := err.(syscall.Errno); ok {
		if errno == 0 {
			return nil
		}
		return errno
	}
	return err
}
