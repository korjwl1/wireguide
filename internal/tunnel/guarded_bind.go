package tunnel

import (
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// guardedBind makes the Windows outer-socket rule an invariant of Send:
// packets leave only after a successful interface binding. An absent
// underlay or a failed rebind drops packets until protection is restored.
// Keeping binding intent across Close/Open also protects UAPI port changes.
type guardedBind struct {
	conn.Bind
	binder   conn.BindSocketToInterface
	mu       sync.RWMutex
	open     bool
	families [2]socketFamilyBinding
}

type socketFamilyBinding struct {
	index      uint32
	configured bool
	blackhole  bool
	allowed    bool
}

func (b *guardedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	b.open = true
	for family := range b.families {
		b.families[family].allowed = false
		if b.families[family].configured {
			// A failed application keeps this family blocked. The underlay
			// monitor retries, so the socket never falls back to /1 routes.
			_ = b.applyFamily(family)
		}
	}
	return fns, actual, nil
}

func (b *guardedBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.open = false
	for family := range b.families {
		b.families[family].allowed = false
	}
	return b.Bind.Close()
}

func (b *guardedBind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	family := 0
	if endpoint.DstIP().Unmap().Is6() {
		family = 1
	}
	if !b.open || !b.families[family].allowed {
		return nil // same drop semantics as WireGuard's blackhole bind
	}
	return b.Bind.Send(bufs, endpoint)
}

func (b *guardedBind) BindSocketToInterface4(index uint32, blackhole bool) error {
	return b.setFamily(0, index, blackhole)
}

func (b *guardedBind) BindSocketToInterface6(index uint32, blackhole bool) error {
	return b.setFamily(1, index, blackhole)
}

func (b *guardedBind) setFamily(family int, index uint32, blackhole bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.families[family] = socketFamilyBinding{index: index, blackhole: blackhole || index == 0, configured: true}
	return b.applyFamily(family)
}

// applyFamily is called only with mu held exclusively, excluding Send.
func (b *guardedBind) applyFamily(family int) error {
	state := &b.families[family]
	state.allowed = false
	if !b.open || state.blackhole {
		return nil
	}
	var err error
	if family == 0 {
		err = b.binder.BindSocketToInterface4(state.index, false)
	} else {
		err = b.binder.BindSocketToInterface6(state.index, false)
	}
	state.allowed = err == nil
	return err
}
