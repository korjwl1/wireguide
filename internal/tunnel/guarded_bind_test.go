package tunnel

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// Native Windows sends can wait for RIO completion. Close must reach the
// underlying bind to wake them, as required by conn.Bind's contract.
type stalledSendBind struct {
	*testInterfaceBind
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *stalledSendBind) Send([][]byte, conn.Endpoint) error {
	close(b.started)
	<-b.release
	return net.ErrClosed
}

func (b *stalledSendBind) Close() error {
	b.once.Do(func() { close(b.release) })
	return nil
}

func TestGuardedBindCloseInterruptsStalledSend(t *testing.T) {
	base := &stalledSendBind{testInterfaceBind: &testInterfaceBind{Bind: conn.NewStdNetBind()},
		started: make(chan struct{}), release: make(chan struct{})}
	b := &guardedBind{Bind: base, binder: base}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	if err := b.BindSocketToInterface4(7, false); err != nil {
		t.Fatal(err)
	}
	ep, err := base.ParseEndpoint("127.0.0.1:51820")
	if err != nil {
		t.Fatal(err)
	}
	sent := make(chan struct{})
	go func() { _ = b.Send([][]byte{{1}}, ep); close(sent) }()
	<-base.started
	closed := make(chan struct{})
	go func() { _ = b.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		// Release the fake send so a failing test also cleans up its goroutines.
		_ = base.Close()
		<-closed
		<-sent
		t.Fatal("Close waited for Send instead of interrupting the native socket")
	}
	<-sent
}

// This fake resets native socket options on Open, as real socket recreation
// does. Send records any datagram that escaped without a bound interface.
type testInterfaceBind struct {
	conn.Bind
	mu     sync.Mutex
	open   bool
	bound  [2]uint32
	fail4  atomic.Bool
	sent   atomic.Int64
	leaked atomic.Int64
	calls  atomic.Int64
}

func (b *testInterfaceBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bound = [2]uint32{}
	b.open = true
	return nil, port, nil
}
func (b *testInterfaceBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bound = [2]uint32{}
	b.open = false
	return nil
}
func (b *testInterfaceBind) Send(_ [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return net.ErrClosed
	}
	family := 0
	if ep.DstIP().Unmap().Is6() {
		family = 1
	}
	if b.bound[family] == 0 {
		b.leaked.Add(1)
	}
	b.sent.Add(1)
	return nil
}
func (b *testInterfaceBind) BindSocketToInterface4(index uint32, blackhole bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls.Add(1)
	if b.fail4.Load() {
		return errors.New("setsockopt failed")
	}
	b.bound[0] = index
	return nil
}
func (b *testInterfaceBind) BindSocketToInterface6(index uint32, blackhole bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls.Add(1)
	b.bound[1] = index
	return nil
}

func newTestGuardedBind(t *testing.T) (*guardedBind, *testInterfaceBind, conn.Endpoint) {
	t.Helper()
	base := &testInterfaceBind{Bind: conn.NewStdNetBind()}
	b := &guardedBind{Bind: base, binder: base}
	ep, err := base.ParseEndpoint("203.0.113.7:51820")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Open(51820); err != nil {
		t.Fatal(err)
	}
	return b, base, ep
}

func TestGuardedBindDropsBeforePinAndAfterPinFailure(t *testing.T) {
	b, base, ep := newTestGuardedBind(t)
	_ = b.Send([][]byte{{1}}, ep)
	if base.sent.Load() != 0 {
		t.Fatal("initial handshake escaped before socket pin")
	}
	if err := b.BindSocketToInterface4(7, false); err != nil {
		t.Fatal(err)
	}
	_ = b.Send([][]byte{{1}}, ep)
	if base.sent.Load() != 1 {
		t.Fatal("protected send was dropped")
	}
	base.fail4.Store(true)
	if err := b.BindSocketToInterface4(8, false); err == nil {
		t.Fatal("binding failure hidden")
	}
	_ = b.Send([][]byte{{1}}, ep)
	if base.sent.Load() != 1 {
		t.Fatal("datagram escaped after failed rebind")
	}
	base.fail4.Store(false)
	if err := b.BindSocketToInterface4(8, false); err != nil {
		t.Fatal(err)
	}
	_ = b.Send([][]byte{{1}}, ep)
	if base.sent.Load() != 2 || base.leaked.Load() != 0 {
		t.Fatal("protection did not recover")
	}
}

func TestGuardedBindReappliesAcrossSocketReopen(t *testing.T) {
	b, base, ep := newTestGuardedBind(t)
	_ = b.BindSocketToInterface4(7, false)
	_ = b.Close()
	_, _, err := b.Open(12345)
	if err != nil {
		t.Fatal(err)
	}
	_ = b.Send([][]byte{{1}}, ep)
	if base.bound[0] != 7 || base.sent.Load() != 1 || base.leaked.Load() != 0 {
		t.Fatal("socket recreation lost interface protection")
	}
	base.fail4.Store(true)
	_ = b.Close()
	_, _, _ = b.Open(23456)
	_ = b.Send([][]byte{{1}}, ep)
	if base.sent.Load() != 1 {
		t.Fatal("reopened socket sent after protection failed")
	}
}

func TestGuardedBindBlackholesOnlyUnavailableFamily(t *testing.T) {
	b, base, ep := newTestGuardedBind(t)
	_ = b.BindSocketToInterface4(0, true)
	_ = b.BindSocketToInterface6(9, false)
	_ = b.Send([][]byte{{1}}, ep)
	v6, err := base.ParseEndpoint("[2001:db8::7]:51820")
	if err != nil {
		t.Fatal(err)
	}
	_ = b.Send([][]byte{{1}}, v6)
	if base.sent.Load() != 1 || base.leaked.Load() != 0 {
		t.Fatal("family blackhole did not isolate unavailable underlay")
	}
}

func TestGuardedBindSerializesSendsWithRebindAndReopen(t *testing.T) {
	b, base, ep := newTestGuardedBind(t)
	_ = b.BindSocketToInterface4(7, false)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 500 {
				_ = b.Send([][]byte{{1}}, ep)
			}
		}()
	}
	for range 50 {
		_ = b.Close()
		_, _, _ = b.Open(0)
		_ = b.BindSocketToInterface4(0, true)
		_ = b.BindSocketToInterface4(7, false)
	}
	wg.Wait()
	if base.leaked.Load() != 0 {
		t.Fatalf("%d unbound datagrams escaped", base.leaked.Load())
	}
}
