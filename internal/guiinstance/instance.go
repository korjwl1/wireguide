// Package guiinstance reserves the Windows GUI before any helper or tray work.
package guiinstance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	activateRequest  byte = 1
	activateAccepted byte = 1
	activateClosing  byte = 2
	contactTimeout        = 5 * time.Second
	handshakeTimeout      = time.Second
)

var errClosing = errors.New("existing GUI is shutting down")

// Instance owns the activation listener for the entire GUI lifetime. Requests
// are coalesced and buffered, including while helper authorization is pending.
type Instance struct {
	listener net.Listener
	requests chan struct{}
	done     chan struct{}
	closing  atomic.Bool
	once     sync.Once
	mu       sync.Mutex
	active   net.Conn
	wg       sync.WaitGroup
}

func newInstance(l net.Listener) *Instance {
	i := &Instance{listener: l, done: make(chan struct{})}
	if l != nil {
		i.requests = make(chan struct{}, 1)
		i.wg.Add(1)
		go i.serve()
	}
	return i
}

func (i *Instance) Requests() <-chan struct{} { return i.requests }
func (i *Instance) Done() <-chan struct{}     { return i.done }

// BeginShutdown rejects activation but retains the reservation until Close,
// so a new GUI cannot start alongside the old helper's teardown.
func (i *Instance) BeginShutdown() { i.closing.Store(true) }

func (i *Instance) Close() {
	i.once.Do(func() {
		i.BeginShutdown()
		close(i.done)
		if i.listener != nil {
			_ = i.listener.Close()
		}
		i.mu.Lock()
		if i.active != nil {
			_ = i.active.Close()
		}
		i.mu.Unlock()
		i.wg.Wait()
	})
}

func (i *Instance) serve() {
	defer i.wg.Done()
	for {
		c, err := i.listener.Accept()
		if err != nil {
			return
		}
		i.mu.Lock()
		select {
		case <-i.done:
			i.mu.Unlock()
			_ = c.Close()
			return
		default:
		}
		i.active = c
		i.mu.Unlock()
		i.handle(c)
		_ = c.Close()
		i.mu.Lock()
		i.active = nil
		i.mu.Unlock()
	}
}

func (i *Instance) handle(c net.Conn) {
	if c.SetDeadline(time.Now().Add(handshakeTimeout)) != nil {
		return
	}
	var request [1]byte
	if _, err := io.ReadFull(c, request[:]); err != nil || request[0] != activateRequest {
		return
	}
	if i.closing.Load() {
		_, _ = c.Write([]byte{activateClosing})
		return
	}
	select {
	case i.requests <- struct{}{}:
	default:
	}
	_, _ = c.Write([]byte{activateAccepted})
}

func notify(ctx context.Context, c net.Conn, grantForeground func(net.Conn) error) error {
	defer c.Close()
	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := c.SetDeadline(deadline); err != nil {
		return err
	}
	if err := grantForeground(c); err != nil {
		return err
	}
	if _, err := c.Write([]byte{activateRequest}); err != nil {
		return err
	}
	var reply [1]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		return err
	}
	switch reply[0] {
	case activateAccepted:
		return nil
	case activateClosing:
		return errClosing
	default:
		return fmt.Errorf("unexpected GUI activation response %d", reply[0])
	}
}

// acquire retries the exclusive listener reservation and activation handshake
// together. If the previous process exits during contact, the next iteration
// can become the new primary. A failed contact never creates a second GUI.
func acquire(ctx context.Context, listen func() (net.Listener, error), dial func(context.Context) (net.Conn, error), grantForeground func(net.Conn) error) (*Instance, error) {
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("cannot activate existing WireGuide window: %w (%v)", err, lastErr)
		}
		l, err := listen()
		if err == nil {
			return newInstance(l), nil
		}
		lastErr = err
		c, err := dial(ctx)
		if err == nil {
			err = notify(ctx, c, grantForeground)
			if err == nil {
				return nil, nil
			}
		}
		lastErr = err
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}
