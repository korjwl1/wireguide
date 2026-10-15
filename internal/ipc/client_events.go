package ipc

import (
	"context"
	"fmt"
	"net"
	"time"
)

// A reader retains its own immutable connection/handler pair. Replacing a
// subscription cannot redirect an old reader onto the new connection.
type eventSubscription struct {
	conn    net.Conn
	handler EventHandler
}

// Subscribe replaces the event stream, bounding setup by DefaultCallTimeout.
func (c *Client) Subscribe(handler EventHandler) error {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultCallTimeout)
	defer cancel()
	return c.SubscribeContext(ctx, handler)
}

// SubscribeContext bounds the dial, serialization wait and acknowledgement.
// The context only governs setup; Close or replacement owns a live stream.
func (c *Client) SubscribeContext(ctx context.Context, handler EventHandler) error {
	select {
	case <-c.closed:
		return ErrClientClosed
	case <-ctx.Done():
		return ctx.Err()
	case c.subscribeGate <- struct{}{}:
	}
	defer func() { <-c.subscribeGate }()
	if c.IsClosed() {
		return ErrClientClosed
	}
	conn, err := DialContext(ctx, c.addr)
	if err != nil {
		return fmt.Errorf("dial event conn: %w", err)
	}
	sub := &eventSubscription{conn: conn, handler: handler}
	c.eventMu.Lock()
	if c.IsClosed() {
		c.eventMu.Unlock()
		conn.Close()
		return ErrClientClosed
	}
	previous := c.events
	c.events = sub // Close must also interrupt a pending acknowledgement.
	c.eventMu.Unlock()
	if previous != nil {
		previous.conn.Close()
	}
	if err := acknowledgeSubscription(ctx, conn); err != nil {
		c.releaseSubscription(sub)
		if c.IsClosed() {
			return ErrClientClosed
		}
		return err
	}
	go c.eventLoop(sub)
	return nil
}

func acknowledgeSubscription(ctx context.Context, conn net.Conn) error {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	req, _ := NewRequest(1, MethodSubscribe, nil)
	err := WriteFrame(conn, req)
	var resp Response
	if err == nil {
		err = ReadFrame(conn, &resp)
	}
	stop() // A later caller cancellation must not close the live stream.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("subscribe acknowledgement: %w", err)
	}
	if resp.Error != nil {
		return resp.Error
	}
	if resp.ID != req.ID {
		return fmt.Errorf("subscribe acknowledgement: unexpected response ID %d", resp.ID)
	}
	return conn.SetDeadline(time.Time{})
}

// HasSubscription becomes false when the event stream ends, even if control
// RPCs still work. The GUI health monitor can then repair just this stream.
func (c *Client) HasSubscription() bool {
	c.eventMu.Lock()
	defer c.eventMu.Unlock()
	return c.events != nil && !c.IsClosed()
}

func (c *Client) releaseSubscription(sub *eventSubscription) {
	sub.conn.Close()
	c.eventMu.Lock()
	if c.events == sub {
		c.events = nil
	}
	c.eventMu.Unlock()
}

func (c *Client) eventLoop(sub *eventSubscription) {
	defer c.releaseSubscription(sub)
	for {
		var notif Request
		if err := ReadFrame(sub.conn, &notif); err != nil {
			return
		}
		if sub.handler != nil {
			sub.handler(notif.Method, notif.Params)
		}
	}
}
