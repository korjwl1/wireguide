package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// EventHandler is called when an event notification is received.
type EventHandler func(method string, params json.RawMessage)

// DefaultCallTimeout is the default timeout for RPC calls when no context is provided.
const DefaultCallTimeout = 10 * time.Second

// Client is an IPC client with a control connection and optional event stream.
type Client struct {
	addr        string
	controlMu   sync.Mutex
	controlConn net.Conn

	eventConn net.Conn
	nextID    uint64

	// Pending requests waiting for responses
	pendingMu sync.Mutex
	pending   map[uint64]chan *Response

	// Lifecycle
	closeOnce sync.Once
	closed    chan struct{}

	// eventMu guards onEvent so that Subscribe (writer) and eventLoop (reader)
	// can't race if Subscribe is ever called more than once on the same Client
	// (shouldn't happen in current usage — helper reconnect creates a fresh
	// Client — but defensive).
	eventMu sync.Mutex
	onEvent EventHandler
}

// NewClient creates a client connected to addr.
func NewClient(addr string) (*Client, error) {
	conn, err := Dial(addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	c := &Client{
		addr:        addr,
		controlConn: conn,
		pending:     make(map[uint64]chan *Response),
		closed:      make(chan struct{}),
	}

	go c.readLoop()
	return c, nil
}

// Close terminates all connections. Safe to call multiple times.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		// Log caller so we can tell WHY a client was closed — shutdown,
		// health-monitor swap, or something unexpected.
		slog.Info("ipc client: Close() called", "addr", c.addr)
		close(c.closed)
		if c.controlConn != nil {
			c.controlConn.Close()
		}
		if c.eventConn != nil {
			c.eventConn.Close()
		}
	})
	return nil
}

// IsClosed reports whether the client has been closed.
func (c *Client) IsClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// Call makes an RPC call with the default timeout.
func (c *Client) Call(method string, params interface{}, result interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultCallTimeout)
	defer cancel()
	return c.CallWithContext(ctx, method, params, result)
}

// CallWithContext makes an RPC call with explicit context for cancellation/timeout.
func (c *Client) CallWithContext(ctx context.Context, method string, params interface{}, result interface{}) error {
	if c.IsClosed() {
		return fmt.Errorf("client closed")
	}

	id := atomic.AddUint64(&c.nextID, 1)
	req, err := NewRequest(id, method, params)
	if err != nil {
		return err
	}

	respCh := make(chan *Response, 1)
	c.pendingMu.Lock()
	c.pending[id] = respCh
	c.pendingMu.Unlock()

	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
	}()

	c.controlMu.Lock()
	err = WriteFrame(c.controlConn, req)
	c.controlMu.Unlock()
	if err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closed:
		return fmt.Errorf("client closed")
	case resp, ok := <-respCh:
		if !ok {
			return fmt.Errorf("client closed")
		}
		if resp.Error != nil {
			return resp.Error
		}
		if result != nil && len(resp.Result) > 0 {
			return json.Unmarshal(resp.Result, result)
		}
		return nil
	}
}

// Subscribe opens a second connection and subscribes to events.
// The handler is called for each event notification received.
func (c *Client) Subscribe(handler EventHandler) error {
	c.eventMu.Lock()
	c.onEvent = handler
	c.eventMu.Unlock()

	conn, err := Dial(c.addr)
	if err != nil {
		return fmt.Errorf("dial event conn: %w", err)
	}
	c.eventConn = conn

	// Send subscribe request (use ID=1 on event conn)
	req, _ := NewRequest(1, MethodSubscribe, nil)
	if err := WriteFrame(conn, req); err != nil {
		conn.Close()
		return err
	}

	// Read ack
	var resp Response
	if err := ReadFrame(conn, &resp); err != nil {
		conn.Close()
		return err
	}
	if resp.Error != nil {
		conn.Close()
		return resp.Error
	}

	go c.eventLoop()
	return nil
}

func (c *Client) readLoop() {
	var exitErr error
	defer func() {
		slog.Debug("ipc client: readLoop exiting", "addr", c.addr, "error", exitErr)
		c.pendingMu.Lock()
		for _, ch := range c.pending {
			close(ch)
		}
		c.pending = make(map[uint64]chan *Response) // reset, don't set to nil
		c.pendingMu.Unlock()
	}()

	for {
		var resp Response
		if err := ReadFrame(c.controlConn, &resp); err != nil {
			exitErr = err
			return
		}

		c.pendingMu.Lock()
		ch, ok := c.pending[resp.ID]
		c.pendingMu.Unlock()
		if ok {
			respCopy := resp
			select {
			case ch <- &respCopy:
			default:
				// Receiver gave up (timeout); drop
			}
		}
	}
}

func (c *Client) eventLoop() {
	for {
		data, err := ReadFrameRaw(c.eventConn)
		if err != nil {
			return
		}
		var notif Request
		if err := json.Unmarshal(data, &notif); err != nil {
			continue
		}
		c.eventMu.Lock()
		handler := c.onEvent
		c.eventMu.Unlock()
		if handler != nil {
			handler(notif.Method, notif.Params)
		}
	}
}
