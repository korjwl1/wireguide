package ipc

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

// EventHandler is called when an event notification is received.
type EventHandler func(method string, params json.RawMessage)

// Client is an IPC client with a control connection and optional event stream.
type Client struct {
	addr       string
	controlMu  sync.Mutex
	controlConn net.Conn

	eventConn net.Conn
	nextID    uint64

	// Pending requests waiting for responses
	pendingMu sync.Mutex
	pending   map[uint64]chan *Response

	// Reader state
	readerOnce sync.Once
	closed     chan struct{}

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

// Close terminates all connections.
func (c *Client) Close() error {
	select {
	case <-c.closed:
		return nil
	default:
		close(c.closed)
	}
	if c.controlConn != nil {
		c.controlConn.Close()
	}
	if c.eventConn != nil {
		c.eventConn.Close()
	}
	return nil
}

// Call makes an RPC call and waits for response.
func (c *Client) Call(method string, params interface{}, result interface{}) error {
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
	case <-c.closed:
		return fmt.Errorf("client closed")
	case resp := <-respCh:
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
	c.onEvent = handler

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
	defer func() {
		c.pendingMu.Lock()
		for _, ch := range c.pending {
			close(ch)
		}
		c.pending = nil
		c.pendingMu.Unlock()
	}()

	for {
		var resp Response
		if err := ReadFrame(c.controlConn, &resp); err != nil {
			return
		}

		c.pendingMu.Lock()
		ch, ok := c.pending[resp.ID]
		c.pendingMu.Unlock()
		if ok {
			respCopy := resp
			ch <- &respCopy
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
		if c.onEvent != nil {
			c.onEvent(notif.Method, notif.Params)
		}
	}
}
