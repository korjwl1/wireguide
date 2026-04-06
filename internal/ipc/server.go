package ipc

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Handler processes an RPC request and returns a result or error.
type Handler func(params json.RawMessage) (interface{}, error)

// Server is an IPC server that dispatches RPC requests to handlers
// and broadcasts events to subscribed clients.
type Server struct {
	listener net.Listener
	handlers map[string]Handler
	ownerUID int // expected peer UID on Unix (-1 to skip check)

	mu           sync.Mutex
	eventSubs    map[*subscriber]struct{} // active event subscribers
	shutdownCh   chan struct{}
	onConnect    func() // called when a control conn attaches (any)
	onDisconnect func() // called when the last control conn closes
	controlConns map[net.Conn]struct{}
}

type subscriber struct {
	conn net.Conn
	ch   chan []byte
}

// NewServer creates a server. ownerUID is the expected UID of connecting
// peers on Unix (pass -1 to skip peer credential checks, e.g. in tests).
func NewServer(listener net.Listener, ownerUID ...int) *Server {
	uid := -1
	if len(ownerUID) > 0 {
		uid = ownerUID[0]
	}
	return &Server{
		listener:     listener,
		handlers:     make(map[string]Handler),
		ownerUID:     uid,
		eventSubs:    make(map[*subscriber]struct{}),
		shutdownCh:   make(chan struct{}),
		controlConns: make(map[net.Conn]struct{}),
	}
}

// Handle registers an RPC handler for the given method.
func (s *Server) Handle(method string, h Handler) {
	s.mu.Lock()
	s.handlers[method] = h
	s.mu.Unlock()
}

// OnConnect sets a callback fired whenever a control connection attaches.
// Used by the helper to cancel a pending grace-window shutdown when the GUI
// reconnects within the window.
func (s *Server) OnConnect(fn func()) {
	s.mu.Lock()
	s.onConnect = fn
	s.mu.Unlock()
}

// OnDisconnect sets a callback fired when the last control connection closes.
func (s *Server) OnDisconnect(fn func()) {
	s.mu.Lock()
	s.onDisconnect = fn
	s.mu.Unlock()
}

// Serve accepts connections until the listener is closed.
func (s *Server) Serve() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.shutdownCh:
				return nil
			default:
				return err
			}
		}
		go s.handleConn(conn)
	}
}

// Shutdown stops the server.
func (s *Server) Shutdown() {
	select {
	case <-s.shutdownCh:
	default:
		close(s.shutdownCh)
	}
	s.listener.Close()

	s.mu.Lock()
	for sub := range s.eventSubs {
		sub.conn.Close()
	}
	for c := range s.controlConns {
		c.Close()
	}
	s.mu.Unlock()
}

// Broadcast sends an event notification to all subscribers.
func (s *Server) Broadcast(method string, params interface{}) {
	notif, err := NewNotification(method, params)
	if err != nil {
		slog.Warn("failed to build notification", "error", err)
		return
	}
	data, err := json.Marshal(notif)
	if err != nil {
		return
	}

	s.mu.Lock()
	subs := make([]*subscriber, 0, len(s.eventSubs))
	for sub := range s.eventSubs {
		subs = append(subs, sub)
	}
	s.mu.Unlock()

	for _, sub := range subs {
		select {
		case sub.ch <- data:
		default:
			// Drop event if subscriber is slow (prevents helper from blocking)
		}
	}
}

// handleConn processes one connection. The first request determines if this
// is a control connection (regular RPC) or an event stream (after Subscribe).
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	// Verify the connecting process belongs to the expected owner.
	if err := verifyPeerUID(conn, s.ownerUID); err != nil {
		slog.Warn("ipc: rejecting connection: peer credential check failed", "error", err)
		return
	}

	remoteDesc := fmt.Sprintf("%p", conn)
	isControl := false
	defer func() {
		if isControl {
			s.mu.Lock()
			delete(s.controlConns, conn)
			remaining := len(s.controlConns)
			fn := s.onDisconnect
			s.mu.Unlock()
			slog.Info("ipc: control conn closed",
				"conn", remoteDesc,
				"remaining", remaining)
			if remaining == 0 && fn != nil {
				fn()
			}
		} else {
			slog.Debug("ipc: non-control conn closed", "conn", remoteDesc)
		}
	}()

	const readDeadline = 60 * time.Second
	for {
		if tc, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = tc.SetReadDeadline(time.Now().Add(readDeadline))
		}
		var req Request
		if err := ReadFrame(conn, &req); err != nil {
			slog.Debug("ipc: ReadFrame error, closing conn",
				"conn", remoteDesc,
				"is_control", isControl,
				"error", err)
			return // connection closed or read deadline exceeded
		}

		if req.Method == MethodSubscribe {
			// Upgrade this connection to an event stream
			slog.Debug("ipc: upgrading to event stream", "conn", remoteDesc)
			s.handleSubscribe(conn, req.ID)
			return // handleSubscribe takes over the connection
		}

		if !isControl {
			isControl = true
			s.mu.Lock()
			s.controlConns[conn] = struct{}{}
			count := len(s.controlConns)
			fn := s.onConnect
			s.mu.Unlock()
			slog.Info("ipc: new control conn",
				"conn", remoteDesc,
				"count", count,
				"first_method", req.Method)
			if fn != nil {
				fn()
			}
		}

		// Dispatch RPC
		resp := s.dispatch(&req)
		if resp != nil && !req.IsNotification() {
			if err := WriteFrame(conn, resp); err != nil {
				slog.Debug("ipc: WriteFrame error, closing conn",
					"conn", remoteDesc,
					"error", err)
				return
			}
		}
	}
}

func (s *Server) dispatch(req *Request) *Response {
	s.mu.Lock()
	handler, ok := s.handlers[req.Method]
	s.mu.Unlock()
	if !ok {
		return NewErrorResponse(req.ID, ErrCodeMethodNotFound, "method not found: "+req.Method)
	}

	result, err := handler(req.Params)
	if err != nil {
		code := ErrCodeAppError
		if ce, ok := err.(*CodedError); ok {
			code = ce.Code
		}
		return NewErrorResponse(req.ID, code, err.Error())
	}

	resp, marshalErr := NewResponse(req.ID, result)
	if marshalErr != nil {
		return NewErrorResponse(req.ID, ErrCodeInternalError, marshalErr.Error())
	}
	return resp
}

// handleSubscribe takes over a connection as an event stream.
func (s *Server) handleSubscribe(conn net.Conn, reqID uint64) {
	sub := &subscriber{
		conn: conn,
		ch:   make(chan []byte, 32),
	}

	s.mu.Lock()
	s.eventSubs[sub] = struct{}{}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.eventSubs, sub)
		s.mu.Unlock()
		// Do NOT close sub.ch — a concurrent Broadcast may still be trying to
		// send to it (it copies the subs list outside the lock). Sending to a
		// closed channel panics. The channel will be GC'd once both the
		// subscriber and the last Broadcast referencing it are done.
	}()

	// Acknowledge subscription
	ack, _ := NewResponse(reqID, Empty{})
	if err := WriteFrame(conn, ack); err != nil {
		return
	}

	// Pump events to this subscriber
	for {
		select {
		case <-s.shutdownCh:
			return
		case data, ok := <-sub.ch:
			if !ok {
				return
			}
			if _, err := conn.Write(frameBytes(data)); err != nil {
				return
			}
		}
	}
}

// frameBytes prepends the 4-byte length prefix.
func frameBytes(data []byte) []byte {
	buf := make([]byte, 4+len(data))
	buf[0] = byte(len(data) >> 24)
	buf[1] = byte(len(data) >> 16)
	buf[2] = byte(len(data) >> 8)
	buf[3] = byte(len(data))
	copy(buf[4:], data)
	return buf
}
