//go:build linux

package reconnect

import (
	"log/slog"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// linuxNetworkChangeDetector subscribes to the kernel's RTNETLINK multicast
// groups for route, address, and link transitions on the underlying
// interfaces. When a relevant event fires we coalesce a burst into a single
// notification on ChangeChan (500ms debounce). The reconnect monitor then
// triggers a per-tunnel reconnect, instead of waiting up to 40s for the
// generic sleep/wake heuristic to notice.
//
// We DO NOT use NetworkManager DBus here — that would tie us to NM, which
// not every distro ships (Alpine/Arch headless). Raw netlink works on any
// kernel with CONFIG_RTNETLINK (i.e. every modern Linux).
type linuxNetworkChangeDetector struct {
	mu      sync.Mutex
	fd      int
	stopCh  chan struct{}
	changeCh chan struct{}
	running bool
}

func NewNetworkChangeDetector() NetworkChangeDetector {
	return &linuxNetworkChangeDetector{}
}

func (d *linuxNetworkChangeDetector) Start() {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return
	}
	d.stopCh = make(chan struct{})
	d.changeCh = make(chan struct{}, 1)
	d.running = true
	d.mu.Unlock()

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		slog.Warn("netlink socket open failed; falling back to no-op detector", "error", err)
		d.mu.Lock()
		d.running = false
		d.mu.Unlock()
		return
	}
	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_LINK |
			unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV4_IFADDR |
			unix.RTMGRP_IPV6_ROUTE | unix.RTMGRP_IPV6_IFADDR,
	}
	if err := unix.Bind(fd, addr); err != nil {
		slog.Warn("netlink bind failed", "error", err)
		_ = unix.Close(fd)
		d.mu.Lock()
		d.running = false
		d.mu.Unlock()
		return
	}
	d.mu.Lock()
	d.fd = fd
	d.mu.Unlock()
	go d.readLoop()
	slog.Info("netlink network-change detector started")
}

func (d *linuxNetworkChangeDetector) Stop() {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return
	}
	d.running = false
	fd := d.fd
	stop := d.stopCh
	d.mu.Unlock()

	select {
	case <-stop:
	default:
		close(stop)
	}
	if fd != 0 {
		// Shutdown unblocks the recvfrom in readLoop.
		_ = unix.Shutdown(fd, unix.SHUT_RDWR)
		_ = unix.Close(fd)
	}
}

func (d *linuxNetworkChangeDetector) ChangeChan() <-chan struct{} {
	return d.changeCh
}

// readLoop drains netlink messages. Every message we receive that isn't a
// trivial NLMSG_DONE/NLMSG_ERROR is treated as "topology changed" — we don't
// try to filter by message type because any of our subscribed groups
// firing implies a route/address/link change worth re-checking.
//
// Error handling per man netlink(7):
//   - EINTR / EAGAIN / EWOULDBLOCK: transient; keep going.
//   - ENOBUFS: kernel ran out of receive buffer and dropped messages —
//     we may have missed an RTM event. Fire a single "force" signal so
//     the reconnect monitor re-evaluates, then continue reading.
//   - Anything else (EBADF on shutdown, etc.): exit cleanly.
func (d *linuxNetworkChangeDetector) readLoop() {
	buf := make([]byte, 8192)
	for {
		d.mu.Lock()
		running := d.running
		fd := d.fd
		d.mu.Unlock()
		if !running {
			return
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			switch err {
			// EAGAIN == EWOULDBLOCK on Linux; listing one is enough.
			case syscall.EINTR, syscall.EAGAIN:
				continue
			case syscall.ENOBUFS:
				slog.Warn("netlink ENOBUFS — kernel dropped messages, forcing reconnect check")
				select {
				case d.changeCh <- struct{}{}:
				default:
				}
				continue
			}
			// EBADF / ENOTCONN are expected during shutdown.
			d.mu.Lock()
			stillRunning := d.running
			d.mu.Unlock()
			if stillRunning {
				slog.Debug("netlink read returned error, stopping", "error", err)
			}
			return
		}
		if n <= 0 {
			continue
		}
		// Signal the debouncer non-blockingly.
		select {
		case d.changeCh <- struct{}{}:
		default:
			// Coalesce: a notification is already pending.
		}
	}
}

// Note on coalescing: the readLoop sends directly to changeCh (cap 1)
// non-blockingly. If multiple RTM messages arrive in quick succession
// only the first one is delivered until a consumer drains the channel —
// the cap-1 buffer already implements "edge-triggered, single pending
// notification" coalescing. The reconnect monitor downstream runs each
// reconnect under its own backoff, so a separate debouncer goroutine
// inside this detector adds no value.
