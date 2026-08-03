//go:build linux

package reconnect

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// linuxNetworkChangeDetector uses RTNETLINK only as a wake-up source. A
// notification is emitted only when the actual non-tunnel default route
// changes. Address and link chatter is common on Linux (NetworkManager,
// mDNS, IPv6 temporary addresses, and our own TUN setup all generate it), so
// treating every netlink message as an upstream change causes reconnect loops.
type linuxNetworkChangeDetector struct {
	mu           sync.Mutex
	fd           int
	stopCh       chan struct{}
	changeCh     chan struct{}
	running      bool
	lastSnapshot string
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
	d.lastSnapshot = defaultRouteSnapshot()
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
	slog.Info("netlink network-change detector started", "default_route", d.lastSnapshot)
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
		_ = unix.Shutdown(fd, unix.SHUT_RDWR)
		_ = unix.Close(fd)
	}
}

func (d *linuxNetworkChangeDetector) ChangeChan() <-chan struct{} { return d.changeCh }

func (d *linuxNetworkChangeDetector) checkDefaultRoute() {
	now := defaultRouteSnapshot()
	d.mu.Lock()
	previous := d.lastSnapshot
	if now == previous {
		d.mu.Unlock()
		return
	}
	d.lastSnapshot = now
	d.mu.Unlock()

	slog.Info("network primary upstream changed", "previous", previous, "now", now)
	select {
	case d.changeCh <- struct{}{}:
	default:
	}
}

func (d *linuxNetworkChangeDetector) readLoop() {
	buf := make([]byte, 8192)
	for {
		d.mu.Lock()
		running, fd := d.running, d.fd
		d.mu.Unlock()
		if !running {
			return
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			switch err {
			case syscall.EINTR, syscall.EAGAIN:
				continue
			case syscall.ENOBUFS:
				slog.Warn("netlink ENOBUFS; rechecking the default route")
				d.checkDefaultRoute()
				continue
			}
			d.mu.Lock()
			stillRunning := d.running
			d.mu.Unlock()
			if stillRunning {
				slog.Debug("netlink read returned error, stopping", "error", err)
			}
			return
		}
		if n > 0 {
			d.checkDefaultRoute()
		}
	}
}

func defaultRouteSnapshot() string {
	v4, err4 := os.Open("/proc/net/route")
	if err4 == nil {
		defer v4.Close()
	}
	v6, err6 := os.Open("/proc/net/ipv6_route")
	if err6 == nil {
		defer v6.Close()
	}
	return routeSnapshot(v4, v6, func(iface string) bool {
		if iface == "lo" {
			return true
		}
		_, err := os.Stat("/sys/class/net/" + iface + "/tun_flags")
		return err == nil
	})
}

type defaultRoute struct {
	iface   string
	gateway string
	metric  uint64
}

func routeSnapshot(v4, v6 io.Reader, isTunnel func(string) bool) string {
	parts := make([]string, 0, 2)
	if route, ok := bestIPv4Default(v4, isTunnel); ok {
		parts = append(parts, fmt.Sprintf("v4:%s:%s:%d", route.iface, route.gateway, route.metric))
	}
	if route, ok := bestIPv6Default(v6, isTunnel); ok {
		parts = append(parts, fmt.Sprintf("v6:%s:%s:%d", route.iface, route.gateway, route.metric))
	}
	return strings.Join(parts, "|")
}

func bestIPv4Default(r io.Reader, isTunnel func(string) bool) (defaultRoute, bool) {
	var best defaultRoute
	found := false
	if r == nil {
		return best, false
	}
	s := bufio.NewScanner(r)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" || isTunnel(f[0]) {
			continue
		}
		flags, err1 := strconv.ParseUint(f[3], 16, 64)
		metric, err2 := strconv.ParseUint(f[6], 10, 64)
		if err1 != nil || err2 != nil || flags&unix.RTF_UP == 0 {
			continue
		}
		candidate := defaultRoute{iface: f[0], gateway: f[2], metric: metric}
		if !found || candidate.metric < best.metric {
			best, found = candidate, true
		}
	}
	return best, found
}

func bestIPv6Default(r io.Reader, isTunnel func(string) bool) (defaultRoute, bool) {
	var best defaultRoute
	found := false
	if r == nil {
		return best, false
	}
	s := bufio.NewScanner(r)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) < 10 || f[0] != strings.Repeat("0", 32) || f[1] != "00" || f[2] != strings.Repeat("0", 32) || f[3] != "00" || isTunnel(f[9]) {
			continue
		}
		metric, err := strconv.ParseUint(f[5], 16, 64)
		flags, flagsErr := strconv.ParseUint(f[8], 16, 64)
		if err != nil || flagsErr != nil || flags&unix.RTF_UP == 0 {
			continue
		}
		candidate := defaultRoute{iface: f[9], gateway: f[4], metric: metric}
		if !found || candidate.metric < best.metric {
			best, found = candidate, true
		}
	}
	return best, found
}
