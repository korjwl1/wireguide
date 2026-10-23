//go:build darwin

package network

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

type endpointRoute struct {
	index int
	flags int
}

var routeQuerySequence atomic.Uint32

// lookupEndpointRoute asks the kernel for its actual unscoped forwarding
// decision. RTM_GET avoids spawning route(8) for every watchdog sample.
// A failed lookup is unknown, never evidence of a loop.
var lookupEndpointRoute = func(address string) (endpointRoute, error) {
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return endpointRoute{}, err
	}
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return endpointRoute{}, err
	}
	defer unix.Close(fd)
	unix.CloseOnExec(fd)
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		return endpointRoute{}, err
	}
	addrs := make([]route.Addr, unix.RTAX_MAX)
	if ip.Is4() {
		addrs[unix.RTAX_DST] = &route.Inet4Addr{IP: ip.As4()}
	} else {
		addrs[unix.RTAX_DST] = &route.Inet6Addr{IP: ip.As16()}
	}
	seq := int(routeQuerySequence.Add(1))
	req := route.RouteMessage{Version: unix.RTM_VERSION, Type: unix.RTM_GET,
		ID: uintptr(os.Getpid()), Seq: seq, Addrs: addrs}
	data, err := req.Marshal()
	if err != nil {
		return endpointRoute{}, err
	}
	if _, err := unix.Write(fd, data); err != nil {
		return endpointRoute{}, err
	}
	deadline := time.Now().Add(time.Second)
	var buf [8192]byte
	for time.Now().Before(deadline) {
		n, err := unix.Read(fd, buf[:])
		if err != nil {
			return endpointRoute{}, err
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, buf[:n])
		if err != nil {
			return endpointRoute{}, err
		}
		for _, message := range messages {
			response, ok := message.(*route.RouteMessage)
			if !ok || response.Type != unix.RTM_GET || response.ID != req.ID || response.Seq != seq {
				continue
			}
			if response.Err != nil {
				return endpointRoute{}, response.Err
			}
			return endpointRoute{index: response.Index, flags: response.Flags}, nil
		}
	}
	return endpointRoute{}, fmt.Errorf("endpoint route lookup timed out")
}

func (r endpointRoute) loopsThrough(index int) bool {
	return index != 0 && r.index == index && !r.blocksTraffic()
}

func (r endpointRoute) blocksTraffic() bool {
	return r.flags&(unix.RTF_BLACKHOLE|unix.RTF_REJECT) != 0
}

func endpointRouteMissing(err error) bool {
	return errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH)
}

// EndpointRoutingLoop reports a verified recursive endpoint route. Missing
// routes, blackholes and query failures never count as a detected loop.
func (m *DarwinManager) EndpointRoutingLoop(endpoints []string) (string, error) {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	reason, err := m.endpointRoutingLoop(endpoints)
	if m.endpointTrafficGuard != nil {
		m.endpointTrafficGuard(reason == "" && err == nil)
	}
	return reason, err
}

func (m *DarwinManager) SetEndpointTrafficGuard(allow func(bool)) {
	m.endpointTrafficGuard = allow
}

func (m *DarwinManager) endpointRoutingLoop(endpoints []string) (string, error) {
	m.mu.Lock()
	ifaceName := m.lastIface
	m.mu.Unlock()
	if ifaceName == "" {
		return "", nil
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", err
	}
	var queryErr error
	for _, endpoint := range endpoints {
		r, err := lookupEndpointRoute(endpoint)
		if endpointRouteMissing(err) {
			continue // no route can carry a recursive packet
		}
		if err != nil {
			queryErr = err
			continue
		}
		if r.loopsThrough(iface.Index) {
			return fmt.Sprintf("endpoint %s routes back through %s", endpoint, ifaceName), nil
		}
	}
	return "", queryErr
}
