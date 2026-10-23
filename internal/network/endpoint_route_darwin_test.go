//go:build darwin

package network

import (
	"errors"
	"net"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLookupEndpointRouteLoopback(t *testing.T) {
	iface, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"127.0.0.1", "::1"} {
		r, err := lookupEndpointRoute(address)
		if err != nil {
			t.Fatalf("lookup %s: %v", address, err)
		}
		if r.index != iface.Index {
			t.Fatalf("lookup %s interface = %d, want lo0 (%d)", address, r.index, iface.Index)
		}
	}
}

func TestEndpointRoutingLoopRequiresPositiveRouteEvidence(t *testing.T) {
	iface, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	original := lookupEndpointRoute
	t.Cleanup(func() { lookupEndpointRoute = original })
	for _, tc := range []struct {
		name          string
		route         endpointRoute
		err           error
		loop, unknown bool
	}{
		{"through own tunnel", endpointRoute{index: iface.Index}, nil, true, false},
		{"physical route even under heavy upload", endpointRoute{index: iface.Index + 1}, nil, false, false},
		{"blackhole is a safe outage", endpointRoute{index: iface.Index, flags: unix.RTF_BLACKHOLE}, nil, false, false},
		{"reject is a safe outage", endpointRoute{index: iface.Index, flags: unix.RTF_REJECT}, nil, false, false},
		{"no route cannot loop", endpointRoute{}, unix.ESRCH, false, false},
		{"unreachable cannot loop", endpointRoute{}, unix.ENETUNREACH, false, false},
		{"query failure is unknown", endpointRoute{}, errors.New("query failed"), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookupEndpointRoute = func(string) (endpointRoute, error) { return tc.route, tc.err }
			allowed := true
			m := &DarwinManager{lastIface: "lo0", endpointTrafficGuard: func(value bool) { allowed = value }}
			reason, err := m.EndpointRoutingLoop([]string{"203.0.113.7"})
			if (reason != "") != tc.loop || (err != nil) != tc.unknown {
				t.Fatalf("reason=%q err=%v", reason, err)
			}
			if allowed != (!tc.loop && !tc.unknown) {
				t.Fatalf("unsafe/unknown route send gate allowed=%t", allowed)
			}
		})
	}
}

func TestFailedEndpointRepairKeepsOuterTrafficBlockedUntilVerified(t *testing.T) {
	iface, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	oldRun, oldLookup, oldGateway := run, lookupEndpointRoute, getDefaultGatewayFor
	t.Cleanup(func() { run = oldRun; lookupEndpointRoute = oldLookup; getDefaultGatewayFor = oldGateway })
	run = func(string, ...string) error { return errors.New("route mutation failed") }
	getDefaultGatewayFor = func(ipv6 bool) (string, error) {
		if ipv6 {
			return "", nil
		}
		return "192.0.2.1", nil
	}
	current := endpointRoute{index: iface.Index}
	lookupEndpointRoute = func(string) (endpointRoute, error) { return current, nil }
	allowed := true
	m := &DarwinManager{lastIface: "lo0", lastEndpoints: []string{"203.0.113.7"}, lastHasV4Default: true,
		lastGatewayV4: "192.0.2.1", endpointTrafficGuard: func(value bool) { allowed = value }}
	m.reapply()
	if allowed {
		t.Fatal("failed bypass and blackhole install resumed unsafe outer sends")
	}
	current.index = iface.Index + 1
	reason, err := m.EndpointRoutingLoop([]string{"203.0.113.7"})
	if reason != "" || err != nil || !allowed {
		t.Fatalf("safe route did not recover sends: %q %v allowed=%t", reason, err, allowed)
	}
}

func TestReapplyKeepsExistingBlackholeWithoutUnderlay(t *testing.T) {
	iface, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	oldRun, oldLookup, oldGateway := run, lookupEndpointRoute, getDefaultGatewayFor
	t.Cleanup(func() { run = oldRun; lookupEndpointRoute = oldLookup; getDefaultGatewayFor = oldGateway })
	run = func(string, ...string) error { t.Fatal("unchanged blackhole generated more route events"); return nil }
	getDefaultGatewayFor = func(bool) (string, error) { return "", nil }
	lookupEndpointRoute = func(string) (endpointRoute, error) {
		return endpointRoute{index: iface.Index, flags: unix.RTF_BLACKHOLE}, nil
	}
	m := &DarwinManager{lastIface: "lo0", lastEndpoints: []string{"203.0.113.7"}, lastHasV4Default: true}
	m.reapply()
}

func TestReapplyRepairsEndpointRouteWithUnchangedGateway(t *testing.T) {
	iface, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	oldRun, oldLookup, oldGateway := run, lookupEndpointRoute, getDefaultGatewayFor
	t.Cleanup(func() { run = oldRun; lookupEndpointRoute = oldLookup; getDefaultGatewayFor = oldGateway })
	getDefaultGatewayFor = func(ipv6 bool) (string, error) {
		if ipv6 {
			return "", nil
		}
		return "192.0.2.1", nil
	}
	for _, flags := range []int{0, unix.RTF_BLACKHOLE} {
		current := endpointRoute{index: iface.Index, flags: flags}
		lookupEndpointRoute = func(string) (endpointRoute, error) { return current, nil }
		var calls []string
		allowed, deleted := true, false
		run = func(name string, args ...string) error {
			if allowed {
				t.Fatal("route mutation ran while outer UDP sends were allowed")
			}
			call := name + " " + strings.Join(args, " ")
			calls = append(calls, call)
			if strings.Contains(call, " delete ") {
				deleted = true
				current = endpointRoute{index: iface.Index}
				return nil
			}
			if strings.Contains(call, " add ") {
				if !deleted {
					return errors.New("route exists")
				}
				current = endpointRoute{index: iface.Index + 1}
				return nil
			}
			// Darwin's RTM_CHANGE preserves existing BLACKHOLE flags.
			current.index = iface.Index + 1
			return nil
		}
		m := &DarwinManager{lastIface: "lo0", lastEndpoints: []string{"203.0.113.7"},
			bypassEndpoints: []string{"203.0.113.7"}, lastHasV4Default: true, lastGatewayV4: "192.0.2.1",
			endpointTrafficGuard: func(value bool) { allowed = value }}
		m.reapply()
		if len(calls) != 2 || current.blocksTraffic() || !allowed {
			t.Fatalf("repair did not restore a safe usable route: %v, route=%+v allowed=%t", calls, current, allowed)
		}
		for _, call := range calls {
			if flags == 0 && strings.Contains(call, " delete ") {
				t.Fatalf("repair opened a delete/add gap: %v", calls)
			}
		}
		if len(m.bypassEndpoints) != 1 {
			t.Fatalf("bypass tracking duplicated: %v", m.bypassEndpoints)
		}
		m.reapply()
		if len(calls) != 2 {
			t.Fatalf("healthy unchanged route was rewritten: %v", calls)
		}
	}
}
