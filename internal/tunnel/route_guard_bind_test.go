package tunnel

import "testing"

func TestRouteGuardDropsWhileEndpointRoutesAreBeingReplaced(t *testing.T) {
	_, base, ep := newTestGuardedBind(t)
	base.bound[0] = 7
	b := &routeGuardBind{Bind: base, allowed: true}
	_ = b.Send([][]byte{{1}}, ep)
	b.SetEndpointTrafficAllowed(false)
	for range 1000 {
		_ = b.Send([][]byte{{1}}, ep)
	}
	if base.sent.Load() != 1 {
		t.Fatal("outer packet escaped during endpoint route replacement")
	}
	b.SetEndpointTrafficAllowed(true)
	_ = b.Send([][]byte{{1}}, ep)
	if base.sent.Load() != 2 {
		t.Fatal("route guard did not resume sending")
	}
}
