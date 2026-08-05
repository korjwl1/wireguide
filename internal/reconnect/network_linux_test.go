//go:build linux

package reconnect

import (
	"strings"
	"testing"
)

func TestRouteSnapshotIgnoresNoiseAndTunnelDefaults(t *testing.T) {
	v4 := `Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
wlan0 00000000 0101A8C0 0003 0 0 600 00000000 0 0 0
wg-demo 00000000 00000000 0001 0 0 0 00000000 0 0 0
wlan0 0001A8C0 00000000 0001 0 0 600 00FFFFFF 0 0 0
`
	v6 := `00000000000000000000000000000000 00 00000000000000000000000000000000 00 FE800000000000000001000000000001 00000400 00000000 00000000 00000003 wlan0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 00000001 wg-demo
`
	isTunnel := func(name string) bool { return name == "wg-demo" }
	got := routeSnapshot(strings.NewReader(v4), strings.NewReader(v6), isTunnel)
	want := "v4:wlan0:0101A8C0:600|v6:wlan0:FE800000000000000001000000000001:1024"
	if got != want {
		t.Fatalf("routeSnapshot() = %q, want %q", got, want)
	}
}

func TestRouteSnapshotChangesOnlyForDefaultRouteState(t *testing.T) {
	base := `Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
wlan0 00000000 0101A8C0 0003 0 0 600 00000000 0 0 0
`
	withAddressRouteNoise := base + "wlan0 0001A8C0 00000000 0001 0 0 600 00FFFFFF 0 0 0\n"
	changedGateway := strings.Replace(base, "0101A8C0", "FE01A8C0", 1)
	none := func(string) bool { return false }
	a := routeSnapshot(strings.NewReader(base), nil, none)
	b := routeSnapshot(strings.NewReader(withAddressRouteNoise), nil, none)
	c := routeSnapshot(strings.NewReader(changedGateway), nil, none)
	if a != b {
		t.Fatalf("non-default route noise changed snapshot: %q != %q", a, b)
	}
	if a == c {
		t.Fatalf("gateway change did not change snapshot: %q", a)
	}
}
