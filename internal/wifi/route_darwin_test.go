//go:build darwin

package wifi

import (
	"errors"
	"testing"
	"time"
)

func TestIsWiFiInterface_CachedAndFailSafe(t *testing.T) {
	origOut, origNow := hardwarePortsOutput, routeNow
	defer func() { hardwarePortsOutput, routeNow = origOut, origNow; wifiDevCache.ok = false }()

	now := time.Unix(5000, 0)
	routeNow = func() time.Time { return now }
	wifiDevCache.ok = false
	calls := 0
	hardwarePortsOutput = func() (string, error) {
		calls++
		return "Hardware Port: Wi-Fi\nDevice: en0\n\nHardware Port: USB 10/100 LAN\nDevice: en7\n", nil
	}
	if !IsWiFiInterface("en0") || IsWiFiInterface("en7") {
		t.Fatal("wrong classification")
	}
	if calls != 1 {
		t.Errorf("expected cached lookup, calls=%d", calls)
	}
	now = now.Add(61 * time.Second)
	IsWiFiInterface("en0")
	if calls != 2 {
		t.Errorf("expected refresh after TTL, calls=%d", calls)
	}

	// Failure with a cold cache => treated as Wi-Fi (hold).
	wifiDevCache.ok = false
	hardwarePortsOutput = func() (string, error) { return "", errors.New("boom") }
	if !IsWiFiInterface("en7") {
		t.Error("lookup failure must read as Wi-Fi")
	}
}

func TestDefaultRoute_TunnelIfaceUnknown(t *testing.T) {
	orig := routeGetDefaultOutput
	defer func() { routeGetDefaultOutput = orig }()
	routeGetDefaultOutput = func() (string, error) {
		return "    gateway: 10.0.0.1\n  interface: utun4\n", nil
	}
	gw, iface := DefaultRoute()
	if gw != "10.0.0.1" || iface != "" {
		t.Errorf("got %q %q", gw, iface)
	}
}
