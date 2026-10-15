package reconnect

import (
	"testing"
	"time"
)

func TestInterfaceCooldownRetainsFinalChange(t *testing.T) {
	g := interfaceChangeGate{cooldown: 2 * time.Second}
	now := time.Unix(100, 0)
	if g.observe("en0", now) {
		t.Fatal("initial observation is not a change")
	}
	if !g.observe("en5", now.Add(time.Second)) {
		t.Fatal("first change was lost")
	}
	if g.observe("en0", now.Add(2*time.Second)) {
		t.Fatal("rapid flap bypassed cooldown")
	}
	if !g.observe("en0", now.Add(3*time.Second)) {
		t.Fatal("stable final interface change was discarded")
	}
	if g.observe("en0", now.Add(4*time.Second)) {
		t.Fatal("unchanged interface retriggered recovery")
	}
}
