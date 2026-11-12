package domain

import (
	"sync"
	"testing"
)

func TestCounterEpochSequenceAndParser(t *testing.T) {
	first := NewCounterEpoch()
	owner, sequence, ok := ParseCounterEpoch(first)
	if !ok || owner == "" || sequence == 0 {
		t.Fatalf("invalid generated epoch %q", first)
	}
	next := NewCounterEpoch()
	nextOwner, nextSequence, ok := ParseCounterEpoch(next)
	if !ok || nextOwner != owner || nextSequence <= sequence {
		t.Fatalf("epoch did not advance: %s then %s", first, next)
	}
	for _, invalid := range []string{"", "old-random-token", "wg1..1", "wg1.a.0", "wg1.a.01", "wg1.a.+1", "wg1.a.-1", "wg1.a.1.extra", "wg1.a.18446744073709551616"} {
		if _, _, ok := ParseCounterEpoch(invalid); ok {
			t.Errorf("accepted invalid epoch %q", invalid)
		}
	}
}

func TestCounterEpochConcurrentAllocation(t *testing.T) {
	epochs := make(chan string, 512)
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 64; j++ {
				epochs <- NewCounterEpoch()
			}
		}()
	}
	group.Wait()
	close(epochs)
	seen := map[string]bool{}
	for epoch := range epochs {
		if seen[epoch] {
			t.Fatalf("duplicate epoch %s", epoch)
		}
		seen[epoch] = true
		if _, _, ok := ParseCounterEpoch(epoch); !ok {
			t.Fatal(epoch)
		}
	}
}
