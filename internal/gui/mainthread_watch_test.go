package gui

import (
	"testing"
	"time"
)

func TestMainThreadWatchStartupStallRecoveryAndSleep(t *testing.T) {
	w := new(mainThreadWatch)
	now := time.Now()
	threshold := 10 * time.Second
	if ping, stall := w.tick(now, 0, threshold); ping != 1 || stall {
		t.Fatal("initial probe")
	}
	for i := 1; i <= 20; i++ {
		if ping, stall := w.tick(now.Add(time.Duration(i)*time.Second), 0, threshold); ping != 0 || stall {
			t.Fatal("startup was diagnosed as a hang or flooded the main queue")
		}
	}
	if ping, stall := w.tick(now.Add(21*time.Second), 1, threshold); ping != 2 || stall {
		t.Fatal("initial acknowledgement")
	}
	for i := 22; i < 31; i++ {
		w.tick(now.Add(time.Duration(i)*time.Second), 1, threshold)
	}
	if _, stall := w.tick(now.Add(31*time.Second), 1, threshold); !stall {
		t.Fatal("sustained main-thread stall was missed")
	}
	if _, stall := w.tick(now.Add(32*time.Second), 1, threshold); stall {
		t.Fatal("same hang was reported repeatedly")
	}
	if ping, stall := w.tick(now.Add(33*time.Second), 2, threshold); ping != 3 || stall {
		t.Fatal("recovery")
	}
	if _, stall := w.tick(now.Add(time.Hour), 2, threshold); stall {
		t.Fatal("sleep/scheduler gap caused a false report")
	}
}
