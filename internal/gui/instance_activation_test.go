package gui

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestRelaunchWaitsForWindowReadyThenActivatesAgain(t *testing.T) {
	requests, ready, done := make(chan struct{}, 1), make(chan struct{}), make(chan struct{})
	activated, finished := make(chan struct{}, 2), make(chan struct{})
	go func() {
		waitInstanceActivations(requests, ready, done, func() { activated <- struct{}{} })
		close(finished)
	}()
	requests <- struct{}{}
	select {
	case <-activated:
		t.Fatal("activated before WebView was ready")
	case <-time.After(20 * time.Millisecond):
	}
	close(ready)
	select {
	case <-activated:
	case <-time.After(time.Second):
		t.Fatal("lost relaunch during startup")
	}
	requests <- struct{}{}
	select {
	case <-activated:
	case <-time.After(time.Second):
		t.Fatal("later relaunch did not focus window")
	}
	close(done)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("activation loop did not stop")
	}
}

func TestQuitBeforeWindowReadyDoesNotReopenWindow(t *testing.T) {
	requests, ready, done := make(chan struct{}, 1), make(chan struct{}), make(chan struct{})
	requests <- struct{}{}
	close(done)
	close(ready)
	var calls atomic.Int32
	waitInstanceActivations(requests, ready, done, func() { calls.Add(1) })
	if calls.Load() != 0 {
		t.Fatal("reopened window during quit")
	}
}
