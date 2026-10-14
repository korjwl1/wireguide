package guiinstance

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func testInstance(t *testing.T) *Instance {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	i := newInstance(l)
	t.Cleanup(i.Close)
	return i
}

func contact(i *Instance) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", i.listener.Addr().String())
	if err != nil {
		return err
	}
	return notify(ctx, c, func(net.Conn) error { return nil })
}

func TestActivationIsBufferedAndCoalescedDuringStartup(t *testing.T) {
	i := testInstance(t)
	for n := 0; n < 10; n++ {
		if err := contact(i); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-i.Requests():
	case <-time.After(time.Second):
		t.Fatal("startup activation lost")
	}
	select {
	case <-i.Requests():
		t.Fatal("duplicate launches were not coalesced")
	default:
	}
	if err := contact(i); err != nil {
		t.Fatal(err)
	}
	select {
	case <-i.Requests():
	case <-time.After(time.Second):
		t.Fatal("later activation lost")
	}
}

func TestClosingRejectsActivationButKeepsReservation(t *testing.T) {
	i := testInstance(t)
	i.BeginShutdown()
	if err := contact(i); !errors.Is(err, errClosing) {
		t.Fatalf("closing contact: %v", err)
	}
	select {
	case <-i.Requests():
		t.Fatal("closing window activated")
	default:
	}
	select {
	case <-i.Done():
		t.Fatal("reservation released before teardown completed")
	default:
	}
	i.Close()
	i.Close()
	select {
	case <-i.Done():
	default:
		t.Fatal("close did not signal completion")
	}
}

func TestCloseInterruptsSilentClient(t *testing.T) {
	i := testInstance(t)
	c, err := net.Dial("tcp", i.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Wait for acceptance without sending an activation request.
	deadline := time.Now().Add(time.Second)
	for {
		i.mu.Lock()
		accepted := i.active != nil
		i.mu.Unlock()
		if accepted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not accepted")
		}
		time.Sleep(time.Millisecond)
	}
	done := make(chan struct{})
	go func() { i.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("close waited for client deadline")
	}
}

func TestConcurrentSecondLaunchesOnlyActivate(t *testing.T) {
	i := testInstance(t)
	var wg sync.WaitGroup
	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := contact(i); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	select {
	case <-i.Requests():
	default:
		t.Fatal("no activation queued")
	}
	select {
	case <-i.Requests():
		t.Fatal("unbounded activation queue")
	default:
	}
}

func TestFailedContactNeverCreatesAnotherGUI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	i, err := acquire(ctx, func() (net.Listener, error) { return nil, errors.New("already reserved") }, func(context.Context) (net.Conn, error) { return nil, errors.New("unresponsive existing GUI") }, func(net.Conn) error { return nil })
	if i != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("failed contact created GUI or lost deadline: %v %v", i, err)
	}
}

func TestPreviousProcessExitDuringContactAllowsFreshStart(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	i, err := acquire(ctx, func() (net.Listener, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("existing GUI")
		}
		return l, nil
	}, func(context.Context) (net.Conn, error) { return nil, net.ErrClosed }, func(net.Conn) error { return nil })
	if err != nil || i == nil {
		l.Close()
		t.Fatalf("did not replace exited process: %v", err)
	}
	i.Close()
}
