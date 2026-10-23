package update

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func testScheduler(t *testing.T) *Scheduler {
	t.Helper()
	store, err := NewStateStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return NewScheduler(store, nil, nil)
}

func TestSchedulerRetainsUpdateAcrossNotModifiedAndFailure(t *testing.T) {
	s := testScheduler(t)
	calls := 0
	s.fetch = func(_ context.Context, etag, _ string) (*CheckResult, error) {
		calls++
		if calls == 1 {
			return &CheckResult{ETag: "v99", Info: &UpdateInfo{Available: true, Version: "99.0.0", DownloadURL: "https://github.com/example"}}, nil
		}
		if etag != "v99" {
			t.Errorf("lost conditional request validator: %q", etag)
		}
		if calls == 2 {
			return nil, errors.New("offline")
		}
		return &CheckResult{NotModified: true}, nil
	}
	first, err := s.CheckNow()
	if err != nil {
		t.Fatal(err)
	}
	first.Info.Version = "caller mutation"
	if _, err := s.CheckNow(); err == nil {
		t.Fatal("expected offline failure")
	}
	res, err := s.CheckNow()
	if err != nil || res.Info == nil || res.Info.Version != "99.0.0" || !res.Info.Available {
		t.Fatalf("304 lost cached update: %+v, %v", res, err)
	}
	latest := s.Latest()
	latest.Info.Available = false
	if !s.Latest().Info.Available {
		t.Fatal("Latest exposed mutable internal update state")
	}
}

func TestSchedulerRestartFetchesCompleteRelease(t *testing.T) {
	s := testScheduler(t)
	if err := s.store.Update(func(st *State) { st.ETag = "old"; st.LastModified = "yesterday"; st.LastSeenVersion = "99.0.0" }); err != nil {
		t.Fatal(err)
	}
	s.fetch = func(_ context.Context, etag, modified string) (*CheckResult, error) {
		if etag != "" || modified != "" {
			t.Fatal("new process sent validators without a cached release body")
		}
		return &CheckResult{Info: &UpdateInfo{Available: true, Version: "99.0.0"}}, nil
	}
	notified := false
	s.notify = func(*UpdateInfo) { notified = true }
	if _, err := s.CheckNow(); err != nil {
		t.Fatal(err)
	}
	if !notified {
		t.Fatal("pending update was not announced after restart")
	}
}

func TestSchedulerSerializesChecksAndCancelsQueuedWork(t *testing.T) {
	s := testScheduler(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s.fetch = func(context.Context, string, string) (*CheckResult, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return &CheckResult{Info: &UpdateInfo{Version: "99.0.0"}}, nil
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = s.CheckNow() }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.check(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("queued check = %v", err)
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("cancelled queued check reached the network")
	}
}
