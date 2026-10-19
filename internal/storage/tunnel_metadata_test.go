package storage

import (
	"os"
	"sync"
	"testing"
)

func TestMetadataUpdateCannotRecreateDeletedTunnel(t *testing.T) {
	s := NewTunnelStore(t.TempDir())
	cfg := testConfig()
	if err := s.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(cfg.Name); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := s.UpdateMeta(cfg.Name, func(m *TunnelMeta) { called = true; m.Notes = "stale" }); !os.IsNotExist(err) {
		t.Fatalf("updating a deleted tunnel = %v, want not-exist", err)
	}
	if called {
		t.Fatal("metadata callback ran for a deleted config")
	}
	if _, err := os.Stat(s.metaPath(cfg.Name)); !os.IsNotExist(err) {
		t.Fatalf("orphan metadata recreated: %v", err)
	}
}

func TestIndependentStoresPreserveConcurrentMetadataFields(t *testing.T) {
	dir := t.TempDir()
	a, b := NewTunnelStore(dir), NewTunnelStore(dir)
	cfg := testConfig()
	if err := a.Save(cfg); err != nil {
		t.Fatal(err)
	}
	// The two store instances model the independent GUI/helper/CLI mutexes.
	for range 20 {
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for i, store := range []*TunnelStore{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs <- store.UpdateMeta(cfg.Name, func(m *TunnelMeta) {
					if i == 0 {
						m.Notes += "n"
					} else {
						m.LatencyProbeTarget += "t"
					}
				})
			}()
		}
		close(start)
		wg.Wait()
		for range 2 {
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
		}
	}
	m, err := a.LoadMeta(cfg.Name)
	if err != nil || len(m.Notes) != 20 || len(m.LatencyProbeTarget) != 20 {
		t.Fatalf("metadata field updates lost: %+v, %v", m, err)
	}
}
