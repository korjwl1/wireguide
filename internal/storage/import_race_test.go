package storage

import (
	"sync"
	"testing"

	"github.com/korjwl1/wireguide/internal/config"
)

func TestConcurrentImportsNeverReplaceExistingKeys(t *testing.T) {
	dir := t.TempDir()
	stores := []*TunnelStore{NewTunnelStore(dir), NewTunnelStore(dir)}
	start := make(chan struct{})
	errs := make(chan error, len(stores))
	var wg sync.WaitGroup
	for _, store := range stores {
		wg.Add(1)
		go func(store *TunnelStore) {
			defer wg.Done()
			<-start
			_, err := store.ImportFromContent("vpn", config.Serialize(testConfig()))
			errs <- err
		}(store)
	}
	close(start)
	wg.Wait()
	close(errs)
	succeeded := 0
	for err := range errs {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d simultaneous imports succeeded; an existing configuration was replaced", succeeded)
	}

	before, err := stores[0].Load("vpn")
	if err != nil {
		t.Fatal(err)
	}
	replacement := testConfig()
	replacement.Interface.PrivateKey = "4OnLoxSBnWDtTxMcDZGM0IYBGBEw6rnWSkAkSDZ0DmY="
	if _, err := stores[1].ImportFromContent("vpn", config.Serialize(replacement)); err == nil {
		t.Fatal("import replaced existing keys")
	}
	after, err := stores[0].Load("vpn")
	if err != nil || after.Interface.PrivateKey != before.Interface.PrivateKey {
		t.Fatalf("key changed: %v", err)
	}
}
