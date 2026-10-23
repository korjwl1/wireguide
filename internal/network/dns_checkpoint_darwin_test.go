package network

import (
	"errors"
	"os"
	"reflect"
	"testing"
)

// Opt-in read-only hardware check: native networksetup queries capture actual
// service preferences. The write wrapper is intercepted even if ordering breaks.
func TestNativeDNSCheckpointBeforeOSWrite(t *testing.T) {
	if os.Getenv("WIREGUIDE_TEST_MACOS_READONLY") != "1" {
		t.Skip("set WIREGUIDE_TEST_MACOS_READONLY=1 on macOS")
	}
	previousRun := run
	writes := 0
	run = func(string, ...string) error { writes++; return errors.New("native test forbids OS writes") }
	t.Cleanup(func() { run = previousRun })
	stop := errors.New("checkpoint stops before mutation")
	services := getAllNetworkServices()
	if len(services) == 0 {
		t.Fatal("no native network services found")
	}
	for _, active := range []bool{false, true} {
		m := NewPlatformManager().(*DarwinManager)
		if active {
			// A surviving tunnel may first see a new service when the union
			// is reapplied after a sibling disconnect, without a route event.
			m.dnsActive = true
			m.savedDNS[services[0]] = []string{"8.8.8.8"}
		}
		captured := 0
		m.SetDNSCheckpoint(func(snapshot DNSSnapshot) error {
			for _, service := range services {
				if _, exists := snapshot.Servers[service]; exists {
					captured++
				}
			}
			return stop
		})
		err := m.SetDNS("wireguide-readonly-check", []string{"198.18.255.53", "wg-checkpoint.invalid"})
		if !errors.Is(err, stop) || captured != len(services) || writes != 0 {
			t.Fatalf("active=%v native checkpoint ordering: error=%v captured_services=%d writes=%d", active, err, captured, writes)
		}
	}
	t.Logf("captured all %d native services before initial and already-active DNS writes", len(services))
}

func TestDNSCheckpointFailureRemainsPendingAndCleanChecksDoNotWrite(t *testing.T) {
	m := NewPlatformManager().(*DarwinManager)
	m.savedDNS["Wi-Fi"] = []string{"8.8.8.8"}
	m.savedSearch["Wi-Fi"] = []string{"home.test"}
	writes := 0
	fail := true
	m.SetDNSCheckpoint(func(snapshot DNSSnapshot) error {
		writes++
		if !reflect.DeepEqual(snapshot.Servers, map[string][]string{"Wi-Fi": {"8.8.8.8"}}) {
			t.Errorf("prepared snapshot is unavailable before dnsActive: %+v", snapshot)
		}
		if fail {
			return errors.New("disk unavailable")
		}
		return nil
	})
	if err := m.captureNewServices(nil); err == nil {
		t.Fatal("checkpoint failure hidden")
	}
	fail = false
	if err := m.captureNewServices(nil); err != nil {
		t.Fatal(err)
	}
	if err := m.captureNewServices(nil); err != nil {
		t.Fatal(err)
	}
	if writes != 2 {
		t.Fatalf("failed checkpoint was not retried, or clean poll rewrote it: %d writes", writes)
	}
}

func TestConcurrentDNSCaptureKeepsNewGenerationPending(t *testing.T) {
	m := NewPlatformManager().(*DarwinManager)
	m.savedDNS["Wi-Fi"] = []string{"8.8.8.8"}
	started, release := make(chan struct{}), make(chan struct{})
	writes := 0
	m.SetDNSCheckpoint(func(snapshot DNSSnapshot) error {
		writes++
		if writes == 1 {
			close(started)
			<-release
		}
		return nil
	})
	done := make(chan error, 1)
	go func() { done <- m.checkpointDNS() }()
	<-started
	m.mu.Lock()
	m.savedDNS["Ethernet"] = []string{"9.9.9.9"}
	m.dnsCheckpointVersion++
	m.mu.Unlock()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := m.checkpointDNS(); err != nil {
		t.Fatal(err)
	}
	if writes != 2 {
		t.Fatalf("concurrent service capture lost its checkpoint: %d writes", writes)
	}
}
