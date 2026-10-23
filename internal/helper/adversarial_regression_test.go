package helper

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
	"testing"
	"time"
)

// Each successful suspend is a distinct reconnect transaction.
func TestAuditNestedReconnectPreservesKillSwitch(t *testing.T) {
	h := newPendingTestHelper(t)
	f := dnsFW(h)
	f.killSwitch = true
	for i := 0; i < 2; i++ {
		if err := h.suspendFirewall(); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := h.resumeFirewall(); err != nil {
			t.Fatal(err)
		}
	}
	if !f.IsKillSwitchEnabled() {
		t.Fatal("two successful reconnect transactions silently lost the enabled kill switch")
	}
}

func TestAuditNestedReconnectKeepsDNSSuspendedUntilLastResume(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"alpha", "utun4", []string{"10.0.0.1"}})
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := h.suspendFirewall(); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.resumeFirewall(); err != nil {
		t.Fatal(err)
	}
	if dnsFW(h).IsDNSProtectionEnabled() {
		t.Fatal("first resume installed DNS rules while another reconnect was still suspended")
	}
}

func TestAuditReapplyHonorsReconnectSuspension(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"alpha", "utun4", []string{"10.0.0.1"}})
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	if err := h.suspendFirewall(); err != nil {
		t.Fatal(err)
	}
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	if dnsFW(h).IsDNSProtectionEnabled() {
		t.Fatal("ordinary reapply installed DNS rules before resume")
	}
}

type auditFailingFirewall struct {
	*pendingTestFirewall
	failEnable bool
}

func (f *auditFailingFirewall) EnableKillSwitch(iface string, addresses, endpoints []string) error {
	if f.failEnable {
		return errors.New("injected temporary OS error")
	}
	return f.pendingTestFirewall.EnableKillSwitch(iface, addresses, endpoints)
}
func TestAuditFailedResumePreservesKillSwitchIntent(t *testing.T) {
	h := newPendingTestHelper(t)
	f := &auditFailingFirewall{pendingTestFirewall: dnsFW(h)}
	h.firewall = f
	stubConnected(t, h, tn{"alpha", "utun4", nil})
	f.killSwitch = true
	if err := h.suspendFirewall(); err != nil {
		t.Fatal(err)
	}
	f.failEnable = true
	if err := h.resumeFirewall(); err == nil {
		t.Fatal("injected error did not fire")
	}
	h.mu.Lock()
	wanted := h.killSwitchWanted
	h.mu.Unlock()
	if !wanted {
		t.Error("failed restore erased the only saved kill switch intent")
	}
	h.persistDesiredState()
	if loadDesiredIntent(h.dataDir).KillSwitch {
		t.Log("persisted kill switch intent survived")
	} else {
		t.Error("next intent write also persisted kill switch OFF while alpha remained wanted")
	}
	f.failEnable = false
	if err := h.resumeFirewall(); err != nil {
		t.Fatal(err)
	}
	if !f.IsKillSwitchEnabled() {
		t.Error("second resume after OS recovery never restored the kill switch")
	}
}

type transitionFaultFirewall struct {
	*pendingTestFirewall
	enableErr, disableErr, dnsErr, addErr bool
	enables                               int
}

func (f *transitionFaultFirewall) EnableKillSwitch(i string, a, e []string) error {
	f.enables++
	if f.enableErr {
		return errors.New("temporary enable error")
	}
	return f.pendingTestFirewall.EnableKillSwitch(i, a, e)
}
func (f *transitionFaultFirewall) DisableKillSwitch() error {
	if f.disableErr {
		return errors.New("temporary disable error")
	}
	return f.pendingTestFirewall.DisableKillSwitch()
}
func (f *transitionFaultFirewall) AddKillSwitchTunnel(string, []string, []string) error {
	if f.addErr {
		return errors.New("temporary permit error")
	}
	return nil
}
func (f *transitionFaultFirewall) EnableDNSProtection(a []firewall.DNSAllow) error {
	if f.dnsErr {
		return errors.New("temporary DNS error")
	}
	return f.pendingTestFirewall.EnableDNSProtection(a)
}
func TestKillSwitchPeriodicRetryAndHealthyRulesStayUntouched(t *testing.T) {
	h := newPendingTestHelper(t)
	stubConnected(t, h, tn{"alpha", "utun4", nil})
	f := &transitionFaultFirewall{pendingTestFirewall: dnsFW(h), enableErr: true}
	h.firewall = f
	_, err := h.handleSetKillSwitch(json.RawMessage(`{"enabled":true}`))
	if err == nil || !loadDesiredIntent(h.dataDir).KillSwitch {
		t.Fatal("failed request lost wanted state")
	}
	retry := h.ksRetryAt
	f.enableErr = false
	if err := h.reconcileKillSwitch(false, retry.Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if f.enables != 1 {
		t.Fatal("backoff ignored")
	}
	if err := h.reconcileKillSwitch(false, retry); err != nil {
		t.Fatal(err)
	}
	if !f.IsKillSwitchEnabled() || f.enables != 2 {
		t.Fatal("periodic retry did not restore blockade")
	}
	if err := h.reconcileKillSwitch(false, retry.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if f.enables != 2 {
		t.Fatal("healthy rules rebuilt needlessly")
	}
}
func TestKillSwitchExplicitOffRetriesWithoutRearming(t *testing.T) {
	h := newPendingTestHelper(t)
	f := &transitionFaultFirewall{pendingTestFirewall: dnsFW(h), disableErr: true}
	f.killSwitch = true
	h.firewall = f
	if _, err := h.handleSetKillSwitch(json.RawMessage(`{"enabled":false}`)); err == nil {
		t.Fatal("missing injected failure")
	}
	if loadDesiredIntent(h.dataDir).KillSwitch {
		t.Fatal("persisted actual On instead of requested Off")
	}
	f.disableErr = false
	if err := h.reconcileKillSwitch(false, h.ksRetryAt); err != nil {
		t.Fatal(err)
	}
	if f.IsKillSwitchEnabled() || h.killSwitchWanted {
		t.Fatal("retry rearmed explicit Off")
	}
}
func TestKillSwitchUserSettingDuringNestedSuspend(t *testing.T) {
	for _, on := range []bool{false, true} {
		t.Run(fmt.Sprint(on), func(t *testing.T) {
			h := newPendingTestHelper(t)
			f := dnsFW(h)
			f.killSwitch = true
			for range 2 {
				if err := h.suspendFirewall(); err != nil {
					t.Fatal(err)
				}
			}
			raw, _ := json.Marshal(ipc.KillSwitchRequest{Enabled: on})
			if _, err := h.handleSetKillSwitch(raw); err != nil {
				t.Fatal(err)
			}
			if f.IsKillSwitchEnabled() {
				t.Fatal("user On bypassed an active suspension")
			}
			if err := h.resumeFirewall(); err != nil {
				t.Fatal(err)
			}
			if f.IsKillSwitchEnabled() {
				t.Fatal("first owner resumed too early")
			}
			if err := h.resumeFirewall(); err != nil {
				t.Fatal(err)
			}
			if f.IsKillSwitchEnabled() != on {
				t.Fatal("last user setting lost")
			}
		})
	}
}
func TestFailedSuspendOwnsNoLevelAndRollbackRemainsRetryable(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"alpha", "utun4", []string{"10.0.0.1"}})
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	f := &transitionFaultFirewall{pendingTestFirewall: dnsFW(h), disableErr: true, dnsErr: true}
	f.killSwitch = true
	h.firewall = f
	if err := h.suspendFirewall(); err == nil {
		t.Fatal("missing injected disable failure")
	}
	if h.fwSuspendDepth != 0 || h.dnsSuspended {
		t.Fatal("failed suspend left an unmatched owner")
	}
	f.disableErr = false
	f.dnsErr = false
	if err := h.reconcileDNSProtection(false, h.dnsRetryAt); err != nil {
		t.Fatal(err)
	}
	if !f.IsDNSProtectionEnabled() {
		t.Fatal("failed rollback was not retried")
	}
}
func TestFailedAdditionalPermitKeepsBlockadeAndRetries(t *testing.T) {
	h := newPendingTestHelper(t)
	stubConnected(t, h, tn{"alpha", "utun4", nil}, tn{"bravo", "utun5", nil})
	f := &transitionFaultFirewall{pendingTestFirewall: dnsFW(h), addErr: true}
	h.firewall = f
	if _, err := h.handleSetKillSwitch(json.RawMessage(`{"enabled":true}`)); err == nil {
		t.Fatal("missing permit error")
	}
	if !f.IsKillSwitchEnabled() {
		t.Fatal("partial apply failed open")
	}
	f.addErr = false
	if err := h.reconcileKillSwitch(false, h.ksRetryAt); err != nil {
		t.Fatal(err)
	}
	if h.ksApplied == "" {
		t.Fatal("permit retry not committed")
	}
}
func TestFailedConnectKeepsKillSwitchRestoreRetry(t *testing.T) {
	h := newPendingTestHelper(t)
	f := &transitionFaultFirewall{pendingTestFirewall: dnsFW(h), enableErr: true}
	f.killSwitch = true
	h.firewall = f
	if err := h.doConnectHeld(&domain.WireGuardConfig{Name: "invalid"}); err == nil {
		t.Fatal("invalid config unexpectedly connected")
	}
	if !h.killSwitchWanted || h.ksRetryAt.IsZero() {
		t.Fatal("connect rollback lost restore intent")
	}
	f.enableErr = false
	if err := h.reconcileKillSwitch(false, h.ksRetryAt); err != nil {
		t.Fatal(err)
	}
	if !f.IsKillSwitchEnabled() {
		t.Fatal("failed connect left blockade disabled")
	}
}

type modelKillSwitchFirewall struct {
	*transitionFaultFirewall
	permits    map[string]bool
	failRemove bool
}

func (f *modelKillSwitchFirewall) EnableKillSwitch(i string, a, e []string) error {
	if err := f.transitionFaultFirewall.EnableKillSwitch(i, a, e); err != nil {
		return err
	}
	f.permits = map[string]bool{}
	if i != "" {
		f.permits[i] = true
	}
	return nil
}
func (f *modelKillSwitchFirewall) AddKillSwitchTunnel(i string, a, e []string) error {
	if err := f.transitionFaultFirewall.AddKillSwitchTunnel(i, a, e); err != nil {
		return err
	}
	f.permits[i] = true
	return nil
}
func (f *modelKillSwitchFirewall) RemoveKillSwitchTunnel(i string) error {
	if f.failRemove {
		return errors.New("temporary stale permit removal error")
	}
	delete(f.permits, i)
	return nil
}
func TestKillSwitchSafetyNetTracksWholeLiveSet(t *testing.T) {
	h := newPendingTestHelper(t)
	stubConnected(t, h, tn{"alpha", "utun4", nil}, tn{"bravo", "utun5", nil})
	f := &modelKillSwitchFirewall{transitionFaultFirewall: &transitionFaultFirewall{pendingTestFirewall: dnsFW(h)}}
	h.firewall = f
	if _, err := h.handleSetKillSwitch(json.RawMessage(`{"enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	if len(f.permits) != 2 {
		t.Fatal("initial reconcile omitted a live tunnel")
	}
	// Bypass helper disconnect just like a manager-side state transition.
	stubConnected(t, h, tn{"bravo", "utun5", nil})
	f.failRemove = true
	if err := h.reconcileKillSwitch(false, time.Now()); err == nil {
		t.Fatal("removal failure hidden")
	}
	f.failRemove = false
	if err := h.reconcileKillSwitch(false, h.ksRetryAt); err != nil {
		t.Fatal(err)
	}
	if len(f.permits) != 1 || !f.permits["utun5"] || !f.IsKillSwitchEnabled() {
		t.Fatal("stale permit survived or live blockade lost")
	}
	stubConnected(t, h)
	if err := h.reconcileKillSwitch(false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(f.permits) != 0 || !f.IsKillSwitchEnabled() {
		t.Fatal("zero tunnels must leave only the base blockade")
	}
	if f.enables != 1 {
		t.Fatal("re-enabled an already-active backend instead of reconciling its permits")
	}
}
func TestDNSReconcileRepairsLostBackendStateWithoutReloadingHealthyRules(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"alpha", "utun4", []string{"10.0.0.1"}})
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	f := dnsFW(h)
	if err := f.DisableDNSProtection(); err != nil {
		t.Fatal(err)
	}
	if err := h.reconcileDNSProtection(false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !f.IsDNSProtectionEnabled() || f.dnsEnables != 2 {
		t.Fatal("cached signature masked a missing DNS policy")
	}
	if err := h.reconcileDNSProtection(false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if f.dnsEnables != 2 {
		t.Fatal("healthy DNS rules reloaded needlessly")
	}
}

type suspendPanicFirewall struct{ *transitionFaultFirewall }

func (f *suspendPanicFirewall) DisableKillSwitch() error { panic("injected suspend panic") }
func TestSuspendPanicRollsBackWithoutAnUnmatchedOwner(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"alpha", "utun4", []string{"10.0.0.1"}})
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	f := &suspendPanicFirewall{&transitionFaultFirewall{pendingTestFirewall: dnsFW(h)}}
	f.killSwitch = true
	h.firewall = f
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("missing injected panic")
			}
		}()
		_ = h.suspendFirewall()
	}()
	if h.fwSuspendDepth != 0 || h.dnsSuspended || !f.IsDNSProtectionEnabled() || !f.IsKillSwitchEnabled() {
		t.Fatal("panic left a partial suspension without an owner")
	}
}
