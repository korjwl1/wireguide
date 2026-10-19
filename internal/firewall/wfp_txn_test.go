package firewall

import (
	"errors"
	"testing"
)

type fakeTxn struct {
	commitStatus            uint32
	begins, commits, aborts int
}

func (t *fakeTxn) ops() wfpTxnOps {
	return wfpTxnOps{
		begin:  func() uint32 { t.begins++; return 0 },
		commit: func() uint32 { t.commits++; return t.commitStatus },
		abort:  func() uint32 { t.aborts++; return 0 },
	}
}

func TestWFPTransactionAbortsOnBodyErrorCommitFailureAndPanic(t *testing.T) {
	txn := &fakeTxn{}
	if err := runWFPTransaction(txn.ops(), "x", func() error { return errors.New("add failed") }); err == nil || txn.commits != 0 || txn.aborts != 1 {
		t.Fatalf("body error: err=%v %+v", err, txn)
	}
	txn = &fakeTxn{commitStatus: 0x80320001}
	if err := runWFPTransaction(txn.ops(), "x", func() error { return nil }); err == nil || txn.aborts != 1 {
		t.Fatalf("commit failure: err=%v %+v", err, txn)
	}
	txn = &fakeTxn{}
	func() {
		defer func() { _ = recover() }()
		_ = runWFPTransaction(txn.ops(), "x", func() error { panic("boom") })
	}()
	if txn.aborts != 1 {
		t.Fatalf("panic left the transaction open: %+v", txn)
	}
	txn = &fakeTxn{}
	if err := runWFPTransaction(txn.ops(), "x", func() error { return nil }); err != nil || txn.commits != 1 || txn.aborts != 0 {
		t.Fatalf("success: err=%v %+v", err, txn)
	}
}

func TestWFPDeleteToleratesOnlyMissingFilters(t *testing.T) {
	status := map[uint64]uint32{1: 0, 2: fwpErrFilterNotFound}
	del := func(id uint64) uint32 { return status[id] }
	if err := deleteWFPFilters(del, []uint64{1, 2}, "DNS"); err != nil {
		t.Fatalf("already-deleted filter treated as failure: %v", err)
	}
	status[3] = 0x80320009 // any other FWP_E_* status
	if err := deleteWFPFilters(del, []uint64{1, 3}, "DNS"); err == nil {
		t.Fatal("failed delete would commit and lose track of an installed filter")
	}
}

func TestEffectiveDNSAllowDropsUnpinnedOnlyUnderKillSwitch(t *testing.T) {
	allow := []DNSAllow{{Servers: []string{"1.1.1.1"}}, {Interface: "wg0", Servers: []string{"10.0.0.1"}}}
	if got := effectiveDNSAllow(allow, false); len(got) != 2 {
		t.Fatalf("without kill switch: %+v", got)
	}
	got := effectiveDNSAllow(allow, true)
	if len(got) != 1 || got[0].Interface != "wg0" {
		t.Fatalf("with kill switch: %+v", got)
	}
}
