package firewall

import "fmt"

// fwpErrFilterNotFound is FWP_E_FILTER_NOT_FOUND from winerror.h (also
// golang.org/x/sys/windows.FWP_E_FILTER_NOT_FOUND). A filter that is already
// gone needs no deletion. Kept here, untagged, so the transaction logic below
// is testable on every platform.
const fwpErrFilterNotFound uint32 = 0x80320003

// wfpTxnOps is the slice of the WFP API one transaction needs.
type wfpTxnOps struct {
	begin, commit, abort func() uint32
}

// runWFPTransaction runs body inside one WFP transaction. Any body error,
// panic or commit failure aborts it, so the kernel keeps the previous filter
// set. Callers must update tracked filter IDs and enabled flags only after a
// nil return; recording them earlier is how a failed removal used to leave
// untracked port-53 blocks behind (issue #48).
func runWFPTransaction(ops wfpTxnOps, what string, body func() error) error {
	if status := ops.begin(); status != 0 {
		return fmt.Errorf("FwpmTransactionBegin0(%s): 0x%x", what, status)
	}
	committed := false
	defer func() {
		if !committed {
			ops.abort()
		}
	}()
	if err := body(); err != nil {
		return err
	}
	if status := ops.commit(); status != 0 {
		return fmt.Errorf("FwpmTransactionCommit0(%s): 0x%x", what, status)
	}
	committed = true
	return nil
}

// deleteWFPFilters deletes ids inside the caller's open transaction. An
// already-missing filter counts as deleted; any other failure is returned so
// the caller aborts and keeps tracking every ID for a later retry.
func deleteWFPFilters(del func(uint64) uint32, ids []uint64, what string) error {
	for _, id := range ids {
		if status := del(id); status != 0 && status != fwpErrFilterNotFound {
			return fmt.Errorf("FwpmFilterDeleteById0(%s, %d): 0x%x", what, id, status)
		}
	}
	return nil
}
