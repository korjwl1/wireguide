//go:build darwin && !cgo

package elevate

// Non-CGo tools cannot query ServiceManagement; retain the launchctl check.
func backgroundApprovalRequired(string) bool { return false }
