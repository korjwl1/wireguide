//go:build !windows

package diag

// getRoutesWindowsFull is a stub on non-Windows platforms — the GOOS
// dispatch in GetRoutingTable never calls it, but Go's package-level
// type-checker still needs every referenced symbol to resolve on every
// build target.
func getRoutesWindowsFull() ([]RouteEntry, error) { return nil, nil }
