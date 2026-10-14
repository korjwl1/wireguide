//go:build !darwin

package network

// CleanupStaleSplitDNS is a no-op off macOS: Linux split-DNS state dies with
// the link and Windows does not support split DNS.
func CleanupStaleSplitDNS() error { return nil }
