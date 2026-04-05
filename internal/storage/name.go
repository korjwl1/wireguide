package storage

import "fmt"

// ValidateTunnelName ensures a tunnel name is safe for use as a filesystem
// path (preventing traversal) and consistent across all entry points —
// both on first save and on rename. Allowed: letters, digits, '-', '_'.
// Length limit guards against filesystem limits on some platforms.
func ValidateTunnelName(name string) error {
	if name == "" {
		return fmt.Errorf("tunnel name is empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("tunnel name too long (max 64 characters)")
	}
	for _, r := range name {
		valid := (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_'
		if !valid {
			return fmt.Errorf("invalid character in tunnel name %q (letters, digits, '-' and '_' only)", name)
		}
	}
	return nil
}
