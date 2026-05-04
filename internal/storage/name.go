package storage

import "fmt"

// ValidateTunnelName ensures a tunnel name is safe for use as a filesystem
// path (preventing traversal) and consistent across all entry points —
// both on first save and on rename. Allowed: letters, digits, '-', '_', spaces.
// Leading/trailing spaces are rejected to avoid confusing filenames.
// Length limit guards against filesystem limits on some platforms.
func ValidateTunnelName(name string) error {
	if name == "" {
		return fmt.Errorf("tunnel name is empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("tunnel name too long (max 64 characters)")
	}
	if name[0] == ' ' || name[len(name)-1] == ' ' {
		return fmt.Errorf("tunnel name cannot start or end with a space")
	}
	for _, r := range name {
		valid := (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == ' '
		if !valid {
			return fmt.Errorf("invalid character in tunnel name %q (letters, digits, '-', '_' and spaces only)", name)
		}
	}
	return nil
}
