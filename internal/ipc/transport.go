package ipc

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
)

// DefaultSocketPath returns the default socket/pipe address for this OS+user.
func DefaultSocketPath() string {
	switch runtime.GOOS {
	case "windows":
		user := os.Getenv("USERNAME")
		if user == "" {
			user = "default"
		}
		return `\\.\pipe\wireguide-` + sanitize(user)
	default:
		uid := os.Getuid()
		return fmt.Sprintf("/tmp/wireguide-%s.sock", strconv.Itoa(uid))
	}
}

func sanitize(s string) string {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			out = append(out, byte(r))
		}
	}
	if len(out) == 0 {
		return "default"
	}
	return string(out)
}
