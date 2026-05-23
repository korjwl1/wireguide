package ipc

import (
	"bytes"
	"testing"
)

// FuzzReadFrameRaw exercises the IPC framing reader with arbitrary
// bytes. The reader runs on a privileged-helper trust boundary — any
// panic or unbounded allocation here is a denial-of-service vector.
func FuzzReadFrameRaw(f *testing.F) {
	// Known-good frame.
	f.Add([]byte{0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'})
	// Empty frame (rejected by length==0 guard).
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	// Header but no body.
	f.Add([]byte{0x00, 0x00, 0x00, 0x05})
	// Header claims oversize.
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	// Truncated header.
	f.Add([]byte{0x00, 0x00})
	// Body shorter than header claims.
	f.Add([]byte{0x00, 0x00, 0x00, 0x0A, 'a', 'b'})

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Reader must not panic and must not allocate more than the
		// 1 MiB maxFrameSize cap regardless of header value.
		_, _ = ReadFrameRaw(bytes.NewReader(raw))
	})
}
