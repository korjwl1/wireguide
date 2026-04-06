package ipc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Max message size: 1MB (prevents memory exhaustion from malformed frames).
const maxFrameSize = 1024 * 1024

// WriteFrame writes a length-prefixed JSON-serialized message to w.
// The header and body are combined into a single Write call to prevent
// stream corruption if multiple goroutines write concurrently.
func WriteFrame(w io.Writer, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if len(data) > maxFrameSize {
		return fmt.Errorf("frame too large: %d bytes", len(data))
	}

	// Combine header + body into one buffer for an atomic write.
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

// ReadFrame reads a length-prefixed message from r into v.
func ReadFrame(r io.Reader, v interface{}) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > maxFrameSize {
		return fmt.Errorf("frame too large: %d bytes", length)
	}
	if length == 0 {
		return fmt.Errorf("empty frame")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	return json.Unmarshal(body, v)
}

// ReadFrameRaw reads a length-prefixed message and returns the raw bytes.
func ReadFrameRaw(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > maxFrameSize {
		return nil, fmt.Errorf("frame too large: %d bytes", length)
	}
	if length == 0 {
		return nil, fmt.Errorf("empty frame")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}
