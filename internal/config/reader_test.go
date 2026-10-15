package config

import (
	"strings"
	"testing"
)

type endlessConfigReader struct{ read int }

func (r *endlessConfigReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = '#'
	}
	r.read += len(p)
	return len(p), nil
}

func TestParseReaderStopsAtSizeLimit(t *testing.T) {
	r := &endlessConfigReader{}
	if _, err := ParseReader(r); err == nil || !strings.Contains(err.Error(), "config too large") {
		t.Fatalf("oversize input accepted: %v", err)
	}
	if r.read != MaxConfigSize+1 {
		t.Fatalf("reader consumed %d bytes, want at most %d", r.read, MaxConfigSize+1)
	}
}
