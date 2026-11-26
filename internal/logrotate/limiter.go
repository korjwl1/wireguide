package logrotate

import (
	"strings"
	"sync"
	"time"
)

// Limiter lets one message per key through per window and counts the rest.
type Limiter struct {
	window time.Duration

	mu      sync.Mutex
	entries map[string]*limitEntry
}

type limitEntry struct {
	last       time.Time
	suppressed int
	// raw is the most recent message that passed for this key, kept for
	// trailing summaries. It lives and dies with the entry.
	raw string
}

// Suppressed describes a key whose repeats were dropped and whose window has
// elapsed without the message recurring.
type Suppressed struct {
	// Message is the last message that passed for the key.
	Message string
	// Count is the number of repeats dropped after it.
	Count int
}

// NewLimiter returns a Limiter with the given window.
func NewLimiter(window time.Duration) *Limiter {
	return &Limiter{window: window, entries: make(map[string]*limitEntry)}
}

// Allow reports whether a message with this key may be logged now. When it
// returns true, suppressed is the number of identical messages dropped since
// the previous one that passed. msg is remembered for Expired summaries.
func (l *Limiter) Allow(key, msg string, now time.Time) (ok bool, suppressed int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		if len(l.entries) > 1024 {
			l.entries = make(map[string]*limitEntry)
		}
		l.entries[key] = &limitEntry{last: now, raw: msg}
		return true, 0
	}
	if now.Sub(e.last) >= l.window {
		s := e.suppressed
		e.last, e.suppressed, e.raw = now, 0, msg
		return true, s
	}
	e.suppressed++
	return false, 0
}

// Expired returns the entries whose window has elapsed and that still hold
// suppressed repeats, and clears their counts so each summary is reported once.
// The entry's last-pass time is left alone: if the message recurs it passes
// again at once (the real warning repeats each window). Lets the caller emit a
// trailing "suppressed N" summary even if the message never recurs.
func (l *Limiter) Expired(now time.Time) []Suppressed {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Suppressed
	for _, e := range l.entries {
		if e.suppressed > 0 && now.Sub(e.last) >= l.window {
			out = append(out, Suppressed{Message: e.raw, Count: e.suppressed})
			e.suppressed = 0
		}
	}
	return out
}

// NormalizeKey collapses digit runs so messages differing only in ports,
// addresses or counters share a key. A leading "[wg:<iface>]" tag is kept
// verbatim so each tunnel interface has its own key.
func NormalizeKey(msg string) string {
	prefix := ""
	if strings.HasPrefix(msg, "[wg:") {
		if end := strings.IndexByte(msg, ']'); end >= 0 {
			prefix, msg = msg[:end+1], msg[end+1:]
		}
	}
	var b strings.Builder
	b.WriteString(prefix)
	inDigits := false
	for _, r := range msg {
		if r >= '0' && r <= '9' {
			if !inDigits {
				b.WriteByte('#')
			}
			inDigits = true
			continue
		}
		inDigits = false
		b.WriteRune(r)
	}
	return b.String()
}
