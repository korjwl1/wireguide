package diag

import (
	"math"
	"testing"
)

// Captured verbatim from `ping -n 3 -w 3000 8.8.8.8` run with
// CREATE_NO_WINDOW on Korean Windows 11 (issue #32): console-less
// ping.exe emits the system MUI language as raw CP949 bytes, so the
// hangul labels ("시간", "평균") are NOT valid UTF-8 here — exactly what
// CombinedOutput hands the parsers in the helper.
const koreanWindowsPingOutput = "\r\n" +
	"Ping 8.8.8.8 32\xb9\xd9\xc0\xcc\xc6\xae \xb5\xa5\xc0\xcc\xc5\xcd \xbb\xe7\xbf\xeb:\r\n" +
	"8.8.8.8\xc0\xc7 \xc0\xc0\xb4\xe4: \xb9\xd9\xc0\xcc\xc6\xae=32 \xbd\xc3\xb0\xa3=33ms TTL=114\r\n" +
	"8.8.8.8\xc0\xc7 \xc0\xc0\xb4\xe4: \xb9\xd9\xc0\xcc\xc6\xae=32 \xbd\xc3\xb0\xa3=32ms TTL=114\r\n" +
	"8.8.8.8\xc0\xc7 \xc0\xc0\xb4\xe4: \xb9\xd9\xc0\xcc\xc6\xae=32 \xbd\xc3\xb0\xa3=33ms TTL=114\r\n" +
	"\r\n" +
	"8.8.8.8\xbf\xa1 \xb4\xeb\xc7\xd1 Ping \xc5\xeb\xb0\xe8:\r\n" +
	"    \xc6\xd0\xc5\xb6: \xba\xb8\xb3\xbf = 3, \xb9\xde\xc0\xbd = 3, \xbc\xd5\xbd\xc7 = 0 (0% \xbc\xd5\xbd\xc7),\r\n" +
	"\xbf\xd5\xba\xb9 \xbd\xc3\xb0\xa3(\xb9\xd0\xb8\xae\xc3\xca):\r\n" +
	"    \xc3\xd6\xbc\xd2 = 32ms, \xc3\xd6\xb4\xeb = 33ms, \xc6\xf2\xb1\xd5 = 32ms\r\n"

const englishWindowsPingOutput = "\r\n" +
	"Pinging 8.8.8.8 with 32 bytes of data:\r\n" +
	"Reply from 8.8.8.8: bytes=32 time=33ms TTL=114\r\n" +
	"Reply from 8.8.8.8: bytes=32 time=32ms TTL=114\r\n" +
	"Reply from 8.8.8.8: bytes=32 time=33ms TTL=114\r\n" +
	"\r\n" +
	"Ping statistics for 8.8.8.8:\r\n" +
	"    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),\r\n" +
	"Approximate round trip times in milli-seconds:\r\n" +
	"    Minimum = 32ms, Maximum = 33ms, Average = 32ms\r\n"

func TestParseIndividualPingTimes_KoreanWindows(t *testing.T) {
	// The three reply lines carry TTL= and must be the only values
	// averaged: (33+32+33)/3. Before the locale-agnostic regex this
	// returned 0 and the caller fell back to wall-clock/3 (~687ms for a
	// 32ms link).
	got := parseIndividualPingTimes(koreanWindowsPingOutput)
	want := (33.0 + 32.0 + 33.0) / 3.0
	if math.Abs(got-want) > 0.01 {
		t.Errorf("got %.3f, want %.3f", got, want)
	}
}

func TestParsePingLatency_KoreanWindowsDoesNotFalseMatch(t *testing.T) {
	// The English "Average = Nms" parser must simply miss (return 0) on
	// Korean output, not mis-parse it.
	if got := parsePingLatency(koreanWindowsPingOutput); got != 0 {
		t.Errorf("got %.3f, want 0", got)
	}
}

func TestParsePingLatency_EnglishWindows(t *testing.T) {
	if got := parsePingLatency(englishWindowsPingOutput); got != 32 {
		t.Errorf("got %.3f, want 32", got)
	}
}

func TestParseIndividualPingTimes_EnglishStillWorks(t *testing.T) {
	got := parseIndividualPingTimes(englishWindowsPingOutput)
	want := (33.0 + 32.0 + 33.0) / 3.0
	if math.Abs(got-want) > 0.01 {
		t.Errorf("got %.3f, want %.3f", got, want)
	}
}

func TestParseIndividualPingTimes_NoTTLFallsBackToAllValues(t *testing.T) {
	// Windows IPv6 replies have no TTL token; the sub-millisecond form
	// uses '<'. All ms values in the output get averaged instead.
	out := "Reply from ::1: time<1ms\r\nReply from ::1: time<1ms\r\n"
	if got := parseIndividualPingTimes(out); math.Abs(got-1.0) > 0.01 {
		t.Errorf("got %.3f, want 1.0", got)
	}
}

func TestParseIndividualPingTimes_Empty(t *testing.T) {
	if got := parseIndividualPingTimes("request timed out"); got != 0 {
		t.Errorf("got %.3f, want 0", got)
	}
}

// Router-sourced "Destination host unreachable" replies carry no RTT token,
// yet ping.exe can exit 0 for them. Both parsers must return 0 so Ping
// reports unreachable instead of fabricating a latency (issue #32).
func TestParsers_DestinationHostUnreachable(t *testing.T) {
	out := "Pinging 10.0.0.7 with 32 bytes of data:\r\n" +
		"Reply from 192.168.1.1: Destination host unreachable.\r\n" +
		"Reply from 192.168.1.1: Destination host unreachable.\r\n" +
		"Reply from 192.168.1.1: Destination host unreachable.\r\n" +
		"Ping statistics for 10.0.0.7:\r\n" +
		"    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),\r\n"
	if got := parsePingLatency(out); got != 0 {
		t.Errorf("parsePingLatency: got %.3f, want 0", got)
	}
	if got := parseIndividualPingTimes(out); got != 0 {
		t.Errorf("parseIndividualPingTimes: got %.3f, want 0", got)
	}
}
