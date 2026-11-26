package domain

import (
	"crypto/rand"
	"strconv"
	"strings"
	"sync/atomic"
)

var counterIncarnation = rand.Text()
var counterSequence atomic.Uint64

func NewCounterEpoch() string {
	sequence := counterSequence.Add(1)
	if sequence == 0 {
		panic("counter epoch sequence exhausted")
	}
	return "wg1." + counterIncarnation + "." + strconv.FormatUint(sequence, 10)
}

func ParseCounterEpoch(epoch string) (string, uint64, bool) {
	rest, ok := strings.CutPrefix(epoch, "wg1.")
	if !ok {
		return "", 0, false
	}
	incarnation, number, ok := strings.Cut(rest, ".")
	if !ok || incarnation == "" || len(incarnation) > 128 {
		return "", 0, false
	}
	sequence, err := strconv.ParseUint(number, 10, 64)
	if err != nil || sequence == 0 || strconv.FormatUint(sequence, 10) != number {
		return "", 0, false
	}
	return incarnation, sequence, true
}
