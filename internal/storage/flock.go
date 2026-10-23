package storage

import (
	"errors"
	"time"
)

var ErrStoreBusy = errors.New("another process is holding the storage lock; retry shortly")

func flockExclusive(fd int) error { return flockAcquire(fd, false) }

func flockAcquire(fd int, shared bool) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		acquired, err := tryFlock(fd, shared)
		if acquired || err != nil {
			return err
		}
		if !time.Now().Before(deadline) {
			return ErrStoreBusy
		}
		time.Sleep(min(20*time.Millisecond, time.Until(deadline)))
	}
}
