package atomicfile

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func replace(src, dst string) error {
	from, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	return retrySharingViolation(func() error {
		return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
	})
}

func replaceInRoot(root *os.Root, src, dst string) error {
	return retrySharingViolation(func() error { return root.Rename(src, dst) })
}

// Windows can report a live reader conflict as ACCESS_DENIED or SHARING_VIOLATION.
// Like Go robustio, retry these errors briefly; persistent ACL errors still fail.
func retrySharingViolation(replace func() error) error {
	deadline := time.Now().Add(time.Second)
	delay := 5 * time.Millisecond
	for {
		err := replace()
		if (!errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_LOCK_VIOLATION)) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(min(delay, time.Until(deadline)))
		delay = min(delay*2, 80*time.Millisecond)
	}
}
