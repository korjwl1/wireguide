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

// Go readers do not grant FILE_SHARE_DELETE. Retry that transient conflict
// without treating permission or path failures as a reason to wait.
func retrySharingViolation(replace func() error) error {
	deadline := time.Now().Add(time.Second)
	delay := 5 * time.Millisecond
	for {
		err := replace()
		if (!errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_LOCK_VIOLATION)) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(min(delay, time.Until(deadline)))
		delay = min(delay*2, 80*time.Millisecond)
	}
}
