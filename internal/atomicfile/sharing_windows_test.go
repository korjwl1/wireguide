package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestAtomicPublicationWaitsForReaderSharingDelete(t *testing.T) {
	for _, rooted := range []bool{false, true} {
		t.Run(map[bool]string{false: "path", true: "root"}[rooted], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "settings.json")
			if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
			name, err := windows.UTF16PtrFromString(path)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			released := make(chan struct{})
			go func() { time.Sleep(75 * time.Millisecond); windows.CloseHandle(handle); close(released) }()
			if rooted {
				root, err := os.OpenRoot(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
				err = WriteInRoot(root, "settings.json", []byte("new"), 0600)
			} else {
				err = WriteFile(path, []byte("new"), 0600)
			}
			<-released
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "new" {
				t.Fatalf("publication: %q %v", data, err)
			}
		})
	}
}
