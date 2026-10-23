package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestWriteFileConcurrentReaders(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows readers may deny delete sharing; replacement failure is covered separately")
	}
	path := filepath.Join(t.TempDir(), "snapshot")
	a, b := strings.Repeat("a", 64<<10), strings.Repeat("b", 64<<10)
	if err := WriteFile(path, []byte(a), 0600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			data, err := os.ReadFile(path)
			if err != nil || (string(data) != a && string(data) != b) {
				t.Errorf("reader saw an incomplete snapshot (%d bytes, error %v)", len(data), err)
				return
			}
		}
	}()
	defer wg.Wait()
	defer close(done)
	for i := 0; i < 12; i++ {
		if err := WriteFile(path, []byte(b), 0600); err != nil {
			t.Fatal(err)
		}
		if err := WriteFile(path, []byte(a), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWriteFileReplacementFailureCleansTemp(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "directory")
	if err := os.Mkdir(dst, 0700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(dst, []byte("private key"), 0600); err == nil {
		t.Fatal("replaced a directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "directory" {
		t.Fatalf("failed write left temporary files: %v, %v", entries, err)
	}
}

func TestWriteFileReplacesSymlinkAndRestrictsPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires a separate Windows privilege")
	}
	dir := t.TempDir()
	target, link := filepath.Join(dir, "target"), filepath.Join(dir, "export.conf")
	if err := os.WriteFile(target, []byte("unchanged"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(link, []byte("private key"), 0600); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(target)
	if err != nil || string(original) != "unchanged" {
		t.Fatalf("followed destination symlink: %q, %v", original, err)
	}
	info, err := os.Lstat(link)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("export is not a private regular file: %v, %v", info, err)
	}
}
