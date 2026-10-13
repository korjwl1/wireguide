//go:build darwin

package gui

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeGUIHangCapture(t *testing.T) {
	if os.Getenv("WIREGUIDE_TEST_HANG_CAPTURE") != "1" {
		t.Skip("runs Apple's sample against this test process")
	}
	dir := t.TempDir()
	if err := captureGUIHang(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "hang-diagnostics", "hang-*.txt"))
	if err != nil || len(files) != 2 {
		t.Fatalf("diagnostic pair: %v %v", files, err)
	}
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil || info.Size() == 0 || info.Mode().Perm() != 0600 {
			t.Fatalf("private nonempty diagnostic: %s %v", file, err)
		}
	}
}
