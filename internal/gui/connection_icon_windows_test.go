package gui

import (
	"os"
	"testing"

	"github.com/wailsapp/wails/v3/pkg/w32"
)

func TestTaskbarConnectionIconRefreshesAfterExplorerRecreation(t *testing.T) {
	calls := 0
	handler := connectionIconMessages(func() { calls++ })
	for _, name := range []string{"TaskbarButtonCreated", "TaskbarCreated"} {
		msg := w32.RegisterWindowMessage(w32.MustStringToUTF16Ptr(name))
		if msg == 0 {
			t.Fatal("Windows did not register the shell message")
		}
		if _, consumed := handler(0, msg, 0, 0); consumed {
			t.Fatal("icon hook swallowed the shell message")
		}
	}
	handler(0, 0, 0, 0)
	if calls != 2 {
		t.Fatal("Explorer/taskbar recreation did not refresh the icon")
	}
}

func TestWindowsConnectionOverlayCreatesAnOwnedNativeIcon(t *testing.T) {
	source, err := os.ReadFile("../../build/appicon.png")
	if err != nil {
		t.Fatal(err)
	}
	images, err := buildConnectionIconImages(source)
	if err != nil {
		t.Fatal(err)
	}
	icon, err := w32.CreateSmallHIconFromImage(images.overlay)
	if err != nil || icon == 0 {
		t.Fatalf("native green overlay creation: %v", err)
	}
	w32.DestroyIcon(icon)
}
