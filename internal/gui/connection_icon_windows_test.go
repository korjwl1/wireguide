package gui

import (
	"os"
	"runtime"
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

func TestWindowsConnectionIconRestoresOriginalHandles(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hwnd := w32.CreateWindowEx(0, w32.MustStringToUTF16Ptr("STATIC"), nil, 0, 0, 0, 32, 32, 0, 0, 0, nil)
	if hwnd == 0 {
		t.Fatal("cannot create test window")
	}
	defer w32.DestroyWindow(hwnd)
	source, err := os.ReadFile("../../build/appicon.png")
	if err != nil {
		t.Fatal(err)
	}
	images, err := buildConnectionIconImages(source)
	if err != nil {
		t.Fatal(err)
	}
	icon, err := w32.CreateLargeHIconFromImage(images.base)
	if err != nil || icon == 0 {
		t.Fatalf("native base icon creation: %v", err)
	}
	defer w32.DestroyIcon(icon)
	w32.SendMessage(hwnd, w32.WM_SETICON, w32.ICON_BIG, uintptr(icon))
	defer applyWindowsConnectionIcon(hwnd, false, images)
	for range 2 { // Explorer refresh must retain the original, not our last icon.
		if err := applyWindowsConnectionIcon(hwnd, true, images); err != nil {
			t.Fatal(err)
		}
		if got := w32.SendMessage(hwnd, w32.WM_GETICON, w32.ICON_BIG, 0); got == 0 || got == uintptr(icon) {
			t.Fatal("connected application icon was not installed")
		}
	}
	if err := applyWindowsConnectionIcon(hwnd, false, images); err != nil {
		t.Fatal(err)
	}
	if got := w32.SendMessage(hwnd, w32.WM_GETICON, w32.ICON_BIG, 0); got != uintptr(icon) {
		t.Fatal("disconnect did not restore Wails' original icon")
	}
	if _, exists := windowConnectionIcons[hwnd]; exists {
		t.Fatal("disconnect retained owned icons")
	}
}
