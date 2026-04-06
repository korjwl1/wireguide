package gui

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

void dockHide() {
	dispatch_async(dispatch_get_main_queue(), ^{
		[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
	});
}

void dockShowAndActivate() {
	dispatch_async(dispatch_get_main_queue(), ^{
		[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
		[NSApp activateIgnoringOtherApps:YES];
	});
}
*/
import "C"
import (
	"log/slog"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
)

var dockWindow *application.WebviewWindow

func showDock() {
	C.dockShowAndActivate()

	go func() {
		for i := 0; i < 10; i++ {
			time.Sleep(200 * time.Millisecond)
			if dockWindow == nil {
				return
			}
			dockWindow.Show()
			dockWindow.Focus()
			C.dockShowAndActivate()

			// Check if the window actually became visible.
			time.Sleep(50 * time.Millisecond)
			if dockWindow.IsVisible() {
				slog.Debug("show window succeeded", "attempt", i+1)
				return
			}
			slog.Debug("show window retry", "attempt", i+1)
		}
		slog.Warn("show window failed after 10 attempts")
	}()
}

func hideDock() { C.dockHide() }
