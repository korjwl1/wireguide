package gui

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

void setDockVisible(bool visible) {
	if (visible) {
		[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
		// After switching back to Regular, the app must be explicitly
		// activated or macOS won't bring it to the foreground.
		[NSApp activateIgnoringOtherApps:YES];
	} else {
		[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
	}
}
*/
import "C"

func showDock() { C.setDockVisible(true) }
func hideDock() { C.setDockVisible(false) }
