package gui

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

void setDockVisible(bool visible) {
	if (visible) {
		[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
	} else {
		[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
	}
}
*/
import "C"

func showDock() { C.setDockVisible(true) }
func hideDock() { C.setDockVisible(false) }
