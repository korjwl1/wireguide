//go:build darwin && cgo

package guiinstance

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework AppKit
#import <AppKit/AppKit.h>
#include <unistd.h>

static int activateLegacyWireGuide(void) {
    @autoreleasepool {
        for (NSString *bundleID in @[@"com.korjwl1.wireguide", @"com.korjwl1.wireguide.dev"]) {
            for (NSRunningApplication *app in [NSRunningApplication runningApplicationsWithBundleIdentifier:bundleID]) {
                if (app.processIdentifier == getpid() || app.terminated) continue;
                return [app activateWithOptions:NSApplicationActivateAllWindows] ? 1 : -1;
            }
        }
        return 0;
    }
}
*/
import "C"

import "fmt"

// Older builds have no activation socket. If one is already registered with
// AppKit, focus it without replacing its helper or creating another tray.
func activateLegacyApplication() (bool, error) {
	switch C.activateLegacyWireGuide() {
	case 1:
		return true, nil
	case -1:
		return false, fmt.Errorf("cannot activate the existing WireGuide application")
	default:
		return false, nil
	}
}
