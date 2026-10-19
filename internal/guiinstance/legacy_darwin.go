//go:build darwin && cgo

package guiinstance

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework AppKit
#import <AppKit/AppKit.h>
#include <unistd.h>
#include <stdlib.h>

static int activateLegacyWireGuide(void) {
    @autoreleasepool {
        for (NSString *bundleID in @[@"com.korjwl1.wireguide", @"com.korjwl1.wireguide.dev"]) {
            for (NSRunningApplication *app in [NSRunningApplication runningApplicationsWithBundleIdentifier:bundleID]) {
                if (app.processIdentifier == getpid() || app.terminated) continue;
                NSURL *plist = [app.bundleURL URLByAppendingPathComponent:@"Contents/Info.plist"];
                NSDictionary *info = plist ? [NSDictionary dictionaryWithContentsOfURL:plist] : nil;
                if ([info[@"WireGuideGUISingleInstanceVersion"] integerValue] >= 1) continue;
                return [app activateWithOptions:NSApplicationActivateAllWindows] ? 1 : -1;
            }
        }
        return 0;
    }
}
static char *wireGuideUserTempDir(void) {
    size_t size = confstr(_CS_DARWIN_USER_TEMP_DIR, NULL, 0);
    if (!size) return NULL;
    char *result = malloc(size);
    if (result && !confstr(_CS_DARWIN_USER_TEMP_DIR, result, size)) { free(result); return NULL; }
    return result;
}
*/
import "C"

import (
	"fmt"
	"path/filepath"
	"unsafe"
)

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

func darwinReservationDir() (string, error) {
	p := C.wireGuideUserTempDir()
	if p == nil {
		return "", fmt.Errorf("cannot locate private user temporary directory")
	}
	defer C.free(unsafe.Pointer(p))
	return filepath.Join(C.GoString(p), "wireguide-gui"), nil
}
