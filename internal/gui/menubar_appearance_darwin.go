package gui

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

// The menu bar tints status-item icons by ITS OWN effective appearance,
// which follows the wallpaper behind the menu bar — NOT the system
// light/dark theme. (A light-theme desktop with a dark wallpaper renders
// a dark menu bar and every template icon white.) Every NSStatusItem's
// button lives in an NSStatusBarWindow owned by this process, so that
// window's effectiveAppearance is the ground truth for how the menu bar
// is rendering us right now. Falls back to NSApp.effectiveAppearance
// (system theme) before the status item's window exists.
static bool wgMenuBarIsDarkImpl(void) {
	NSAppearance *ap = nil;
	for (NSWindow *w in [NSApp windows]) {
		if ([NSStringFromClass([w class]) containsString:@"NSStatusBarWindow"]) {
			ap = w.effectiveAppearance;
			break;
		}
	}
	if (ap == nil) {
		ap = [NSApp effectiveAppearance];
	}
	NSString *best = [ap bestMatchFromAppearancesWithNames:
		@[NSAppearanceNameAqua, NSAppearanceNameDarkAqua]];
	return [best isEqualToString:NSAppearanceNameDarkAqua];
}

bool wgMenuBarIsDark(void) {
	// effectiveAppearance must be read on the main thread. During
	// startup gui.Run already runs on the main thread (direct call);
	// later callers are event-loop goroutines, where the main run loop
	// is live and a dispatch_sync hop is safe and sub-millisecond.
	if ([NSThread isMainThread]) {
		return wgMenuBarIsDarkImpl();
	}
	__block bool result = false;
	dispatch_sync(dispatch_get_main_queue(), ^{
		result = wgMenuBarIsDarkImpl();
	});
	return result;
}
*/
import "C"

// menuBarIsDark reports whether the menu bar is currently rendering with
// a dark appearance (white icon tint).
func menuBarIsDark() bool { return bool(C.wgMenuBarIsDark()) }
