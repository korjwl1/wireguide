package gui

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

// Menu-bar appearance tracking, the way native apps do it: KVO on the
// status item button's effectiveAppearance (see Apple forum thread
// 662322 and yujitach/nsstatusitem-lightdark-detect). The menu bar's
// rendered appearance follows the wallpaper behind it — NOT the system
// theme — and the button's effectiveAppearance is the only signal that
// tracks it exactly, including theme switches, wallpaper changes and
// per-display differences. NSKeyValueObservingOptionInitial means the
// observer fires once with the correct current value as soon as it is
// installed, so no polling and no guessed fallback is ever needed.
//
// Wails v3 keeps its NSStatusItem private, so we bootstrap by locating
// the status item's window (an NSStatusBarWindow owned by this process)
// and taking its button view. If the window can't be found the observer
// is simply never installed and the tray keeps the default white glyph.

extern void wgMenuBarAppearanceChanged(bool dark);

@interface WGAppearanceObserver : NSObject
@end

@implementation WGAppearanceObserver
- (void)observeValueForKeyPath:(NSString *)keyPath
                      ofObject:(id)object
                        change:(NSDictionary *)change
                       context:(void *)context {
	NSView *view = (NSView *)object;
	NSString *best = [view.effectiveAppearance bestMatchFromAppearancesWithNames:
		@[NSAppearanceNameAqua, NSAppearanceNameDarkAqua]];
	wgMenuBarAppearanceChanged([best isEqualToString:NSAppearanceNameDarkAqua]);
}
@end

// Held for the app's lifetime; the observation is never removed because
// the status item outlives every code path that could tear it down.
static WGAppearanceObserver *wgObserver = nil;

// Finds this process's status-bar button. The button is normally the
// NSStatusBarWindow's contentView; fall back to the first NSButton in
// its subviews in case a macOS release inserts a wrapper view.
static NSView *wgFindStatusBarButton(void) {
	for (NSWindow *w in [NSApp windows]) {
		if (![NSStringFromClass([w class]) containsString:@"NSStatusBarWindow"]) {
			continue;
		}
		NSView *content = w.contentView;
		if (content == nil) {
			continue;
		}
		if ([content isKindOfClass:[NSButton class]]) {
			return content;
		}
		for (NSView *sub in content.subviews) {
			if ([sub isKindOfClass:[NSButton class]]) {
				return sub;
			}
		}
		return content; // effectiveAppearance of any view in the window works
	}
	return nil;
}

// Installs the KVO observer. Returns true when installed (or already
// installed); false when the status item's window doesn't exist yet.
bool wgObserveMenuBarAppearance(void) {
	__block bool ok = false;
	void (^work)(void) = ^{
		if (wgObserver != nil) {
			ok = true;
			return;
		}
		NSView *button = wgFindStatusBarButton();
		if (button == nil) {
			return;
		}
		wgObserver = [[WGAppearanceObserver alloc] init];
		[button addObserver:wgObserver
		         forKeyPath:@"effectiveAppearance"
		            options:(NSKeyValueObservingOptionNew | NSKeyValueObservingOptionInitial)
		            context:NULL];
		ok = true;
	};
	if ([NSThread isMainThread]) {
		work();
	} else {
		dispatch_sync(dispatch_get_main_queue(), work);
	}
	return ok;
}
*/
import "C"

import (
	"log/slog"
	"time"
)

// watchMenuBarAppearance registers cb to receive the menu bar's rendered
// appearance (dark = white icon tint) and installs the KVO observer.
// The status item is created asynchronously by Wails during app startup,
// so installation is retried briefly; if the button never appears (an OS
// that hosts status items out of process), cb is never called and the
// tray keeps its default white glyph.
//
// cb fires on the AppKit main thread — callers must not do blocking work
// or main-thread dispatches inside it directly.
func watchMenuBarAppearance(cb func(dark bool)) {
	menuBarAppearanceCB.Store(&cb)
	go func() {
		for i := 0; i < 40; i++ { // ~20s budget for the status item to exist
			if bool(C.wgObserveMenuBarAppearance()) {
				slog.Info("menubar appearance observer installed")
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		slog.Warn("menubar appearance observer not installed (status-bar window not found); tray glyph stays white")
	}()
}
