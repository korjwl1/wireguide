#import <Cocoa/Cocoa.h>
#include <stdio.h>
#include "../native_tray_darwin.m"

static NSString *selected = nil;
void wgNativeTrayAction(char *action) { selected = [NSString stringWithUTF8String:action]; }

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc != 2) return 2;
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        NSData *icon = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:argv[1]]];
        wgNativeTrayCreate(icon.bytes, icon.length);
        wgNativeTraySetMenu("[{\"title\":\"WireGuide\",\"enabled\":false},{\"title\":\"Test tunnel\",\"action\":\"tunnel:test\",\"enabled\":true}]");
        wgNativeTraySetConnected(true);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 300*NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
            if (wgTray == nil || wgTray.item.menu != wgTray.menu || wgTray.menu.numberOfItems != 2) exit(3);
            if (!wgTray.item.button.image.isTemplate || wgTray.badge.hidden || wgTray.badge.isOpaque) exit(9);
            if ([wgTray.badge hitTest:NSMakePoint(2,2)] != nil) exit(10);
            wgTray.item.button.appearsDisabled = YES;
            if (wgTray.badge.alphaValue > 0.5) exit(11);
            wgTray.item.button.appearsDisabled = NO;
            if (wgTray.badge.alphaValue < 0.9) exit(12);
            if ([wgTray.menu itemAtIndex:0].enabled || ![wgTray.menu itemAtIndex:1].enabled) exit(4);
            [wgTray.menu performActionForItemAtIndex:1];
            if (![selected isEqualToString:@"tunnel:test"]) exit(5);
            [wgTray.menu cancelTracking];
            if (wgTray.item.menu != wgTray.menu) exit(6);
            wgNativeTrayDestroy();
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100*NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
                if (wgTray != nil) exit(7);
                puts("native tray: persistent menu, action dispatch and cleanup passed");
                exit(0);
            });
        });
        [NSApp run];
    }
    return 8;
}
