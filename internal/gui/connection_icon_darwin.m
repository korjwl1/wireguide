#import <Cocoa/Cocoa.h>
#include "connection_icon_darwin.h"

// Keep Icon Services' canvas, padding and native representations. Replacing
// this with the shared, edge-to-edge PNG makes the Dock icon grow on connect.
static NSImage *wgBaseApplicationIcon = nil;
static NSImage *wgConnectedApplicationIcon = nil;

int wgSetApplicationConnectionIcon(int connected) {
    if (![NSThread isMainThread] || NSApp == nil) return 0;
    if (!connected) {
        [NSApp setApplicationIconImage:nil];
        [wgConnectedApplicationIcon release];
        wgConnectedApplicationIcon = nil;
        [wgBaseApplicationIcon release];
        wgBaseApplicationIcon = nil;
        return 1;
    }
    if (wgConnectedApplicationIcon == nil) {
        wgBaseApplicationIcon = [[NSApp applicationIconImage] copy];
        NSImage *base = wgBaseApplicationIcon;
        if (base == nil || base.size.width <= 0 || base.size.height <= 0) {
            [wgBaseApplicationIcon release];
            wgBaseApplicationIcon = nil;
            return 0;
        }
        // A drawing handler lets AppKit choose the backing resolution,
        // including Retina and Dock magnification, from the original icon.
        wgConnectedApplicationIcon = [[NSImage imageWithSize:base.size flipped:NO drawingHandler:^BOOL(NSRect rect) {
            [base drawInRect:rect fromRect:NSZeroRect operation:NSCompositingOperationCopy fraction:1 respectFlipped:NO hints:nil];
            CGFloat sx = rect.size.width / 256.0, sy = rect.size.height / 256.0;
            [[NSColor whiteColor] setFill];
            [[NSBezierPath bezierPathWithOvalInRect:NSMakeRect(rect.origin.x + 15 * sx, rect.origin.y + 15 * sy, 58 * sx, 58 * sy)] fill];
            [[NSColor colorWithSRGBRed:52.0/255 green:199.0/255 blue:89.0/255 alpha:1] setFill];
            [[NSBezierPath bezierPathWithOvalInRect:NSMakeRect(rect.origin.x + 18 * sx, rect.origin.y + 18 * sy, 52 * sx, 52 * sy)] fill];
            return YES;
        }] retain];
    }
    [NSApp setApplicationIconImage:wgConnectedApplicationIcon];
    return 1;
}
