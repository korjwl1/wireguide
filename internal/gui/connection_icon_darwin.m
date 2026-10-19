#import <Cocoa/Cocoa.h>
#include "connection_icon_darwin.h"

// Called on the AppKit thread. NSData copies the caller's Go buffer before
// returning; NSApplication retains its image and releases the replaced one.
int wgSetApplicationConnectionIcon(const void *bytes, size_t count, int connected) {
    if (![NSThread isMainThread] || NSApp == nil) return 0;
    if (!connected) {
        [NSApp setApplicationIconImage:nil];
        return 1;
    }
    NSData *data = [NSData dataWithBytes:bytes length:count];
    NSImage *image = [[NSImage alloc] initWithData:data];
    if (image == nil) return 0;
    [NSApp setApplicationIconImage:image];
    [image release];
    return 1;
}
