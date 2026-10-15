#import <Cocoa/Cocoa.h>
#include "../connection_icon_darwin.h"

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc != 2) return 2;
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        NSData *original = [[[NSApp applicationIconImage] TIFFRepresentation] retain];
        NSData *connected = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:argv[1]]];
        if (connected == nil) return 3;
        NSBitmapImageRep *source = [NSBitmapImageRep imageRepWithData:connected];
        for (int i = 0; i < 25; i++) {
            @autoreleasepool {
                if (!wgSetApplicationConnectionIcon(connected.bytes, connected.length, 1)) return 4;
                NSBitmapImageRep *bitmap = [NSBitmapImageRep imageRepWithData:[[NSApp applicationIconImage] TIFFRepresentation]];
                // AppKit rasterizes the app image at the display's backing
                // scale (512 pixels on this Retina Mac for a 256px source).
                NSInteger x = 211 * bitmap.pixelsWide / source.pixelsWide;
                NSInteger y = 211 * bitmap.pixelsHigh / source.pixelsHigh;
                NSColor *dot = [[bitmap colorAtX:x y:y] colorUsingColorSpace:[NSColorSpace deviceRGBColorSpace]];
                // Icon Services also converts the color profile. The Go
                // test checks exact source RGB; here verify displayed green.
                if (dot == nil || dot.greenComponent < 0.6 || dot.greenComponent < dot.redComponent * 1.5 || dot.greenComponent < dot.blueComponent * 1.5 || dot.alphaComponent < 0.95) {
                    fprintf(stderr, "Unexpected badge pixels: bitmap=%ldx%ld color=%.4f,%.4f,%.4f\n", (long)bitmap.pixelsWide, (long)bitmap.pixelsHigh, dot.redComponent, dot.greenComponent, dot.blueComponent);
                    return 5;
                }
                if (!wgSetApplicationConnectionIcon(NULL, 0, 0)) return 6;
                NSData *reset = [[NSApp applicationIconImage] TIFFRepresentation];
                if ((original != nil || reset != nil) && ![reset isEqualToData:original]) return 7;
            }
        }
        [original release];
        puts("PASS: native AppKit green pixels and exact default icon restoration across 25 On/Off cycles");
        return 0;
    }
}
