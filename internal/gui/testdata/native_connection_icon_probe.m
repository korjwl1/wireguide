#import <Cocoa/Cocoa.h>
#include "../connection_icon_darwin.h"

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc != 1) return 2;
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        NSImage *base = [[NSApp applicationIconImage] copy];
        NSData *original = [[base TIFFRepresentation] retain];
        NSSize canvas = NSMakeSize(256, 256);
        NSImage *originalCanvas = [[NSImage alloc] initWithSize:canvas];
        [originalCanvas lockFocus];
        [base drawInRect:NSMakeRect(0, 0, 256, 256) fromRect:NSZeroRect operation:NSCompositingOperationCopy fraction:1];
        [originalCanvas unlockFocus];
        NSBitmapImageRep *originalPixels = [NSBitmapImageRep imageRepWithData:[originalCanvas TIFFRepresentation]];
        for (int i = 0; i < 25; i++) {
            @autoreleasepool {
                if (!wgSetApplicationConnectionIcon(1)) return 4;
                if (!NSEqualSizes([NSApp applicationIconImage].size, base.size)) return 9;
                NSBitmapImageRep *bitmap = [NSBitmapImageRep imageRepWithData:[[NSApp applicationIconImage] TIFFRepresentation]];
                NSImage *currentCanvas = [[NSImage alloc] initWithSize:canvas];
                [currentCanvas lockFocus];
                [[NSApp applicationIconImage] drawInRect:NSMakeRect(0, 0, 256, 256) fromRect:NSZeroRect operation:NSCompositingOperationCopy fraction:1];
                [currentCanvas unlockFocus];
                NSBitmapImageRep *currentPixels = [NSBitmapImageRep imageRepWithData:[currentCanvas TIFFRepresentation]];
                for (NSInteger py = 0; i == 0 && py < originalPixels.pixelsHigh; py++) {
                    for (NSInteger px = 0; px < originalPixels.pixelsWide; px++) {
                        CGFloat nx = (px + 0.5) * 256.0 / originalPixels.pixelsWide;
                        CGFloat ny = (py + 0.5) * 256.0 / originalPixels.pixelsHigh;
                        if (hypot(nx - 44, ny - 212) <= 32) continue;
                        NSColor *before = [[originalPixels colorAtX:px y:py] colorUsingColorSpace:[NSColorSpace deviceRGBColorSpace]];
                        NSColor *after = [[currentPixels colorAtX:px y:py] colorUsingColorSpace:[NSColorSpace deviceRGBColorSpace]];
                        if (fabs(before.alphaComponent - after.alphaComponent) > 0.02 ||
                            (before.alphaComponent > 0.95 && (fabs(before.redComponent - after.redComponent) > 0.03 || fabs(before.greenComponent - after.greenComponent) > 0.03 || fabs(before.blueComponent - after.blueComponent) > 0.03))) {
                            fprintf(stderr, "Base icon changed outside badge at %ld,%ld: alpha %.3f -> %.3f\n", (long)px, (long)py, before.alphaComponent, after.alphaComponent);
                            return 8;
                        }
                    }
                }
                [currentCanvas release];
                // Sample the lower-left badge in the native backing scale.
                NSInteger x = 44 * bitmap.pixelsWide / 256;
                NSInteger y = 212 * bitmap.pixelsHigh / 256;
                NSColor *dot = [[bitmap colorAtX:x y:y] colorUsingColorSpace:[NSColorSpace deviceRGBColorSpace]];
                // Icon Services also converts the color profile. The Go
                // test checks exact source RGB; here verify displayed green.
                if (dot == nil || dot.greenComponent < 0.6 || dot.greenComponent < dot.redComponent * 1.5 || dot.greenComponent < dot.blueComponent * 1.5 || dot.alphaComponent < 0.95) {
                    fprintf(stderr, "Unexpected badge pixels: bitmap=%ldx%ld color=%.4f,%.4f,%.4f\n", (long)bitmap.pixelsWide, (long)bitmap.pixelsHigh, dot.redComponent, dot.greenComponent, dot.blueComponent);
                    return 5;
                }
                if (!wgSetApplicationConnectionIcon(0)) return 6;
                NSData *reset = [[NSApp applicationIconImage] TIFFRepresentation];
                if ((original != nil || reset != nil) && ![reset isEqualToData:original]) return 7;
            }
        }
        [originalCanvas release];
        [base release];
        [original release];
        puts("PASS: native AppKit preserves icon size and pixels outside the badge, green pixels and exact default restoration across 25 On/Off cycles");
        return 0;
    }
}
