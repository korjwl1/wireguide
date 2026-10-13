#import <Cocoa/Cocoa.h>
#include "native_tray_darwin.h"

extern void wgNativeTrayAction(char *action);

@interface WGTrayController : NSObject
@property(retain) NSStatusItem *item;
@property(retain) NSMenu *menu;
- (void)selectItem:(NSMenuItem *)sender;
@end

@implementation WGTrayController
- (void)selectItem:(NSMenuItem *)sender {
    NSString *action = sender.representedObject;
    if ([action isKindOfClass:[NSString class]]) {
        wgNativeTrayAction((char *)action.UTF8String);
    }
}
- (void)dealloc {
    [_item release];
    [_menu release];
    [super dealloc];
}
@end

static WGTrayController *wgTray = nil;

static void wgSetTrayImage(NSData *data) {
    NSImage *image = [[NSImage alloc] initWithData:data];
    if (image == nil) return;
    image.size = NSMakeSize(18, 18);
    wgTray.item.button.image = image;
    [image release];
}

void wgNativeTrayCreate(const void *bytes, size_t count) {
    NSData *data = [[NSData alloc] initWithBytes:bytes length:count];
    dispatch_async(dispatch_get_main_queue(), ^{
        if (wgTray == nil) {
            wgTray = [[WGTrayController alloc] init];
            wgTray.item = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
            wgTray.menu = [[[NSMenu alloc] initWithTitle:@"WireGuide"] autorelease];
            wgTray.menu.autoenablesItems = NO;
            // Let AppKit handle mouse, keyboard, highlight and dismissal.
            // Keep the menu attached; no local event monitor or fake event.
            wgTray.item.menu = wgTray.menu;
            wgTray.item.button.toolTip = @"WireGuide";
            [wgTray.item.button setAccessibilityLabel:@"WireGuide"];
            wgSetTrayImage(data);
        }
        [data release];
    });
}

void wgNativeTraySetIcon(const void *bytes, size_t count) {
    NSData *data = [[NSData alloc] initWithBytes:bytes length:count];
    dispatch_async(dispatch_get_main_queue(), ^{
        if (wgTray != nil) wgSetTrayImage(data);
        [data release];
    });
}

void wgNativeTraySetMenu(const char *json) {
    NSString *payload = [[NSString alloc] initWithUTF8String:json];
    dispatch_async(dispatch_get_main_queue(), ^{
        if (wgTray != nil) {
            NSArray *rows = [NSJSONSerialization JSONObjectWithData:[payload dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
            if ([rows isKindOfClass:[NSArray class]]) {
                [wgTray.menu removeAllItems];
                for (NSDictionary *row in rows) {
                    if ([row[@"separator"] boolValue]) {
                        [wgTray.menu addItem:[NSMenuItem separatorItem]];
                        continue;
                    }
                    NSMenuItem *item = [[[NSMenuItem alloc] initWithTitle:row[@"title"] ?: @"" action:@selector(selectItem:) keyEquivalent:@""] autorelease];
                    item.target = wgTray;
                    item.representedObject = row[@"action"];
                    item.enabled = [row[@"enabled"] boolValue];
                    [wgTray.menu addItem:item];
                }
            }
        }
        [payload release];
    });
}

void wgNativeTraySetTooltip(const char *text) {
    NSString *value = [[NSString alloc] initWithUTF8String:text];
    dispatch_async(dispatch_get_main_queue(), ^{
        wgTray.item.button.toolTip = value;
        [wgTray.item.button setAccessibilityLabel:value];
        [value release];
    });
}

void wgNativeTrayDestroy(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (wgTray == nil) return;
        [wgTray.menu cancelTracking];
        [[NSStatusBar systemStatusBar] removeStatusItem:wgTray.item];
        [wgTray release];
        wgTray = nil;
    });
}
