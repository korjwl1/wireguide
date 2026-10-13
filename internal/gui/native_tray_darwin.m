#import <Cocoa/Cocoa.h>
#include "native_tray_darwin.h"

extern void wgNativeTrayAction(char *action);

// AppKit tints the template glyph. A separate, transparent badge retains
// connection color and never intercepts the status button's clicks.
@interface WGConnectionBadge : NSView
@property(assign) NSStatusBarButton *owner;
- (instancetype)initWithButton:(NSStatusBarButton *)button;
- (void)detach;
@end
@implementation WGConnectionBadge
- (instancetype)initWithButton:(NSStatusBarButton *)button {
    self = [super initWithFrame:NSMakeRect(0, 0, 5, 5)];
    if (self) {
        _owner = button;
        [button addObserver:self forKeyPath:@"appearsDisabled" options:NSKeyValueObservingOptionInitial context:NULL];
        [self setAccessibilityElement:NO];
    }
    return self;
}
- (void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary *)change context:(void *)context {
    self.alphaValue = _owner.appearsDisabled ? 0.45 : 1.0;
}
- (BOOL)isOpaque { return NO; }
- (NSView *)hitTest:(NSPoint)point { return nil; }
- (void)drawRect:(NSRect)dirtyRect {
    [[NSColor systemGreenColor] setFill];
    [[NSBezierPath bezierPathWithOvalInRect:NSInsetRect(self.bounds, 0.25, 0.25)] fill];
}
- (void)detach {
    if (_owner != nil) [_owner removeObserver:self forKeyPath:@"appearsDisabled"];
    _owner = nil;
}
- (void)dealloc {
    [self detach];
    [super dealloc];
}
@end

@interface WGTrayController : NSObject
@property(retain) NSStatusItem *item;
@property(retain) NSMenu *menu;
@property(retain) WGConnectionBadge *badge;
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
    [_badge detach];
    [_badge removeFromSuperview];
    [_badge release];
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
    image.template = YES;
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
            NSStatusBarButton *button = wgTray.item.button;
            wgTray.badge = [[[WGConnectionBadge alloc] initWithButton:button] autorelease];
            wgTray.badge.hidden = YES;
            wgTray.badge.translatesAutoresizingMaskIntoConstraints = NO;
            [button addSubview:wgTray.badge];
            [NSLayoutConstraint activateConstraints:@[
                [wgTray.badge.widthAnchor constraintEqualToConstant:5],
                [wgTray.badge.heightAnchor constraintEqualToConstant:5],
                [wgTray.badge.centerXAnchor constraintEqualToAnchor:button.centerXAnchor constant:-6],
                [wgTray.badge.centerYAnchor constraintEqualToAnchor:button.centerYAnchor constant:button.isFlipped ? 6 : -6]
            ]];
            [button setAccessibilityValue:@"Disconnected"];
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
            NSArray *rows = [NSJSONSerialization JSONObjectWithData:[payload dataUsingEncoding:NSUTF8StringEncoding] options:0 error:NULL];
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

void wgNativeTraySetConnected(bool connected) {
    dispatch_async(dispatch_get_main_queue(), ^{
        wgTray.badge.hidden = !connected;
        [wgTray.item.button setAccessibilityValue:connected ? @"Connected" : @"Disconnected"];
    });
}
