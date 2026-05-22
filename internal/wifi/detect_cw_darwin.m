#import <CoreWLAN/CoreWLAN.h>
#import <CoreLocation/CoreLocation.h>
#include <stdlib.h>

// WGLocationDelegate handles CLLocationManager authorization callbacks.
// Kept alive as a static so ARC doesn't release it.
@interface WGLocationDelegate : NSObject <CLLocationManagerDelegate>
@end
@implementation WGLocationDelegate
- (void)locationManagerDidChangeAuthorization:(CLLocationManager *)manager {
    // no-op — we only need the app to appear in Location Services list
}
// Legacy callback for macOS < 11
- (void)locationManager:(CLLocationManager *)manager
    didChangeAuthorizationStatus:(CLAuthorizationStatus)status {
}
@end

static CLLocationManager *gLocManager = nil;
static WGLocationDelegate *gLocDelegate = nil;

// cwRequestLocationAuthorization triggers the CoreLocation authorization flow
// so this .app bundle appears in System Settings → Location Services.
// Must be dispatched to the main thread; safe to call multiple times.
void cwRequestLocationAuthorization(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (gLocManager != nil) return;
        gLocDelegate = [[WGLocationDelegate alloc] init];
        gLocManager = [[CLLocationManager alloc] init];
        gLocManager.delegate = gLocDelegate;
        [gLocManager requestWhenInUseAuthorization];
    });
}

const char* cwCurrentSSID(void) {
    CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
    CWInterface *iface = [client interface];
    if (!iface) return NULL;
    NSString *ssid = [iface ssid];
    if (!ssid || ssid.length == 0) return NULL;
    return strdup([ssid UTF8String]);
}

const char* cwInterfaceName(void) {
    CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
    CWInterface *iface = [client interface];
    if (!iface) return NULL;
    NSString *name = [iface interfaceName];
    if (!name || name.length == 0) return NULL;
    return strdup([name UTF8String]);
}

// ---------- Event-driven SSID monitor ----------
//
// CoreWLAN exposes change notifications via the CWEventDelegate protocol.
// Subscribing to CWEventTypeSSIDDidChange / linkDidChange replaces the
// 5-second polling loop we previously used — the OS calls us only when
// the user actually moves between networks.
//
// Threading: Obj-C delegate callbacks fire on the main thread by default.
// We invoke the C function pointer that Go provided; Go does a non-blocking
// channel send. No locks, no allocations beyond the strdup'd c-string.

@interface WGSSIDDelegate : NSObject <CWEventDelegate>
@end

@implementation WGSSIDDelegate
- (void)ssidDidChangeForWiFiInterfaceWithName:(NSString *)interfaceName {
    extern void goSSIDChanged(const char *);
    CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
    CWInterface *iface = [client interfaceWithName:interfaceName];
    NSString *ssid = iface ? [iface ssid] : nil;
    const char *cstr = (ssid && ssid.length > 0) ? strdup([ssid UTF8String]) : strdup("");
    goSSIDChanged(cstr);
    // goSSIDChanged is responsible for free()ing — it copies into Go memory.
}

// linkDidChange also fires when the user joins/leaves networks. Treat it as
// an SSID-change signal so we don't miss transitions ssidDidChange skipped.
- (void)linkDidChangeForWiFiInterfaceWithName:(NSString *)interfaceName {
    [self ssidDidChangeForWiFiInterfaceWithName:interfaceName];
}
@end

static WGSSIDDelegate *gSSIDDelegate = nil;
static BOOL gSSIDMonitorActive = NO;

// cwStartSSIDMonitor subscribes the singleton delegate to CWWiFiClient
// SSID + link events. Returns 0 on success, non-zero (errno-like) on
// failure — caller (Go) falls back to polling if non-zero.
//
// Defensive against being called from a process without a running
// main-thread runloop (e.g., the helper daemon — which now polls
// instead, but a stray call must NEVER hang the process). We use
// dispatch_async + a 2 s timeout-bounded semaphore so the worst case
// is "return an error" rather than "SIGTRAP / hang forever".
int cwStartSSIDMonitor(void) {
    // If we're on the main thread already, dispatch_sync(main, ...) would
    // deadlock — just run the body inline.
    if ([NSThread isMainThread]) {
        if (gSSIDMonitorActive) return 0;
        CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
        if (!client) return 1;
        if (!gSSIDDelegate) gSSIDDelegate = [[WGSSIDDelegate alloc] init];
        [client setDelegate:gSSIDDelegate];
        NSError *err = nil;
        [client startMonitoringEventWithType:CWEventTypeSSIDDidChange error:&err];
        if (err) return 2;
        [client startMonitoringEventWithType:CWEventTypeLinkDidChange error:&err];
        if (err) return 3;
        gSSIDMonitorActive = YES;
        return 0;
    }

    __block int result = 0;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_main_queue(), ^{
        do {
            if (gSSIDMonitorActive) break;
            CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
            if (!client) { result = 1; break; }
            if (!gSSIDDelegate) gSSIDDelegate = [[WGSSIDDelegate alloc] init];
            [client setDelegate:gSSIDDelegate];
            NSError *err = nil;
            [client startMonitoringEventWithType:CWEventTypeSSIDDidChange error:&err];
            if (err) { result = 2; break; }
            [client startMonitoringEventWithType:CWEventTypeLinkDidChange error:&err];
            if (err) { result = 3; break; }
            gSSIDMonitorActive = YES;
        } while (0);
        dispatch_semaphore_signal(sem);
    });

    // 2 s timeout. If the main-queue runloop is not actually running
    // (headless daemon, etc.) the block above will never execute and the
    // semaphore will never signal — bail out with an error so the Go
    // caller falls back to polling instead of hanging forever.
    if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC)) != 0) {
        return 99; // timeout — no main-queue runloop
    }
    return result;
}

// cwStopSSIDMonitor tears down the subscription. Idempotent — safe to
// call when not active. Same defensive dispatch pattern as start.
void cwStopSSIDMonitor(void) {
    if ([NSThread isMainThread]) {
        if (!gSSIDMonitorActive) return;
        CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
        NSError *err = nil;
        [client stopMonitoringEventWithType:CWEventTypeSSIDDidChange error:&err];
        [client stopMonitoringEventWithType:CWEventTypeLinkDidChange error:&err];
        [client setDelegate:nil];
        gSSIDMonitorActive = NO;
        return;
    }
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_main_queue(), ^{
        if (gSSIDMonitorActive) {
            CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
            NSError *err = nil;
            [client stopMonitoringEventWithType:CWEventTypeSSIDDidChange error:&err];
            [client stopMonitoringEventWithType:CWEventTypeLinkDidChange error:&err];
            [client setDelegate:nil];
            gSSIDMonitorActive = NO;
        }
        dispatch_semaphore_signal(sem);
    });
    // 1 s budget — best-effort. If the main queue isn't running, we
    // can't actually tear down anyway; return so the caller can
    // continue shutdown.
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 1LL * NSEC_PER_SEC));
}
