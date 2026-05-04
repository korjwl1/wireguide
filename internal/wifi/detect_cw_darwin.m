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
