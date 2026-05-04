#import <CoreWLAN/CoreWLAN.h>
#include <stdlib.h>

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
