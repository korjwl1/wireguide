//go:build darwin && cgo

#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#include "background_approval_darwin.h"

int wgBackgroundApprovalRequired(const char *plistPath) {
    @autoreleasepool {
        if (plistPath == NULL || plistPath[0] == '\0') return 0;
        if (@available(macOS 13.0, *)) {
            NSString *path = [NSString stringWithUTF8String:plistPath];
            if (path == nil) return 0;
            NSURL *url = [NSURL fileURLWithPath:path];
            // Legacy launchd disable overrides and BTM approval are separate.
            // Query the public API without registering or changing the service.
            return [SMAppService statusForLegacyURL:url] == SMAppServiceStatusRequiresApproval;
        }
        return 0;
    }
}
