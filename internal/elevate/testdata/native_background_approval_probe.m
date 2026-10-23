#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#import <objc/runtime.h>
#include "../background_approval_darwin.h"

static NSInteger fakeStatus;
static int queries;
static BOOL correctURL;

static SMAppServiceStatus probeStatus(id object, SEL selector, NSURL *url) {
    queries++;
    correctURL = [url.path isEqualToString:@"/Library/LaunchDaemons/com.wireguide.approval-probe.plist"];
    return (SMAppServiceStatus)fakeStatus;
}

int main(void) {
    @autoreleasepool {
        if (@available(macOS 13.0, *)) {
            const char *installed = "/Library/LaunchDaemons/com.wireguide.helper.plist";
            NSURL *url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:installed]];
            SMAppServiceStatus actual = [SMAppService statusForLegacyURL:url];
            if (wgBackgroundApprovalRequired(installed) != (actual == SMAppServiceStatusRequiresApproval)) return 1;
            printf("Actual legacy approval status: %ld\n", (long)actual);

            Method method = class_getClassMethod([SMAppService class], @selector(statusForLegacyURL:));
            if (method == NULL) return 2;
            IMP original = method_setImplementation(method, (IMP)probeStatus);
            NSInteger statuses[] = {-1, SMAppServiceStatusNotRegistered, SMAppServiceStatusEnabled,
                SMAppServiceStatusRequiresApproval, SMAppServiceStatusNotFound, 99};
            for (int i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++) {
                fakeStatus = statuses[i];
                int before = queries;
                int required = wgBackgroundApprovalRequired("/Library/LaunchDaemons/com.wireguide.approval-probe.plist");
                if (queries != before + 1 || !correctURL || required != (fakeStatus == SMAppServiceStatusRequiresApproval)) return 3;
            }
            int before = queries;
            if (wgBackgroundApprovalRequired(NULL) || wgBackgroundApprovalRequired("") || queries != before) return 4;
            method_setImplementation(method, original);
            puts("PASS: native legacy status query; only requiresApproval blocks; unknown/missing/enabled states and invalid paths do not");
            return 0;
        }
        return 77;
    }
}
