#import <Cocoa/Cocoa.h>
#include <stdatomic.h>
#include "mainthread_probe_darwin.h"

static _Atomic uint64_t wgMainThreadAcknowledged = 0;
void wgMainThreadPing(uint64_t sequence) {
    dispatch_async(dispatch_get_main_queue(), ^{
        atomic_store(&wgMainThreadAcknowledged, sequence);
    });
}
uint64_t wgMainThreadAck(void) { return atomic_load(&wgMainThreadAcknowledged); }
