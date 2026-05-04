//go:build darwin

package wifi

/*
#cgo LDFLAGS: -framework CoreWLAN -framework CoreLocation -framework Foundation
#include <stdlib.h>

// Implemented in detect_cw_darwin.m (compiled as Objective-C by the Go toolchain).
const char* cwCurrentSSID(void);
const char* cwInterfaceName(void);
void cwRequestLocationAuthorization(void);
*/
import "C"
import "unsafe"

// currentSSIDCoreWLAN queries CoreWLAN for the current SSID.
// On macOS 14+ this is the only API that (a) reliably returns the SSID and
// (b) triggers a CoreLocation authorisation prompt so WireGuide appears in
// System Settings → Privacy & Security → Location Services.
func currentSSIDCoreWLAN() string {
	cs := C.cwCurrentSSID()
	if cs == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(cs))
	return C.GoString(cs)
}

// RequestLocationAuthorization calls CLLocationManager.requestWhenInUseAuthorization
// on the main thread. This registers the app with macOS Location Services so the
// user can grant SSID access in System Settings → Privacy & Security → Location Services.
func RequestLocationAuthorization() {
	C.cwRequestLocationAuthorization()
}

// wifiInterfaceNameCoreWLAN returns the BSD name of the Wi-Fi interface via CoreWLAN.
func wifiInterfaceNameCoreWLAN() string {
	cs := C.cwInterfaceName()
	if cs == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(cs))
	return C.GoString(cs)
}
