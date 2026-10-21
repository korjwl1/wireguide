//go:build darwin && cgo

package elevate

/*
#cgo LDFLAGS: -framework Foundation -framework ServiceManagement
#include <stdlib.h>
#include "background_approval_darwin.h"
*/
import "C"

import "unsafe"

func backgroundApprovalRequired(plist string) bool {
	path := C.CString(plist)
	defer C.free(unsafe.Pointer(path))
	return C.wgBackgroundApprovalRequired(path) != 0
}
