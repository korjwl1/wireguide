//go:build !darwin

package wifi

func currentSSIDCoreWLAN() string       { return "" }
func wifiInterfaceNameCoreWLAN() string  { return "" }
func RequestLocationAuthorization()      {}
