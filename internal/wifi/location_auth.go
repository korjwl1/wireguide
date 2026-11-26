package wifi

// Location Services authorization states reported to the GUI. Only the
// GUI process may call LocationAuthorization: the helper runs as root and
// must never request or report an authorization of its own.
const (
	LocationAuthorized    = "authorized"
	LocationDenied        = "denied"
	LocationRestricted    = "restricted"
	LocationNotDetermined = "not_determined"
	LocationUnknown       = "unknown"
)

// locationAuthRawFn is the platform read (stubbed in tests).
var locationAuthRawFn = locationAuthorizationRaw

// mapLocationAuthStatus converts a raw CLAuthorizationStatus into one of
// the Location* strings. Unknown or unexpected values map to "unknown".
func mapLocationAuthStatus(raw int) string {
	switch raw {
	case 0:
		return LocationNotDetermined
	case 1:
		return LocationRestricted
	case 2:
		return LocationDenied
	case 3, 4:
		return LocationAuthorized
	default:
		return LocationUnknown
	}
}

// LocationAuthorization reports this process's Location Services status:
// authorized / denied / restricted / not_determined, or unknown when it
// cannot be read (error, macOS < 11, or a non-macOS platform).
func LocationAuthorization() string {
	return mapLocationAuthStatus(locationAuthRawFn())
}
