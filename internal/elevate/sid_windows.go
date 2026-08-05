//go:build windows

package elevate

import "golang.org/x/sys/windows"

// CurrentUserSID returns the current process token's user SID in string
// form (S-1-5-21-…). "" on failure. Note os.Getuid() is -1 on Windows —
// the SID is the only usable owner identity, which is why the helper's
// pipe ACL and peer checks are keyed on it rather than a UID.
func CurrentUserSID() string {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil || u == nil || u.User.Sid == nil {
		return ""
	}
	return u.User.Sid.String()
}
