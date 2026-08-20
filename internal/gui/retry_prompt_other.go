//go:build !darwin && !windows

package gui

// askHelperRetry on Linux retries without a dialog: there is no
// universally-available native dialog binary (zenity/kdialog vary by
// desktop), and retrying re-triggers the pkexec prompt, which is itself
// the user-visible surface. The 3-attempt cap in gui.Run bounds this.
// The error detail is already in the logs; there is no dialog to show it in.
func askHelperRetry(string) bool {
	return true
}
