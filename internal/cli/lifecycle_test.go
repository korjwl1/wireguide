package cli

import (
	"runtime"
	"testing"
)

// TestBundleFromExePath pins the lookup that decides WHICH WireGuide.app
// `ctl start` launches.
//
// This exists because getting it wrong is not a cosmetic failure. When the
// CLI cannot identify its own bundle it falls back to resolving the bundle
// ID through LaunchServices, and a build tree next to an installed copy in
// /Applications both claim com.korjwl1.wireguide. LaunchServices then starts
// whichever it likes — observed live: `ctl start` from a dev build launched
// /Applications/WireGuide.app instead, whose LaunchDaemon plist differs, so
// each build kept reinstalling its own plist and prompting for an admin
// password on every launch.
func TestBundleFromExePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		// bundleFromExePath only runs on the darwin launch path, and these
		// fixtures are Unix paths that filepath mangles under Windows
		// separator rules.
		t.Skip("darwin-only bundle lookup; fixtures use Unix paths")
	}
	tests := []struct {
		name string
		exe  string
		want string
	}{
		{
			name: "standard bundle layout",
			exe:  "/Applications/WireGuide.app/Contents/MacOS/wireguide",
			want: "/Applications/WireGuide.app",
		},
		{
			name: "bundle in a build tree",
			exe:  "/Users/me/src/wireguide/bin/WireGuide.app/Contents/MacOS/wireguide",
			want: "/Users/me/src/wireguide/bin/WireGuide.app",
		},
		{
			name: "bare binary on PATH is not in a bundle",
			exe:  "/usr/local/bin/wireguide",
			want: "",
		},
		{
			name: "dev build next to its bundle is not in a bundle",
			exe:  "/Users/me/src/wireguide/bin/wireguide",
			want: "",
		},
		{
			// Only the three levels a real bundle uses are searched, so a
			// directory that merely ends in .app far up the tree does not
			// get mistaken for the enclosing bundle.
			name: "unrelated .app ancestor is out of range",
			exe:  "/Users/me/Weird.app/a/b/c/d/wireguide",
			want: "",
		},
		{
			name: "relative path inside a bundle",
			exe:  "bin/WireGuide.app/Contents/MacOS/wireguide",
			want: "bin/WireGuide.app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bundleFromExePath(tt.exe); got != tt.want {
				t.Errorf("bundleFromExePath(%q) = %q, want %q", tt.exe, got, tt.want)
			}
		})
	}
}
