//go:build !linux

package update

// Only used when callers explicitly ask for Linux asset preferences.
func linuxPackageFormat() string { return "deb" }
