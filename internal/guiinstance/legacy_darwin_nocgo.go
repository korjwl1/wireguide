//go:build darwin && !cgo

package guiinstance

func activateLegacyApplication() (bool, error) { return false, nil }
