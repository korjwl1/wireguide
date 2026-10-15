package update

import (
	"runtime"
	"strings"
)

// matchAsset picks the release asset matching the running OS+arch.
// It prefers exact ".dmg/.zip/.exe/.tar.gz" extensions over auxiliary
// artifacts (debug symbols, manifests) when multiple candidates
// would match.
func matchAsset(assets []Asset) string {
	arch := runtime.GOARCH

	osNames := []string{runtime.GOOS}
	switch runtime.GOOS {
	case "darwin":
		osNames = append(osNames, "macos", "osx")
	case "windows":
		osNames = append(osNames, "win", "win64")
	}

	preferredExt := preferredExtensions(runtime.GOOS)

	// Pass 1: token-anchored OS+arch match with preferred extension.
	for _, ext := range preferredExt {
		for _, a := range assets {
			name := strings.ToLower(a.Name)
			if !strings.HasSuffix(name, ext) {
				continue
			}
			if assetMatchesOSArch(name, osNames, arch) {
				return a.Name
			}
		}
	}
	// Pass 2: token-anchored OS+arch with any extension (fallback
	// for releases that ship .pkg / .app.tar.gz / etc.).
	for _, a := range assets {
		name := strings.ToLower(a.Name)
		if assetMatchesOSArch(name, osNames, arch) {
			return a.Name
		}
	}
	return ""
}

func assetMatchesOSArch(name string, osNames []string, arch string) bool {
	hasArch := matchTokenAnchored(name, arch)
	if !hasArch {
		return false
	}
	for _, osn := range osNames {
		if matchTokenAnchored(name, osn) {
			return true
		}
	}
	return false
}

// matchTokenAnchored returns true if `token` appears in `name`
// surrounded by start-of-string / dash / underscore / dot on the
// left, and the same OR end-of-token-followed-by-extension on the
// right. Prevents `arm` matching inside `arm64` and similar.
func matchTokenAnchored(name, token string) bool {
	idx := 0
	for idx < len(name) {
		i := strings.Index(name[idx:], token)
		if i < 0 {
			return false
		}
		start := idx + i
		end := start + len(token)
		// Left boundary
		leftOK := start == 0
		if !leftOK {
			c := name[start-1]
			leftOK = c == '-' || c == '_' || c == '.'
		}
		// Right boundary
		rightOK := end == len(name)
		if !rightOK {
			c := name[end]
			rightOK = c == '-' || c == '_' || c == '.'
		}
		if leftOK && rightOK {
			return true
		}
		idx = start + 1
	}
	return false
}

// isCanonicalChecksumName matches only well-known checksum-file
// names (case-insensitive). New tooling tends to use one of these.
func isCanonicalChecksumName(name string) bool {
	switch strings.ToLower(name) {
	case "sha256sums", "sha256sums.txt", "checksums.txt", "checksums",
		"sha256.txt", "shasums":
		return true
	}
	return false
}

func preferredExtensions(goos string) []string {
	switch goos {
	case "darwin":
		return []string{".dmg", ".zip", ".pkg"}
	case "linux":
		return []string{".tar.gz", ".tar.xz", ".deb", ".rpm", ".appimage"}
	case "windows":
		return []string{".exe", ".msi", ".zip"}
	}
	return []string{".zip", ".tar.gz"}
}
