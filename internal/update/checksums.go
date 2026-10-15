package update

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// fetchExpectedHash downloads a SHA256SUMS-style file and extracts
// the hash for the given asset name. Supported formats:
//
//   - GNU coreutils: "<hex-hash>  <filename>" (two spaces, text mode)
//   - GNU coreutils: "<hex-hash> *<filename>" (binary mode, leading *)
//   - BSD-style:     "SHA256 (<filename>) = <hex-hash>"
//   - filenames containing spaces (rare, but legal — the hash is
//     still the first whitespace-delimited token)
//
// Returns an empty string if the URL fetch fails or no line matches.
func fetchExpectedHash(ctx context.Context, checksumURL, assetName string, client *http.Client) string {
	if err := checkUpdateRawURL(checksumURL); err != nil {
		return ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checksumURL, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return ""
	}
	return parseExpectedHash(body, assetName)
}

// parseExpectedHash extracts the hash for assetName from SHA256SUMS-style
// content. Factored out of fetchExpectedHash so DownloadUpdate can run the
// same parser over the SIGNATURE-VERIFIED bytes — the authoritative source —
// instead of a separately-fetched copy. Returns "" when no line matches.
func parseExpectedHash(body []byte, assetName string) string {
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// BSD-style first: "SHA256 (filename) = hash"
		if hash := matchBSDChecksumLine(line, assetName); hash != "" {
			return hash
		}
		// GNU/coreutils: hash whitespace [*]filename
		// strings.Fields collapses runs of whitespace, but the
		// filename can itself contain spaces — split *only* on the
		// first run so the rest of the line stays intact.
		idx := indexAnyWhitespace(line)
		if idx < 0 {
			continue
		}
		hash := line[:idx]
		filename := strings.TrimLeft(line[idx:], " \t")
		// Optional leading '*' indicates binary mode.
		filename = strings.TrimPrefix(filename, "*")
		if !isHexString(hash) {
			continue
		}
		if strings.EqualFold(filename, assetName) {
			return hash
		}
	}
	return ""
}

var bsdChecksumLine = regexp.MustCompile(`^SHA256\s*\(\s*(.+?)\s*\)\s*=\s*([0-9a-fA-F]+)\s*$`)

func matchBSDChecksumLine(line, assetName string) string {
	m := bsdChecksumLine.FindStringSubmatch(line)
	if len(m) != 3 {
		return ""
	}
	if strings.EqualFold(m[1], assetName) {
		return m[2]
	}
	return ""
}

func indexAnyWhitespace(s string) int {
	for i, r := range s {
		if r == ' ' || r == '\t' {
			return i
		}
	}
	return -1
}

func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
