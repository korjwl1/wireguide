package diag

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// localeLangs are the GUI languages; a key missing from any of them renders
// as the raw key there.
var localeLangs = []string{"en", "ko", "ja", "zh"}

func loadLocales(t *testing.T) map[string]map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]map[string]any{}
	for _, l := range localeLangs {
		b, err := os.ReadFile(filepath.Join("..", "..", "frontend", "src", "i18n", l+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var d map[string]map[string]any
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		out[l] = d
	}
	return out
}

// localeString returns section.key in one language ("" when absent).
func localeString(d map[string]map[string]any, section, key string) string {
	s, _ := d[section][key].(string)
	return s
}

// TestDNSChipKeysTranslated asserts that each displayed DNS mode has a chip
// label and hint in all four locales.
func TestDNSChipKeysTranslated(t *testing.T) {
	loc := loadLocales(t)
	for _, mode := range []string{DNSModeGlobal, DNSModeSplit, DNSModeSearch} {
		for _, l := range localeLangs {
			for _, k := range []string{"dns_chip_" + mode, "dns_chip_" + mode + "_hint"} {
				if localeString(loc[l], "tunnel", k) == "" {
					t.Errorf("%s: tunnel.%s missing", l, k)
				}
			}
		}
	}
}
