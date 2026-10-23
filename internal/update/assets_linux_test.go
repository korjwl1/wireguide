package update

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestLinuxAssetFollowsInstalledPackage(t *testing.T) {
	for _, tc := range []struct {
		name, rpm, dpkgQuery string
		dpkg                 bool
		want                 string
	}{
		{"RPM with dpkg available", "exit 0", "exit 1", true, "rpm"},
		{"DEB with rpm available", "exit 1", "printf 'install ok installed'", true, "deb"},
		{"unpackaged RPM host", "exit 1", "", false, "rpm"},
		{"removed DEB receipt", "exit 1", "printf 'deinstall ok config-files'", false, "rpm"},
		{"unpackaged with both tools", "exit 1", "exit 1", true, "deb"},
		{"no package manager", "", "", false, "deb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range map[string]string{"rpm": tc.rpm, "dpkg-query": tc.dpkgQuery} {
				if body != "" {
					writePackageTool(t, dir, name, body)
				}
			}
			if tc.dpkg {
				writePackageTool(t, dir, "dpkg", "exit 0")
			}
			t.Setenv("PATH", dir)
			if got := linuxPackageFormat(); got != tc.want {
				t.Fatalf("format = %q, want %q", got, tc.want)
			}
			// Archives and the other package format must not take precedence
			// over the native package, regardless of asset ordering.
			prefix := "WireGuide-linux-" + runtime.GOARCH
			assets := []Asset{{Name: prefix + ".tar.gz"}, {Name: prefix + ".deb"}, {Name: prefix + ".rpm"}}
			if got, want := matchAsset(assets), prefix+"."+tc.want; got != want {
				t.Fatalf("asset = %q, want %q", got, want)
			}
		})
	}
}

func TestLinuxPackageQueryHonorsDeadline(t *testing.T) {
	dir := t.TempDir()
	writePackageTool(t, dir, "rpm", "exec /bin/sleep 10")
	t.Setenv("PATH", dir)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if got := detectLinuxPackageFormat(ctx); got != "rpm" {
		t.Fatalf("fallback format = %q, want rpm", got)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("package query exceeded its deadline: %s", elapsed)
	}
}

func writePackageTool(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
}
