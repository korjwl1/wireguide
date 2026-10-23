//go:build !windows

package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivilegedStoreRejectsDirectorySymlink(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root-owned administrative links are trusted")
	}
	base := t.TempDir()
	external := filepath.Join(base, "external")
	if err := os.Mkdir(external, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(external, "victim.conf"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "tunnels")
	if err := os.Symlink(external, link); err != nil {
		t.Fatal(err)
	}
	s := NewUserTunnelStore(link, os.Getuid())
	if err := s.Delete("victim"); err == nil {
		t.Fatal("helper followed a user-controlled directory symlink")
	}
	if _, err := os.Stat(filepath.Join(external, "victim.conf")); err != nil {
		t.Fatal("outside file was changed")
	}
	if _, err := os.Stat(filepath.Join(external, ".imports.lock")); !os.IsNotExist(err) {
		t.Fatal("outside directory received a lock file")
	}
}

func TestProfileSymlinkCannotReadOutsideRoot(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "tunnels")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "private")
	secret := "root:$6$SECRETHASH:19000:0:99999"
	if err := os.WriteFile(outside, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "x.conf")); err != nil {
		t.Fatal(err)
	}
	_, err := NewTunnelStore(dir).Load("x")
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("outside data exposed: %v", err)
	}
}
