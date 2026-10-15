package storage

import (
	"os"
	"testing"
)

func TestSettingsSaveFailsWhenLockUnavailable(t *testing.T) {
	s := NewSettingsStore(t.TempDir())
	if err := s.Save(DefaultSettings()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.path + ".lock"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.path+".lock", 0700); err != nil {
		t.Fatal(err)
	}
	settings := DefaultSettings()
	settings.Language = "ko"
	if err := s.Save(settings); err == nil {
		t.Fatal("Save succeeded without the cross-process lock")
	}
	after, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed save changed settings")
	}
}
