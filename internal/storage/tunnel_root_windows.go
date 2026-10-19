package storage

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func verifyProfileDirectory(info os.FileInfo, _ int, _ bool) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("profile directory is a reparse point")
	}
	return nil
}

func verifyProfileFile(info os.FileInfo, _ int) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("profile is not a regular file")
	}
	return nil
}

func verifyProfileRoot(root *os.Root, uid int, sid string) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return verifyProfileHandle(f, uid, sid)
}
func verifyProfileHandle(f *os.File, uid int, sid string) error {
	if sid == "" {
		return fmt.Errorf("authenticated profile owner SID is required")
	}
	expected, err := windows.StringToSid(sid)
	if err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !windows.EqualSid(owner, expected) {
		return fmt.Errorf("profile belongs to another Windows user")
	}
	return nil
}
func openProfileRead(root *os.Root, name string) (*os.File, error) { return root.Open(name) }
