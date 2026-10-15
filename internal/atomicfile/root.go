package atomicfile

import (
	"crypto/rand"
	"os"
)

// WriteInRoot publishes a private snapshot through an already-open directory.
// Neither a renamed parent nor a destination symlink can redirect publication.
func WriteInRoot(root *os.Root, name string, data []byte, perm os.FileMode) error {
	temp := ".wireguide-" + rand.Text() + ".tmp"
	f, err := root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer root.Remove(temp)
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := root.Rename(temp, name); err != nil {
		return err
	}
	if dir, err := root.Open("."); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
