package helper

import (
	"os"
	"path/filepath"

	"github.com/korjwl1/wireguide/internal/storage"
)

func (h *Helper) readUserSettingsBytes() ([]byte, error) {
	if h.userFileUID != nil {
		return storage.ReadUserFile(h.userAppSupport, "config.json", *h.userFileUID, h.userFileSID, 4<<20)
	}
	// Direct fixtures supply a private directory without a GUI owner identity.
	return os.ReadFile(filepath.Join(h.userAppSupport, "config.json"))
}
