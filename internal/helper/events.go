package helper

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
)

// statusDTO returns the current connection status for broadcast. Since the
// tunnel package's ConnectionStatus is already an alias for the domain type
// with wire-safe JSON tags, we just dereference and return it — no field-by-
// field translation.
func (h *Helper) statusDTO() ipc.ConnectionStatus {
	return *h.manager.Status()
}

// eventLoop broadcasts status updates to subscribed GUIs on change. Change
// detection is done by JSON round-trip compare (robust against field swaps).
func (h *Helper) eventLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastJSON []byte
	for {
		select {
		case <-h.done:
			return
		case <-ticker.C:
			status := h.statusDTO()
			currentJSON, err := json.Marshal(status)
			if err != nil {
				continue
			}
			if !bytes.Equal(lastJSON, currentJSON) {
				lastJSON = currentJSON
				h.server.Broadcast(ipc.EventStatus, status)
			}
		}
	}
}
