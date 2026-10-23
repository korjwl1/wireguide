package helper

import (
	"log/slog"
	"net"

	"github.com/korjwl1/wireguide/internal/ipc"
)

func (h *Helper) reportAutomationOverlap(name, cidr string, addr net.IP) {
	signature := cidr + ":" + addr.String()
	h.wifiMu.Lock()
	if h.automationSkipped == nil {
		h.automationSkipped = make(map[string]string)
	}
	repeated := h.automationSkipped[name] == signature
	h.automationSkipped[name] = signature
	h.wifiMu.Unlock()
	if repeated {
		return
	}
	slog.Info("automation: not connecting, tunnel AllowedIPs overlap the local network",
		"tunnel", name, "cidr", cidr, "local_address", addr.String())
	if h.server != nil {
		h.server.Broadcast(ipc.EventAutomationSkipped, ipc.AutomationSkippedPayload{
			TunnelName: name, Reason: "lan_overlap",
		})
	}
}

func (h *Helper) clearAutomationSkip(name string) {
	h.wifiMu.Lock()
	delete(h.automationSkipped, name)
	h.wifiMu.Unlock()
}
