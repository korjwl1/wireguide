#!/bin/bash
# Stop the helper process if running
pkill -f "wireguide --helper" 2>/dev/null || true

# Clean up nftables rules
nft delete table inet wireguide 2>/dev/null || true
nft delete table inet wireguide_dns 2>/dev/null || true

# Clean up IPC sockets
rm -f /tmp/wireguide-*/wireguide.sock 2>/dev/null || true

# Clean up state directory
rm -rf /var/lib/wireguide/ 2>/dev/null || true
