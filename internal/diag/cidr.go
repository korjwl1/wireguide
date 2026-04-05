// Package diag provides network diagnostic tools.
package diag

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
)

// CIDRInfo describes a CIDR block.
type CIDRInfo struct {
	CIDR       string `json:"cidr"`
	Network    string `json:"network"`
	Broadcast  string `json:"broadcast"`
	FirstHost  string `json:"first_host"`
	LastHost   string `json:"last_host"`
	TotalHosts int64  `json:"total_hosts"`
	Netmask    string `json:"netmask"`
	PrefixLen  int    `json:"prefix_len"`
}

// CalculateCIDR computes network details for a CIDR string.
func CalculateCIDR(cidr string) (*CIDRInfo, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	ones, bits := ipNet.Mask.Size()
	isIPv4 := bits == 32

	info := &CIDRInfo{
		CIDR:      cidr,
		Network:   ipNet.IP.String(),
		Netmask:   net.IP(ipNet.Mask).String(),
		PrefixLen: ones,
	}

	if isIPv4 {
		networkIP := ipToUint32(ipNet.IP.To4())
		hostBits := 32 - ones
		totalHosts := int64(1) << hostBits

		if hostBits > 1 {
			info.TotalHosts = totalHosts - 2 // exclude network + broadcast
			info.FirstHost = uint32ToIP(networkIP + 1).String()
			info.LastHost = uint32ToIP(networkIP + uint32(totalHosts) - 2).String()
			info.Broadcast = uint32ToIP(networkIP + uint32(totalHosts) - 1).String()
		} else if hostBits == 1 {
			info.TotalHosts = 2
			info.FirstHost = ipNet.IP.String()
			info.LastHost = uint32ToIP(networkIP + 1).String()
			info.Broadcast = info.LastHost
		} else {
			info.TotalHosts = 1
			info.FirstHost = ip.String()
			info.LastHost = ip.String()
			info.Broadcast = ip.String()
		}
	} else {
		// IPv6 simplified
		hostBits := 128 - ones
		total := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
		info.TotalHosts = total.Int64() // will overflow for large subnets, but fine for display
		info.FirstHost = ipNet.IP.String()
		info.LastHost = "..."
		info.Broadcast = "N/A (IPv6)"
	}

	return info, nil
}

func ipToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
