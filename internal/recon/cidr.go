package recon

import (
	"encoding/binary"
	"fmt"
	"net"
)

func ExpandCIDR(cidrStr string, maxIPs int) ([]string, error) {
	if maxIPs <= 0 {
		maxIPs = 65536
	}

	ip, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidrStr, err)
	}

	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("only IPv4 CIDR expansion is supported: %s", cidrStr)
	}

	maskOnes, maskBits := ipNet.Mask.Size()
	totalHosts := 1 << (maskBits - maskOnes)
	if totalHosts > maxIPs {
		return nil, fmt.Errorf("CIDR %s has %d IPs (exceeds Termux-safe limit of %d; use a smaller subnet like /24 or /20)", cidrStr, totalHosts, maxIPs)
	}

	startIP := binary.BigEndian.Uint32(v4)
	mask := binary.BigEndian.Uint32(ipNet.Mask)
	network := startIP & mask
	broadcast := network | ^mask

	var ips []string
	if totalHosts <= 2 {
		for cur := network; cur <= broadcast; cur++ {
			ips = append(ips, uint32ToIP(cur))
		}
	} else {
		for cur := network + 1; cur < broadcast; cur++ {
			ips = append(ips, uint32ToIP(cur))
		}
	}

	return ips, nil
}

func uint32ToIP(n uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return net.IP(b).String()
}
