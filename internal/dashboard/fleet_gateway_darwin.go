//go:build darwin

package dashboard

import (
	"net/netip"
	"os/exec"
	"strings"
)

func defaultGatewayIPv4(interfaceName, _ string) string {
	output, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return ""
	}
	var gateway, iface string
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "gateway":
			gateway = fields[1]
		case "interface":
			iface = fields[1]
		}
	}
	if iface != interfaceName {
		return ""
	}
	if ip, err := netip.ParseAddr(gateway); err == nil && ip.Is4() {
		return ip.String()
	}
	return ""
}
