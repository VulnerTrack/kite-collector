//go:build windows

package dashboard

import (
	"net/netip"
	"os/exec"
	"strings"
)

func defaultGatewayIPv4(_ string, localIP string) string {
	output, err := exec.Command("route.exe", "print", "-4").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" || fields[3] != localIP {
			continue
		}
		if ip, err := netip.ParseAddr(fields[2]); err == nil && ip.Is4() {
			return ip.String()
		}
	}
	return ""
}
