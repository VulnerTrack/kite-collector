//go:build linux

package dashboard

import (
	"encoding/hex"
	"os"
	"strings"
)

// defaultGatewayIPv4 reads the kernel route table. Gateway addresses in
// /proc/net/route are little-endian hexadecimal values.
func defaultGatewayIPv4(interfaceName, _ string) string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != interfaceName || fields[1] != "00000000" || fields[3] == "0000" {
			continue
		}
		bytes, err := hex.DecodeString(fields[2])
		if err != nil || len(bytes) != 4 {
			continue
		}
		return strings.Join([]string{itoaByte(bytes[3]), itoaByte(bytes[2]), itoaByte(bytes[1]), itoaByte(bytes[0])}, ".")
	}
	return ""
}

func itoaByte(value byte) string {
	const digits = "0123456789"
	if value >= 100 {
		return string([]byte{digits[value/100], digits[(value/10)%10], digits[value%10]})
	}
	if value >= 10 {
		return string([]byte{digits[value/10], digits[value%10]})
	}
	return string(digits[value])
}
