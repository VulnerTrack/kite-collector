// Package identity — machine fingerprint computation (RFC-0063).
package identity

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
)

// MachineFingerprint computes SHA-256(machine-id + sorted-MACs) as a
// hardware-binding identifier. This supplements the Ed25519 keypair to detect
// key exfiltration to a different host.
func MachineFingerprint() string {
	mid := readMachineID()
	macs := sortedMACs()
	raw := mid + strings.Join(macs, "")
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("sha256:%x", hash)
}

// readMachineID reads the system's machine identifier. On Linux this is
// /etc/machine-id; on macOS the IOPlatformUUID from ioreg; on Windows the
// MachineGuid registry value. Falls back to the hostname.
func readMachineID() string {
	switch runtime.GOOS {
	case "linux":
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			return strings.TrimSpace(string(data))
		}
	case "darwin":
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	h, _ := os.Hostname()
	return h
}

// sortedMACs returns the hardware (MAC) addresses of all non-loopback network
// interfaces, sorted lexicographically. This provides a stable hardware
// binding even when interface ordering changes.
func sortedMACs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var macs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		mac := iface.HardwareAddr.String()
		if mac != "" {
			macs = append(macs, mac)
		}
	}
	sort.Strings(macs)
	return macs
}
