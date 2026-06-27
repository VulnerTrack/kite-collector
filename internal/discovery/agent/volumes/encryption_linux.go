//go:build linux

package volumes

import (
	"context"
	"os"
	"strings"
)

// newProbe returns the Linux LUKS/dm-crypt detector. It reads
// /proc/self/mounts (already loaded by gopsutil) and the /sys/block tree
// to classify each device. No subprocesses, no shell-outs.
//
// Detection logic:
//   - device path starts with /dev/mapper/ AND the underlying block has a
//     `dm/uuid` starting with "CRYPT-LUKS2-" → EncLUKS2
//   - device path starts with /dev/mapper/ AND dm/uuid starts with
//     "CRYPT-LUKS1-" → EncLUKS
//   - device path starts with /dev/mapper/ but uuid is missing/unreadable
//     → EncLUKS (best-effort) — most mapper devices on modern distros are
//     LUKS-backed; rare non-crypt mapper uses (LVM raw, multipath) are
//     overwhelmingly less common than encrypted setups.
//
// State is always EncStateUnlocked when we can see the mount — a locked
// LUKS volume is not mounted and therefore not in /proc/self/mounts.
func newProbe() EncryptionProbe { return linuxProbe{} }

type linuxProbe struct{}

func (linuxProbe) Probe(_ context.Context, _ /*mountPoint*/, device, _ /*filesystem*/ string) (Encryption, EncryptionState) {
	if !strings.HasPrefix(device, "/dev/mapper/") {
		return EncNone, EncStateUnknown
	}
	name := strings.TrimPrefix(device, "/dev/mapper/")
	uuid := readDMUUID(name)
	switch {
	case strings.HasPrefix(uuid, "CRYPT-LUKS2-"):
		return EncLUKS2, EncStateUnlocked
	case strings.HasPrefix(uuid, "CRYPT-LUKS1-"), strings.HasPrefix(uuid, "CRYPT-LUKS-"):
		return EncLUKS, EncStateUnlocked
	case strings.HasPrefix(uuid, "CRYPT-"):
		// Some generic dm-crypt without LUKS metadata.
		return EncLUKS, EncStateUnlocked
	case strings.HasPrefix(uuid, "LVM-"):
		// Plain LVM, not crypto.
		return EncNone, EncStateUnknown
	}
	// Unknown mapper type — be conservative.
	return EncUnknown, EncStateUnknown
}

// readDMUUID returns the dm/uuid attribute of a device-mapper device, or
// the empty string on any error. Reads stop at the first newline.
func readDMUUID(name string) string {
	data, err := os.ReadFile("/sys/block/" + name + "/dm/uuid") //#nosec G304 -- name is sourced from /proc/self/mounts, not user input
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
