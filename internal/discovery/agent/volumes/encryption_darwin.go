//go:build darwin

package volumes

import "context"

// newProbe returns the macOS encryption probe.
//
// TODO(cdms-iter): wire `fdesetup status` (FileVault boot volume) and
// `diskutil apfs list -plist` (per-volume APFS encryption state). Until
// then, the probe returns EncUnknown so cross-platform callers run
// unchanged. Stub keeps the build green on darwin while the Linux LUKS
// detector ships first.
func newProbe() EncryptionProbe { return noopProbe{} }

// silence unused-import grumbles in case future patches add helpers.
var _ = context.Background
