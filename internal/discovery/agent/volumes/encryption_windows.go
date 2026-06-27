//go:build windows

package volumes

import "context"

// newProbe returns the Windows encryption probe.
//
// TODO(cdms-iter): wire WMI Win32_EncryptableVolume (`ProtectionStatus`,
// `EncryptionMethod`) for BitLocker detection. Until then, the probe
// returns EncUnknown so cross-platform callers run unchanged. Stub keeps
// the build green on windows while the Linux LUKS detector ships first.
func newProbe() EncryptionProbe { return noopProbe{} }

var _ = context.Background
