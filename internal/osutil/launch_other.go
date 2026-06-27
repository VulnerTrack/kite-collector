//go:build !windows

package osutil

// IsDoubleClicked reports whether the binary was launched by double-clicking
// in a graphical file manager (e.g. Windows Explorer). On non-Windows
// platforms this always returns false.
func IsDoubleClicked() bool { return false }
