//go:build !windows

package osutil

import (
	"os/exec"
)

// HideWindow is a no-op on non-Windows platforms.
func HideWindow(cmd *exec.Cmd) {}

// IsDoubleClicked reports whether the binary was launched by double-clicking
// in a graphical file manager (e.g. Windows Explorer). On non-Windows
// platforms this always returns false.
func IsDoubleClicked() bool { return false }

// HideConsole is a no-op on non-Windows platforms.
func HideConsole() {}

// ShowConsole is a no-op on non-Windows platforms.
func ShowConsole() {}

// IsAttachedToConsole always returns false on non-Windows platforms.
func IsAttachedToConsole() bool { return false }
