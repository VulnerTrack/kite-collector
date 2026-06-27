//go:build !windows

package main

import "errors"

// runWizard is a no-op on non-Windows platforms. The cobra command surfaces a
// platform-specific error before this is reached; double-click routing in
// main() falls back to runInteractiveMenu when this returns non-nil.
func runWizard() error {
	return errors.New("GUI wizard not supported on this platform")
}
