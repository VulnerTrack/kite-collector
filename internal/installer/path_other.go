//go:build !windows

package installer

// ConfigurePath is a no-op on non-Windows platforms.
func ConfigurePath(opts Options) error {
	return nil
}
