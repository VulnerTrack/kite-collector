//go:build windows

package installer

import "golang.org/x/sys/windows"

// isPrivileged reports whether the current process is running with
// Administrator privileges. We check membership in the BUILTIN\Administrators
// group via the token elevation flag — that matches what kardianos/service
// requires for a system-mode install on Windows.
func isPrivileged() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer func() { _ = token.Close() }()
	return token.IsElevated()
}
