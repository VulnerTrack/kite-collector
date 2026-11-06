//go:build windows
// +build windows

package main

import "golang.org/x/sys/windows"

// Use the Windows URL handler directly, as the modern dashboard does, rather
// than launching rundll32 from PATH. ShellExecute is available on Windows 7.
func openLegacyBrowser(target string) {
	url, err := windows.UTF16PtrFromString(target)
	if err == nil {
		_ = windows.ShellExecute(0, nil, url, nil, nil, windows.SW_SHOWNORMAL)
	}
}
