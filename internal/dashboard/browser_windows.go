//go:build windows

package dashboard

import (
	"golang.org/x/sys/windows"
)

func openBrowser(url string) {
	u, err := windows.UTF16PtrFromString(url)
	if err == nil {
		_ = windows.ShellExecute(0, nil, u, nil, nil, windows.SW_SHOWNORMAL)
	}
}
