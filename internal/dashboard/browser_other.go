//go:build !windows && !darwin

package dashboard

import "os/exec"

func openBrowser(url string) {
	// xdg-open is the standard on Linux.
	_ = exec.Command("xdg-open", url).Start() //#nosec G204 -- url is from trusted internal code
}
