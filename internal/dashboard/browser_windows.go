//go:build windows

package dashboard

import "os/exec"

func openBrowser(url string) {
	_ = exec.Command("cmd", "/c", "start", url).Start() //#nosec G204 -- url is from trusted internal code
}
