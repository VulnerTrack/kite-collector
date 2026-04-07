//go:build darwin

package dashboard

import "os/exec"

func openBrowser(url string) {
	_ = exec.Command("open", url).Start() //#nosec G204 -- url is from trusted internal code
}
