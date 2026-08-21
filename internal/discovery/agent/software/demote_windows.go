//go:build windows

package software

import "os/exec"

// demotion is inert on Windows: the root/non-root split this mechanism
// serves (brew, CocoaPods refusing uid 0) has no Windows counterpart,
// and running a child under another Windows account requires a token,
// not a uid — out of scope for the collectors that use this. The
// fields mirror the unix shape so collector logging compiles on both.
type demotion struct {
	home     string
	username string
	uid      uint32
	gid      uint32
}

func demotionFor(string) *demotion { return nil }

func applyDemotion(*exec.Cmd, *demotion) {}
