//go:build !windows

package software

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// demotion carries the reduced identity a collector child process runs
// under when the agent itself is root but the tool refuses root (brew,
// CocoaPods). Privilege reduction instead of privilege skip: the child
// gets the owning user's uid/gid and a minimal environment — strictly
// less reach than the agent, and exactly the reach the tool demands.
type demotion struct {
	home     string
	username string
	uid      uint32
	gid      uint32
}

// demotionFor returns the demotion to apply for the named tool, or nil
// when none is possible or needed: the agent is not root, the tool is
// not on PATH, or the tool is itself root-owned (nothing meaningful to
// demote to — the root-refusal fallback handles that host).
func demotionFor(binName string) *demotion {
	return demotionForWith(binName, os.Geteuid())
}

// demotionForWith is the euid-injectable core, testable without root.
// The demotion target is the owner of the resolved tool binary: for
// Homebrew that is the "Homebrew-owning user" brew itself insists on,
// and the same ownership convention holds for the CocoaPods gem tree.
func demotionForWith(binName string, euid int) *demotion {
	if euid != 0 {
		return nil
	}
	path, err := exec.LookPath(binName)
	if err != nil {
		return nil
	}
	// brew and friends are typically symlinks into their cellar; the
	// meaningful owner is the target's, not the link's.
	if resolved, rerr := filepath.EvalSymlinks(path); rerr == nil {
		path = resolved
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return nil
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10))
	if err != nil {
		return nil
	}
	return &demotion{
		uid:      st.Uid,
		gid:      st.Gid,
		home:     u.HomeDir,
		username: u.Username,
	}
}

// applyDemotion drops the child to the demotion's identity and replaces
// the inherited environment with the minimal set the package managers
// need (PATH to find their helpers, HOME/USER/LOGNAME for their state
// directories). Root's full environment deliberately does not leak into
// the demoted child.
func applyDemotion(cmd *exec.Cmd, d *demotion) {
	if d == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: d.uid, Gid: d.gid}
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + d.home,
		"USER=" + d.username,
		"LOGNAME=" + d.username,
	}
}
