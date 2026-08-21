//go:build !windows

package software

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ownerIsRoot reports whether the file is uid-0-owned.
func ownerIsRoot(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

// A non-root agent never demotes — the tools run fine as the invoking
// user, and dropping privileges is not ours to do.
func TestDemotionForWith_NotRootReturnsNil(t *testing.T) {
	fakeToolOnPath(t, "faketool", "exit 0\n")
	assert.Nil(t, demotionForWith("faketool", 501))
}

// A tool that is not on PATH has nothing to demote for.
func TestDemotionForWith_MissingToolReturnsNil(t *testing.T) {
	assert.Nil(t, demotionForWith("definitely-not-a-real-tool-xyz", 0))
}

// A root-owned tool offers no meaningful demotion target — that host
// falls back to the root-refusal skip.
func TestDemotionForWith_RootOwnedToolReturnsNil(t *testing.T) {
	if fi, err := os.Stat("/bin/sh"); err != nil || !ownerIsRoot(fi) {
		t.Skip("/bin/sh not root-owned on this host")
	}
	assert.Nil(t, demotionForWith("sh", 0))
}

// The demotion target is the tool's owning user, resolved to real
// uid/gid plus HOME/username for the scrubbed child environment.
func TestDemotionForWith_UserOwnedToolYieldsOwnerIdentity(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the fake tool would be root-owned")
	}
	fakeToolOnPath(t, "faketool", "exit 0\n")

	d := demotionForWith("faketool", 0)
	require.NotNil(t, d, "a root agent must demote to the tool's owner")
	assert.Equal(t, uint32(os.Getuid()), d.uid) //#nosec G115 -- test uid fits
	assert.NotEmpty(t, d.home)
	assert.NotEmpty(t, d.username)
}

// applyDemotion must set the credential AND replace the environment —
// leaking root's environment into the demoted child would defeat the
// "reduce the child's reach" half of the mechanism.
func TestApplyDemotion_SetsCredentialAndScrubsEnvironment(t *testing.T) {
	t.Setenv("SUPER_SECRET_TOKEN", "leaky")
	cmd := exec.CommandContext(context.Background(), "true")
	applyDemotion(cmd, &demotion{uid: 123, gid: 456, home: "/home/x", username: "x"})

	require.NotNil(t, cmd.SysProcAttr)
	require.NotNil(t, cmd.SysProcAttr.Credential)
	assert.Equal(t, uint32(123), cmd.SysProcAttr.Credential.Uid)
	assert.Equal(t, uint32(456), cmd.SysProcAttr.Credential.Gid)

	env := strings.Join(cmd.Env, "\n")
	assert.NotContains(t, env, "SUPER_SECRET_TOKEN")
	assert.Contains(t, env, "HOME=/home/x")
	assert.Contains(t, env, "USER=x")
	assert.Contains(t, env, "LOGNAME=x")
	assert.Contains(t, env, "PATH=")
	assert.Len(t, cmd.Env, 4, "the demoted environment is exactly PATH+HOME+USER+LOGNAME")
}

// A nil demotion must leave the command untouched — the normal
// non-root path takes zero overhead from this mechanism.
func TestApplyDemotion_NilIsNoOp(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), "true")
	applyDemotion(cmd, nil)
	assert.Nil(t, cmd.Env)
	if cmd.SysProcAttr != nil {
		assert.Nil(t, cmd.SysProcAttr.Credential)
	}
}
