package software

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Reproduces the field failure "brew list --versions: wait brew: exit
// status 1" seen when the agent runs under sudo: Homebrew hard-refuses
// to run as root ("Running Homebrew as root is extremely dangerous and
// no longer supported"). That is an environment condition, not a
// collector failure — Collect must return a benign empty inventory.
func TestBrewCollect_RootRefusalIsBenign(t *testing.T) {
	fakeToolOnPath(t, "brew", `echo "Error: Running Homebrew as root is extremely dangerous and no longer supported." >&2
echo "As Homebrew does not drop privileges on installation you would be giving all" >&2
echo "build scripts full access to your system." >&2
exit 1
`)

	res, err := NewBrew().Collect(context.Background())
	require.NoError(t, err, "brew's refusal to run as root must not surface as a collector failure")
	assert.Empty(t, res.Items)
	assert.Empty(t, res.Errs)
}

// Any other non-zero brew exit is a genuine failure and must surface —
// with brew's stderr folded in so the log line is diagnosable.
func TestBrewCollect_OtherFailureSurfacesStderr(t *testing.T) {
	fakeToolOnPath(t, "brew", `echo "Error: unknown command: list" >&2
exit 1
`)

	_, err := NewBrew().Collect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown command: list",
		"brew's stderr must be folded into the error for diagnosability")
}

func TestBrewCollect_Success(t *testing.T) {
	fakeToolOnPath(t, "brew", `echo "wget 1.24.5"
echo "openssl@3 3.3.1 3.2.0"
exit 0
`)

	res, err := NewBrew().Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, res.Items, 2)
}
