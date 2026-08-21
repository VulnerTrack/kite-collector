package driver

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCappedBuffer_WriteBelowCap(t *testing.T) {
	t.Parallel()

	c := &cappedBuffer{max: 10}
	n, err := c.Write([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, 5, n, "Write must report the full input length")
	assert.Equal(t, "hello", c.String())
}

func TestCappedBuffer_WritePartialAtCap(t *testing.T) {
	t.Parallel()

	c := &cappedBuffer{max: 8}
	_, err := c.Write([]byte("hello"))
	require.NoError(t, err)

	// Only 3 bytes of room remain: the write must truncate the stored bytes
	// but still report the full length so the writer never errors.
	n, err := c.Write([]byte("world"))
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "hellowor", c.String(), "stored bytes must be capped at max")
	assert.Equal(t, 8, c.Len())
}

func TestCappedBuffer_WriteAfterFullDropsSilently(t *testing.T) {
	t.Parallel()

	c := &cappedBuffer{max: 4}
	_, err := c.Write([]byte("full"))
	require.NoError(t, err)

	n, err := c.Write([]byte("extra"))
	require.NoError(t, err)
	assert.Equal(t, 5, n, "overflow writes still report success")
	assert.Equal(t, "full", c.String(), "no byte beyond max may be stored")
}

func TestStderrTail_CollapsesAndBounds(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "", stderrTail(nil))
	assert.Equal(t, "a b c", stderrTail([]byte("  a\n\tb   c \n")),
		"whitespace runs must collapse to single spaces")

	long := bytes.Repeat([]byte("x"), maxStderrErrBytes+100)
	tail := stderrTail(long)
	assert.Equal(t, maxStderrErrBytes+len("…"), len(tail))
	assert.True(t, strings.HasSuffix(tail, "…"), "over-long stderr must end with an ellipsis")
}

func TestExitError_WithAndWithoutStderr(t *testing.T) {
	t.Parallel()

	err := exitError("pnputil.exe", 3, []byte("  access denied  "))
	assert.EqualError(t, err, "wait pnputil.exe: exit status 3: access denied")

	err = exitError("pnputil.exe", 3, nil)
	assert.EqualError(t, err, "wait pnputil.exe: exit status 3")
}

func TestRunWithLimits_MissingBinary(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "no-such-tool")
	out, err := runWithLimits(context.Background(), missing)
	require.Error(t, err)
	assert.Nil(t, out)
	assert.Contains(t, err.Error(), "start "+missing,
		"a missing binary must surface as a start error, not an exit status")
}

func TestRunWithLimitsTolerateExit_NonZeroExitIsNotError(t *testing.T) {
	bin := writeFakeTool(t, "grumpy-tool", `echo "partial results"
echo "warning: incomplete" >&2
exit 2
`)
	stdout, stderr, code, err := runWithLimitsTolerateExit(context.Background(), bin)
	require.NoError(t, err, "tolerated exit codes must not fold into err")
	assert.Equal(t, 2, code)
	assert.Equal(t, "partial results\n", string(stdout))
	assert.Contains(t, string(stderr), "warning: incomplete")
}

func TestRunWithLimitsTolerateExit_ZeroExit(t *testing.T) {
	bin := writeFakeTool(t, "happy-tool", `echo "ok"
exit 0
`)
	stdout, stderr, code, err := runWithLimitsTolerateExit(context.Background(), bin)
	require.NoError(t, err)
	assert.Equal(t, 0, code)
	assert.Equal(t, "ok\n", string(stdout))
	assert.Empty(t, stderr)
}
