package scan

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteSSEEvent_ShapesFrameCorrectly(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteSSEEvent(&buf, "status", map[string]string{"phase": "running"}))

	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "event: status\n"), "must start with event line: %q", out)
	assert.Contains(t, out, `"phase":"running"`)
	assert.True(t, strings.HasSuffix(out, "\n\n"), "must end with blank line: %q", out)
}

func TestWriteSSEEvent_MarshalFailure(t *testing.T) {
	var buf bytes.Buffer
	// json.Marshal can't encode channels — pick a type it will reject so we
	// cover the error branch without needing a malicious io.Writer.
	err := WriteSSEEvent(&buf, "status", make(chan int))
	require.Error(t, err)
	assert.Empty(t, buf.String(), "no bytes must be written on marshal failure")
}

func TestSSEEventName_Mapping(t *testing.T) {
	assert.Equal(t, "status", SSEEventName(EventStatus))
	assert.Equal(t, "progress", SSEEventName(EventProgress))
	assert.Equal(t, "done", SSEEventName(EventDone))
	assert.Equal(t, "message", SSEEventName(EventType("unknown")))
}
