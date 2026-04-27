package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
)

// captureLogs swaps slog.Default for the duration of fn and returns each
// emitted record as a parsed map.
func captureLogs(t *testing.T, fn func()) []map[string]any {
	t.Helper()
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	fn()

	var records []map[string]any
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		records = append(records, rec)
	}
	return records
}

func TestLogSoftwareParseErrors_LogsEachError(t *testing.T) {
	errs := []software.CollectError{
		{Collector: "dpkg", Line: 12, Err: errors.New("missing version field"), RawLine: "ii  badpkg  i386"},
		{Collector: "pacman", Line: 3, Err: errors.New("malformed name"), RawLine: ""},
	}
	records := captureLogs(t, func() {
		logSoftwareParseErrors(errs)
	})

	require.Len(t, records, 2)

	assert.Equal(t, "engine: software parse error", records[0]["msg"])
	assert.Equal(t, "WARN", records[0]["level"])
	assert.Equal(t, "dpkg", records[0]["collector"])
	assert.EqualValues(t, 12, records[0]["line"])
	assert.Equal(t, "missing version field", records[0]["error"])
	assert.Equal(t, "ii  badpkg  i386", records[0]["raw_line"])

	assert.Equal(t, "pacman", records[1]["collector"])
	assert.EqualValues(t, 3, records[1]["line"])
}

func TestLogSoftwareParseErrors_TruncatesRawLine(t *testing.T) {
	long := strings.Repeat("x", maxRawLineLog+50)
	records := captureLogs(t, func() {
		logSoftwareParseErrors([]software.CollectError{
			{Collector: "snap", Line: 1, Err: errors.New("nope"), RawLine: long},
		})
	})
	require.Len(t, records, 1)
	got, _ := records[0]["raw_line"].(string)
	assert.Equal(t, maxRawLineLog+len("…"), len(got),
		"raw_line should be truncated to maxRawLineLog plus the ellipsis")
	assert.True(t, strings.HasSuffix(got, "…"))
}

func TestLogSoftwareParseErrors_TruncatesAfterCap(t *testing.T) {
	errs := make([]software.CollectError, maxParseErrorLogs+5)
	for i := range errs {
		errs[i] = software.CollectError{
			Collector: "rpm", Line: i, Err: errors.New("bad"), RawLine: "x",
		}
	}
	records := captureLogs(t, func() {
		logSoftwareParseErrors(errs)
	})

	require.Len(t, records, maxParseErrorLogs+1)
	last := records[len(records)-1]
	assert.Equal(t, "engine: software parse errors truncated", last["msg"])
	assert.EqualValues(t, maxParseErrorLogs, last["shown"])
	assert.EqualValues(t, len(errs), last["total"])
}

func TestLogSoftwareParseErrors_NoOpOnEmpty(t *testing.T) {
	records := captureLogs(t, func() {
		logSoftwareParseErrors(nil)
	})
	assert.Empty(t, records)
}
