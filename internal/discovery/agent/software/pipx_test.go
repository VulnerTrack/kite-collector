package software

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePipxJSON_ValidInput(t *testing.T) {
	raw := `{
		"venvs": {
			"black": {
				"metadata": {
					"main_package": {
						"package": "black",
						"package_version": "24.4.2"
					}
				}
			},
			"ruff": {
				"metadata": {
					"main_package": {
						"package": "ruff",
						"package_version": "0.4.8"
					}
				}
			}
		}
	}`
	result := ParsePipxJSON(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "pipx", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "python")

	names := []string{result.Items[0].SoftwareName, result.Items[1].SoftwareName}
	assert.Contains(t, names, "black")
	assert.Contains(t, names, "ruff")
	assert.False(t, result.HasErrors())
}

func TestParsePipxJSON_EmptyInput(t *testing.T) {
	result := ParsePipxJSON("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParsePipxJSON_EmptyVenvs(t *testing.T) {
	result := ParsePipxJSON(`{"venvs": {}}`)
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParsePipxJSON_InvalidJSON_RecordsError(t *testing.T) {
	result := ParsePipxJSON("{bad")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "pipx", result.Errs[0].Collector)
}

// TestLogPipxDiagnostic_EmitsActionableHint pins the diagnostic Warn shape
// when pipx reports broken venvs. Operators rely on the `hint` attribute
// to learn that they need to run `pipx reinstall-all`.
func TestLogPipxDiagnostic_EmitsActionableHint(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	stderr := []byte("   package eliot has invalid interpreter /usr/bin/python3.13\n" +
		"One or more packages have a missing python interpreter.\n" +
		"    To fix, execute: pipx reinstall-all\n")

	logPipxDiagnostic(1, stderr)

	require.Equal(t, 1, strings.Count(buf.String(), "\n"), "exactly one log record")
	var rec map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rec))

	assert.Equal(t, "WARN", rec["level"])
	assert.Equal(t, "software: pipx reported diagnostic on non-zero exit", rec["msg"])
	assert.EqualValues(t, 1, rec["exit_code"])
	assert.Contains(t, rec["stderr"], "invalid interpreter")
	assert.Equal(t, "pipx may have hidden broken venvs; run `pipx reinstall-all`", rec["hint"])
}

func TestLogPipxDiagnostic_NoHintForUnknownStderr(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	logPipxDiagnostic(2, []byte("connection refused: pipx server unreachable"))

	var rec map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rec))
	assert.EqualValues(t, 2, rec["exit_code"])
	assert.Equal(t, "", rec["hint"], "no hint when stderr doesn't match the known signature")
}

func TestLogPipxDiagnostic_TruncatesLongStderr(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	logPipxDiagnostic(1, []byte(strings.Repeat("x", pipxStderrLogMax+200)))

	var rec map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rec))
	got, _ := rec["stderr"].(string)
	assert.True(t, strings.HasSuffix(got, "…"))
	assert.LessOrEqual(t, len(got), pipxStderrLogMax+len("…"))
}
