package main

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/network/compositefingerprint"
)

func webWritersFixtureSummary(endpoint string) compositefingerprint.StackSummary {
	return compositefingerprint.StackSummary{
		Endpoint: endpoint,
		Hosting: &compositefingerprint.Pick{
			Vendor: "vercel", Product: "vercel", Confidence: "high", Sources: []string{"header"},
		},
		WebServer: &compositefingerprint.Pick{
			Vendor: "nginx", Product: "nginx", Confidence: "medium", Sources: []string{"header", "tls"},
		},
		Analytics: []*compositefingerprint.Pick{
			{Vendor: "google", Product: "ga4", Confidence: "low", Sources: []string{"js"}},
			{Vendor: "plausible", Product: "plausible", Confidence: "medium", Sources: []string{"js"}},
		},
	}
}

func TestWriteWebFingerprintNDJSON_SummaryOnlyIsOneLine(t *testing.T) {
	sum := webWritersFixtureSummary("https://a.example")

	out := captureStdout(t, func() {
		require.NoError(t, writeWebFingerprintNDJSON(compositefingerprint.CompositeResult{}, sum, true))
	})

	require.Equal(t, 1, strings.Count(out, "\n"), "NDJSON emits exactly one line")
	var got compositefingerprint.StackSummary
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, sum, got)
}

func TestWriteWebFingerprintNDJSON_FullDocWrapsSummaryAndResult(t *testing.T) {
	sum := webWritersFixtureSummary("https://a.example")
	res := compositefingerprint.CompositeResult{Scheme: "https", Host: "a.example", Port: 443}

	out := captureStdout(t, func() {
		require.NoError(t, writeWebFingerprintNDJSON(res, sum, false))
	})

	var doc struct {
		Summary compositefingerprint.StackSummary    `json:"summary"`
		Result  compositefingerprint.CompositeResult `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc))
	assert.Equal(t, sum, doc.Summary)
	assert.Equal(t, "a.example", doc.Result.Host)
	assert.Equal(t, 443, doc.Result.Port)
}

func TestWriteWebFingerprintBatchNDJSON_OneLinePerRecord(t *testing.T) {
	sum := webWritersFixtureSummary("https://a.example")
	records := []webBatchRecord{
		{
			Target: "https://a.example", Summary: &sum,
			Result: &compositefingerprint.CompositeResult{Host: "a.example"},
		},
		{Target: "https://down.example", Error: "dial timeout"},
	}

	out := captureStdout(t, func() {
		require.NoError(t, writeWebFingerprintBatchNDJSON(records, false))
	})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 2)
	var full webBatchRecord
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &full))
	assert.Equal(t, "https://a.example", full.Target)
	require.NotNil(t, full.Result)

	// summaryOnly drops the raw result payload but keeps target + error.
	out = captureStdout(t, func() {
		require.NoError(t, writeWebFingerprintBatchNDJSON(records, true))
	})
	lines = strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 2)
	assert.NotContains(t, lines[0], `"result"`)
	var slim webBatchSummaryRecord
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &slim))
	assert.Equal(t, "https://down.example", slim.Target)
	assert.Equal(t, "dial timeout", slim.Error)
	assert.Nil(t, slim.Summary)
}

func TestWriteWebFingerprintCSV_OneRowPerPick(t *testing.T) {
	sum := webWritersFixtureSummary("https://a.example")

	out := captureStdout(t, func() {
		require.NoError(t, writeWebFingerprintCSV("https://a.example", sum))
	})

	records, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 5, "header + hosting + webserver + two analytics picks")
	assert.Equal(t, []string{"target", "layer", "vendor", "product", "confidence", "sources"}, records[0])
	assert.Equal(t, []string{"https://a.example", "hosting", "vercel", "vercel", "high", "header"}, records[1])
	assert.Equal(t, []string{"https://a.example", "webserver", "nginx", "nginx", "medium", "header,tls"}, records[2])
	assert.Equal(t, []string{"https://a.example", "analytics", "google", "ga4", "low", "js"}, records[3])
	assert.Equal(t, []string{"https://a.example", "analytics", "plausible", "plausible", "medium", "js"}, records[4])
}

func TestWriteWebFingerprintBatchCSV_ErrorRowsAndNilSummariesSkipped(t *testing.T) {
	sum := webWritersFixtureSummary("https://ok.example")
	records := []webBatchRecord{
		{Target: "https://ok.example", Summary: &sum},
		{Target: "https://down.example", Error: "tls: handshake failure"},
		{Target: "https://empty.example"}, // no summary → no rows
	}

	out := captureStdout(t, func() {
		require.NoError(t, writeWebFingerprintBatchCSV(records))
	})

	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 6, "header + 4 pick rows + 1 error row")
	assert.Equal(t, []string{"https://down.example", "error", "", "tls: handshake failure", "", ""}, rows[5])
	for _, row := range rows[1:] {
		assert.NotEqual(t, "https://empty.example", row[0], "summary-less record must emit no rows")
	}
}

func TestWriteWebFingerprintBatchText_ErrorNilAndFullRecords(t *testing.T) {
	sum := webWritersFixtureSummary("https://text.example")
	records := []webBatchRecord{
		{Target: "https://down.example", Error: "connection refused"},
		{Target: "https://odd.example"}, // neither result nor summary
		{
			Target: "https://text.example", Summary: &sum,
			Result: &compositefingerprint.CompositeResult{},
		},
	}

	out := captureStdout(t, func() { writeWebFingerprintBatchText(records) })

	assert.Contains(t, out, "=== https://down.example ===")
	assert.Contains(t, out, "[error] connection refused")
	assert.Contains(t, out, "=== https://odd.example ===")
	assert.Contains(t, out, "(no result)")
	assert.Contains(t, out, "=== https://text.example ===")
	assert.Contains(t, out, "endpoint: https://text.example")
	assert.Contains(t, out, "vercel")
}
