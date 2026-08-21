package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vulnertrack/kite-collector/internal/discovery/cloud/storage"
)

func TestConfidenceLabel(t *testing.T) {
	assert.Equal(t, "high", confidenceLabel(storage.ConfidenceHigh))
	assert.Equal(t, "medium", confidenceLabel(storage.ConfidenceMedium))
	assert.Equal(t, "low", confidenceLabel(storage.ConfidenceLow))
	assert.Equal(t, "unknown", confidenceLabel(storage.Confidence(0)))
	assert.Equal(t, "unknown", confidenceLabel(storage.Confidence(42)))
}

func TestTruncateSnippet(t *testing.T) {
	assert.Equal(t, "", truncateSnippet("", 10))
	assert.Equal(t, "short", truncateSnippet("short", 10))
	assert.Equal(t, "exactly-10", truncateSnippet("exactly-10", 10), "boundary length is kept whole")
	assert.Equal(t, "0123456789…", truncateSnippet("0123456789extra", 10))
	assert.Equal(t, "line one line two", truncateSnippet("line one\nline two", 60),
		"newlines collapse to spaces so table rows stay on one line")
}

func TestSortStrings(t *testing.T) {
	var empty []string
	sortStrings(empty)
	assert.Nil(t, empty)

	one := []string{"z"}
	sortStrings(one)
	assert.Equal(t, []string{"z"}, one)

	many := []string{"gcs", "aws-s3", "azure", "aws-s3"}
	sortStrings(many)
	assert.Equal(t, []string{"aws-s3", "aws-s3", "azure", "gcs"}, many)
}

func TestUniqueProviders_SortedSet(t *testing.T) {
	matches := []storage.Match{
		{Provider: "gcs"},
		{Provider: "aws-s3"},
		{Provider: "gcs"},
		{Provider: "azure-blob"},
	}
	assert.Equal(t, []string{"aws-s3", "azure-blob", "gcs"}, uniqueProviders(matches))
	assert.Empty(t, uniqueProviders(nil))
}

func TestWriteStorageBatchTable_StatusRowsAndTotals(t *testing.T) {
	results := []batchResult{
		{Target: "https://app.example/app.js", Matches: []storage.Match{
			{Provider: "aws-s3", Signal: "file", Confidence: storage.ConfidenceHigh},
			{Provider: "gcs", Signal: "url", Confidence: storage.ConfidenceLow},
		}},
		{Target: "https://clean.example/x.js"},
		{Target: "https://down.example/y.js", Error: "connect: refused"},
	}

	out := captureStdout(t, func() { writeStorageBatchTable(results) })

	assert.Contains(t, out, "Storage Fingerprint — Batch Scan")
	assert.Contains(t, out, "TARGET")
	assert.Contains(t, out, "aws-s3,gcs", "providers render as a sorted comma list")
	assert.Contains(t, out, "clean")
	assert.Contains(t, out, "error")
	assert.Contains(t, out, "connect: refused")
	assert.Contains(t, out, "3 target(s); 1 with matches, 1 error(s).")
}

func TestWriteStorageBatchTable_EmptyInput(t *testing.T) {
	out := captureStdout(t, func() { writeStorageBatchTable(nil) })
	assert.Contains(t, out, "0 target(s); 0 with matches, 0 error(s).")
}
