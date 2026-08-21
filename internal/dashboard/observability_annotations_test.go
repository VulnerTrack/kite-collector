package dashboard

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestProbeOutcomeAnnotation(t *testing.T) {
	sev, css, verb := probeOutcomeAnnotation("pass")
	assert.Equal(t, []string{"success", "activity-success", "passed"}, []string{sev, css, verb})
	sev, css, verb = probeOutcomeAnnotation("fail")
	assert.Equal(t, []string{"error", "activity-error", "failed"}, []string{sev, css, verb})
	sev, css, verb = probeOutcomeAnnotation("skip")
	assert.Equal(t, []string{"warn", "activity-warn", "skipped"}, []string{sev, css, verb})
	sev, css, verb = probeOutcomeAnnotation("weird")
	assert.Equal(t, []string{"info", "activity-info", "weird"}, []string{sev, css, verb},
		"unknown outcomes echo the raw value at info")
}

func TestScanStatusAnnotation(t *testing.T) {
	sev, css, verb := scanStatusAnnotation("completed")
	assert.Equal(t, []string{"success", "activity-success", "completed"}, []string{sev, css, verb})
	sev, _, _ = scanStatusAnnotation("failed")
	assert.Equal(t, "error", sev)
	sev, _, verb = scanStatusAnnotation("cancelled")
	assert.Equal(t, "warn", sev)
	assert.Equal(t, "cancelled", verb)
	sev, _, verb = scanStatusAnnotation("queued")
	assert.Equal(t, "info", sev)
	assert.Equal(t, "queued", verb)
}

func TestScanStatusBadge(t *testing.T) {
	assert.Equal(t, "badge-green", scanStatusBadge("completed"))
	assert.Equal(t, "badge-blue", scanStatusBadge("running"))
	assert.Equal(t, "badge-blue", scanStatusBadge("queued"))
	assert.Equal(t, "badge-red", scanStatusBadge("failed"))
	assert.Equal(t, "badge-red", scanStatusBadge("cancelled"))
	assert.Equal(t, "badge-gray", scanStatusBadge("mystery"))
}

// aggregateScanStats: latest metadata, completed-only averaging, the
// in-progress marker, and the no-completed-runs dash.
func TestAggregateScanStats(t *testing.T) {
	assert.Equal(t, scanStats{}, aggregateScanStats(nil), "no runs, zero stats")

	t0 := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	done := func(start time.Time, d time.Duration) model.ScanRun {
		end := start.Add(d)
		return model.ScanRun{StartedAt: start, CompletedAt: &end, Status: model.ScanStatusCompleted}
	}

	// Newest-first, as ListScanRuns returns them.
	runs := []model.ScanRun{
		done(t0.Add(2*time.Hour), 30*time.Second),
		done(t0.Add(1*time.Hour), 10*time.Second),
		done(t0, 20*time.Second),
	}
	s := aggregateScanStats(runs)
	assert.Equal(t, 3, s.Total)
	assert.Equal(t, "30s", s.LatestDuration)
	assert.Equal(t, "20s", s.AverageDuration, "(30+10+20)/3 rounds to 20s")
	assert.Equal(t, "completed", s.LatestStatus)
	assert.Equal(t, "badge-green", s.LatestBadge)
	assert.NotEmpty(t, s.TrendSVG, "completed runs draw the sparkline")

	// Latest still running: duration reads in-progress, average uses the
	// completed remainder.
	inProgress := model.ScanRun{StartedAt: t0.Add(3 * time.Hour), Status: model.ScanStatusRunning}
	s = aggregateScanStats(append([]model.ScanRun{inProgress}, runs...))
	assert.Equal(t, "in progress", s.LatestDuration)
	assert.Equal(t, "20s", s.AverageDuration)

	// Nothing completed at all: the average is an em-dash.
	s = aggregateScanStats([]model.ScanRun{inProgress})
	assert.Equal(t, "—", s.AverageDuration)
	assert.Equal(t, "in progress", s.LatestDuration)
}
