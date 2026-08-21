package dashboard

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

func TestCertDateOnly(t *testing.T) {
	assert.Equal(t, "2026-08-21", certDateOnly("2026-08-21T10:00:00Z"),
		"parseable PKI times reduce to the date")
	assert.Equal(t, "2026-08-21", certDateOnly("2026-08-21 something unparseable"),
		"unparseable-but-long strings keep their first ten characters")
	assert.Equal(t, "short", certDateOnly("short"))
	assert.Equal(t, "", certDateOnly(""))
}

// The filter vocabulary is a closed set; every state must land in the
// right bucket and unknown filters show everything.
func TestCertRowMatchesFilter(t *testing.T) {
	row := func(state string) certRowView { return certRowView{StateKey: state} }

	assert.True(t, certRowMatchesFilter(row(certStateActive), "active"))
	assert.True(t, certRowMatchesFilter(row(certStateExpiring), "active"),
		"expiring certs still count as active")
	assert.True(t, certRowMatchesFilter(row(certStateExpiring), "expiring"))
	assert.False(t, certRowMatchesFilter(row(certStateActive), "expiring"))
	assert.True(t, certRowMatchesFilter(row(certStateExpired), "expired"))
	assert.True(t, certRowMatchesFilter(row(certStateLag), "expired"),
		"renewal-lag rows surface under expired")
	assert.True(t, certRowMatchesFilter(row(certStateRevoked), "revoked"))
	assert.True(t, certRowMatchesFilter(row(certStateSuperseded), "history"))
	assert.False(t, certRowMatchesFilter(row(certStateActive), "revoked"))
	assert.True(t, certRowMatchesFilter(row(certStateActive), "everything-else"),
		"unknown filters pass all rows")
}

func TestActionLabelAndBadgeAndAnchor(t *testing.T) {
	assert.Equal(t, "install agent", actionLabel(installer.ActionInstall))
	assert.Equal(t, "register service", actionLabel(installer.ActionRegisterService))
	assert.Equal(t, "enroll", actionLabel(installer.ActionEnroll))
	assert.Equal(t, "start service", actionLabel(installer.ActionStartService))
	assert.Equal(t, "ready", actionLabel(installer.ActionReady))
	assert.Equal(t, "mystery", actionLabel("mystery"), "unknown tokens echo raw")

	assert.Equal(t, "badge-green", actionBadge(installer.ActionReady))
	assert.Equal(t, "badge-orange", actionBadge(installer.ActionStartService))
	assert.Equal(t, "badge-blue", actionBadge(installer.ActionEnroll))
	assert.Equal(t, "badge-blue", actionBadge(installer.ActionRegisterService))
	assert.Equal(t, "badge-gray", actionBadge(installer.ActionInstall))
	assert.Equal(t, "badge-gray", actionBadge("mystery"))

	assert.Equal(t, "#install-card", anchorForAction(installer.ActionInstall))
	assert.Equal(t, "#install-card", anchorForAction(installer.ActionRegisterService))
	assert.Equal(t, "/kite-login?dashboard=/onboarding#check-card", anchorForAction(installer.ActionEnroll))
	assert.Equal(t, "#stream-card", anchorForAction(installer.ActionStartService))
	assert.Equal(t, "#stream-card", anchorForAction("streaming"))
	assert.Equal(t, "#install-card", anchorForAction("mystery"))
}

func TestAsNumber(t *testing.T) {
	n, ok := asNumber(float64(3.5))
	assert.True(t, ok)
	assert.Equal(t, 3.5, n)

	n, ok = asNumber(json.Number("42"))
	assert.True(t, ok)
	assert.Equal(t, 42.0, n)

	_, ok = asNumber(json.Number("not-a-number"))
	assert.False(t, ok)
	_, ok = asNumber("7")
	assert.False(t, ok, "strings are not silently coerced")
	_, ok = asNumber(nil)
	assert.False(t, ok)
}
