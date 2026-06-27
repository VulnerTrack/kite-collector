package dashboard

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderScanControlsFragment_EnabledWhenCoordinatorWired(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, renderScanControlsFragment(&buf, true))

	out := buf.String()
	assert.Contains(t, out, `hx-post="/api/v1/scan"`, "enabled button must keep the HTMX trigger")
	assert.NotContains(t, out, "disabled", "enabled variant must not render the disabled attribute")
	assert.NotContains(t, out, "title=", "enabled variant must not render a tooltip")
}

func TestRenderScanControlsFragment_DisabledWithTooltipWhenReadOnly(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, renderScanControlsFragment(&buf, false))

	out := buf.String()
	assert.Contains(t, out, "disabled", "read-only variant must render the disabled attribute")
	assert.Contains(t, out, `aria-disabled="true"`, "read-only variant must mark itself disabled for assistive tech")
	assert.Contains(t, out, "title=", "read-only variant must carry a tooltip")
	assert.Contains(t, out, "read-only inspector mode", "tooltip must explain why the button is disabled")
	assert.NotContains(t, out, "hx-post", "read-only variant must not POST to the scan endpoint")
	// The wrapping <span title=...> is required because disabled buttons
	// don't fire mouseover events in some browsers, breaking native title tooltips.
	assert.True(t, strings.HasPrefix(strings.TrimSpace(out), "<span "), "tooltip must wrap the disabled button")
}
