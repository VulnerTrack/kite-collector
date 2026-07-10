package connectorkit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGuard(t *testing.T) {
	g := NewGuard("kandji")
	require.NotNil(t, g)
	assert.Equal(t, "kandji", g.Source, "guard is attributed to the source")

	// A normal page passes; the guard is usable straight away.
	require.NoError(t, g.NextPage(1024))
	assert.Equal(t, 1, g.Iterations())
	assert.Equal(t, int64(1024), g.BytesTotal())
}
