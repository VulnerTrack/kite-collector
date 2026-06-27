// mamba_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMamba_ReusesCondaParser(t *testing.T) {
	// Mamba's output is identical to conda's. Verify the relabelling.
	raw := `[{"name":"numpy","version":"1.26.4","channel":"defaults"}]`
	result := ParseCondaJSON(raw)

	// Simulate what Mamba.Collect does.
	for i := range result.Items {
		result.Items[i].PackageManager = "mamba"
	}

	require.Len(t, result.Items, 1)
	assert.Equal(t, "numpy", result.Items[0].SoftwareName)
	assert.Equal(t, "1.26.4", result.Items[0].Version)
	assert.Equal(t, "mamba", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "python")
}

func TestMamba_Name(t *testing.T) {
	m := NewMamba()
	assert.Equal(t, "mamba", m.Name())
}
