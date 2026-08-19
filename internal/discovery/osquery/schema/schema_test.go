package schema

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCatalog_LoadsAllTables(t *testing.T) {
	tables := Tables()
	require.Greater(t, len(tables), 250, "the 5.23.1 catalog carries 286 tables")

	apps, ok := Lookup("apps")
	require.True(t, ok)
	assert.Contains(t, apps.Description, "macOS applications")
	assert.Equal(t, []string{"darwin"}, apps.Platforms)
	assert.False(t, apps.Evented)
	require.NotEmpty(t, apps.Columns)
	assert.Equal(t, "name", apps.Columns[0].Name)
	assert.NotEmpty(t, apps.Columns[0].Description)
	assert.True(t, apps.SupportsOS("darwin"))
	assert.False(t, apps.SupportsOS("linux"))
}

func TestCatalog_RequiredColumnsAndEvented(t *testing.T) {
	curl, ok := Lookup("curl")
	require.True(t, ok)
	assert.Equal(t, []string{"url"}, curl.RequiredColumns())

	pe, ok := Lookup("process_events")
	require.True(t, ok)
	assert.True(t, pe.Evented)

	procs, ok := Lookup("processes")
	require.True(t, ok)
	assert.True(t, procs.SupportsOS(runtime.GOOS), "processes exists on every platform")
	assert.Empty(t, procs.RequiredColumns())
}

func TestCatalog_UnknownTable(t *testing.T) {
	_, ok := Lookup("definitely_not_a_table")
	assert.False(t, ok)
}
