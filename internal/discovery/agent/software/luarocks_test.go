// luarocks_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLuaRocksOutput_ValidInput(t *testing.T) {
	raw := "luasocket\t3.1.0-1\tinstalled\t/usr/local/lib/luarocks/rocks-5.4\nlpeg\t1.1.0-1\tinstalled\t/usr/local/lib/luarocks/rocks-5.4\n"
	result := ParseLuaRocksOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "luasocket", result.Items[0].SoftwareName)
	assert.Equal(t, "3.1.0-1", result.Items[0].Version)
	assert.Equal(t, "luarocks", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "lua")
	assert.False(t, result.HasErrors())
}

func TestParseLuaRocksOutput_EmptyInput(t *testing.T) {
	result := ParseLuaRocksOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseLuaRocksOutput_MalformedLine(t *testing.T) {
	result := ParseLuaRocksOutput("notabseparated\n")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "luarocks", result.Errs[0].Collector)
}

func TestParseLuaRocksOutput_CPEHasTargetSW(t *testing.T) {
	raw := "luasocket\t3.1.0-1\tinstalled\t/usr/local\n"
	result := ParseLuaRocksOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:luasocket:3.1.0-1:*:*:*:*:lua:*:*", result.Items[0].CPE23)
}
