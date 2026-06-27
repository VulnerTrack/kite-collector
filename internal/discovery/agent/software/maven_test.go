// maven_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMavenOutput_ValidInput(t *testing.T) {
	raw := "   org.apache.logging.log4j:log4j-core:jar:2.23.1:compile\n   com.google.guava:guava:jar:33.1.0-jre:compile\n"
	result := ParseMavenOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "log4j-core", result.Items[0].SoftwareName)
	assert.Equal(t, "org.apache.logging.log4j", result.Items[0].Vendor)
	assert.Equal(t, "2.23.1", result.Items[0].Version)
	assert.Equal(t, "maven", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "java")
	assert.False(t, result.HasErrors())
}

func TestParseMavenOutput_EmptyInput(t *testing.T) {
	result := ParseMavenOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseMavenOutput_SkipsNonDependencyLines(t *testing.T) {
	raw := "The following files have been resolved:\n   org.example:lib:jar:1.0:compile\n"
	result := ParseMavenOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "lib", result.Items[0].SoftwareName)
}

func TestParseMavenOutput_CPEHasTargetSW(t *testing.T) {
	raw := "   org.apache.logging.log4j:log4j-core:jar:2.23.1:compile\n"
	result := ParseMavenOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:org.apache.logging.log4j:log4j-core:2.23.1:*:*:*:*:java:*:*", result.Items[0].CPE23)
}
