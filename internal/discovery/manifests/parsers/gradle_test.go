package parsers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGradleParser(t *testing.T) {
	content := []byte(`
plugins {
    id 'java'
}

dependencies {
    implementation 'org.springframework:spring-core:5.3.30'
    api "com.google.guava:guava:32.1.2-jre"
    testImplementation("junit:junit:4.13.2")
    compileOnly 'javax.servlet:servlet-api:2.5'
}
`)

	p := &GradleParser{}
	result, err := p.Parse(context.Background(), "/app/build.gradle", content)
	require.NoError(t, err)

	assert.Len(t, result.Dependencies, 4)

	byName := depMap(result.Dependencies)
	assert.Equal(t, "5.3.30", byName["org.springframework:spring-core"].Version)
	assert.Equal(t, "runtime", byName["org.springframework:spring-core"].Scope)
	assert.Equal(t, "test", byName["junit:junit"].Scope)
	assert.Equal(t, "optional", byName["javax.servlet:servlet-api"].Scope)
}

func TestGradleParser_Kts(t *testing.T) {
	content := []byte(`
dependencies {
    implementation("io.ktor:ktor-server-core:2.3.4")
}
`)

	p := &GradleParser{}
	result, err := p.Parse(context.Background(), "/app/build.gradle.kts", content)
	require.NoError(t, err)

	assert.Len(t, result.Dependencies, 1)
	assert.Equal(t, "2.3.4", result.Dependencies[0].Version)
}
