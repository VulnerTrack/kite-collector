package parsers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoModParser(t *testing.T) {
	content := []byte(`module github.com/example/project

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/sync v0.3.0
)

require (
	github.com/bytedance/sonic v1.9.1 // indirect
)
`)

	p := &GoModParser{}
	result, err := p.Parse(context.Background(), "/app/go.mod", content)
	require.NoError(t, err)

	assert.Equal(t, "github.com/example/project", result.ProjectName)
	assert.Len(t, result.Dependencies, 3)

	byName := depMap(result.Dependencies)
	assert.Equal(t, "1.9.1", byName["github.com/gin-gonic/gin"].Version, "v prefix stripped")
	assert.True(t, byName["github.com/gin-gonic/gin"].Direct)
	assert.False(t, byName["github.com/bytedance/sonic"].Direct, "indirect dep")
	assert.Equal(t, "github.com/gin-gonic", byName["github.com/gin-gonic/gin"].Vendor)
}

func TestGoModParser_SingleRequire(t *testing.T) {
	content := []byte(`module test

go 1.21

require github.com/stretchr/testify v1.9.0
`)

	p := &GoModParser{}
	result, err := p.Parse(context.Background(), "/app/go.mod", content)
	require.NoError(t, err)

	assert.Len(t, result.Dependencies, 1)
	assert.Equal(t, "1.9.0", result.Dependencies[0].Version)
}
