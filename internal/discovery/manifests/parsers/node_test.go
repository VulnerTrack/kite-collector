package parsers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeParser(t *testing.T) {
	content := []byte(`{
		"name": "my-app",
		"version": "1.0.0",
		"dependencies": {
			"express": "^4.18.2",
			"lodash": "~4.17.21"
		},
		"devDependencies": {
			"jest": "^29.0.0"
		}
	}`)

	p := &NodeParser{}
	result, err := p.Parse(context.Background(), "/app/package.json", content)
	require.NoError(t, err)

	assert.Equal(t, "my-app", result.ProjectName)
	assert.Equal(t, "1.0.0", result.ProjectVersion)
	assert.False(t, result.LockfileUsed)
	assert.Len(t, result.Dependencies, 3)

	byName := depMap(result.Dependencies)
	assert.Equal(t, "4.18.2", byName["express"].Version)
	assert.Equal(t, "runtime", byName["express"].Scope)
	assert.Equal(t, "dev", byName["jest"].Scope)
	assert.True(t, byName["express"].Direct)
}

func TestNodeParser_ScopedPackages(t *testing.T) {
	content := []byte(`{
		"name": "test",
		"dependencies": {
			"@angular/core": "^16.0.0",
			"@types/node": "^20.0.0"
		}
	}`)

	p := &NodeParser{}
	result, err := p.Parse(context.Background(), "/app/package.json", content)
	require.NoError(t, err)

	byName := depMap(result.Dependencies)
	assert.Equal(t, "angular", byName["@angular/core"].Vendor)
	assert.Equal(t, "types", byName["@types/node"].Vendor)
}

func TestNodeLockParser_V3(t *testing.T) {
	content := []byte(`{
		"name": "my-app",
		"version": "2.0.0",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "my-app",
				"version": "2.0.0"
			},
			"node_modules/express": {
				"version": "4.18.2"
			},
			"node_modules/@scope/pkg": {
				"version": "1.0.0",
				"dev": true
			}
		}
	}`)

	p := &NodeLockParser{}
	result, err := p.Parse(context.Background(), "/app/package-lock.json", content)
	require.NoError(t, err)

	assert.Equal(t, "my-app", result.ProjectName)
	assert.True(t, result.LockfileUsed)
	assert.Len(t, result.Dependencies, 2)

	byName := depMap(result.Dependencies)
	assert.Equal(t, "4.18.2", byName["express"].Version)
	assert.Equal(t, "runtime", byName["express"].Scope)
	assert.Equal(t, "dev", byName["@scope/pkg"].Scope)
}

func TestNodeLockParser_V1(t *testing.T) {
	content := []byte(`{
		"name": "old-app",
		"lockfileVersion": 1,
		"dependencies": {
			"lodash": {
				"version": "4.17.21"
			}
		}
	}`)

	p := &NodeLockParser{}
	result, err := p.Parse(context.Background(), "/app/package-lock.json", content)
	require.NoError(t, err)

	assert.True(t, result.LockfileUsed)
	assert.Len(t, result.Dependencies, 1)
	assert.Equal(t, "4.17.21", result.Dependencies[0].Version)
}

func TestNodeParser_InvalidJSON(t *testing.T) {
	p := &NodeParser{}
	_, err := p.Parse(context.Background(), "/app/package.json", []byte(`{invalid`))
	assert.Error(t, err)
}

func depMap(deps []Dependency) map[string]Dependency {
	m := make(map[string]Dependency, len(deps))
	for _, d := range deps {
		m[d.Name] = d
	}
	return m
}
