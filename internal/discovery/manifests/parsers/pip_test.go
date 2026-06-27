package parsers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequirementsParser(t *testing.T) {
	content := []byte(`
flask==2.3.3
requests>=2.31.0
numpy==1.25.2
# this is a comment
-r other.txt
-e ./local-pkg
Django[argon2]>=4.0,<5.0
`)

	p := &RequirementsParser{}
	result, err := p.Parse(context.Background(), "/app/requirements.txt", content)
	require.NoError(t, err)

	assert.Len(t, result.Dependencies, 4)

	byName := depMap(result.Dependencies)
	assert.Equal(t, "2.3.3", byName["flask"].Version)
	assert.Equal(t, "2.31.0", byName["requests"].Version)
	assert.Equal(t, "4.0", byName["django"].Version, "extras stripped, name normalised")
	assert.Equal(t, "runtime", byName["numpy"].Scope)
}

func TestRequirementsParser_NoVersion(t *testing.T) {
	content := []byte("requests\nflask\n")

	p := &RequirementsParser{}
	result, err := p.Parse(context.Background(), "/app/requirements.txt", content)
	require.NoError(t, err)

	assert.Len(t, result.Dependencies, 2)
	assert.Empty(t, result.Dependencies[0].Version)
}

func TestPipfileLockParser(t *testing.T) {
	content := []byte(`{
		"default": {
			"flask": {"version": "==2.3.3"},
			"requests": {"version": "==2.31.0"}
		},
		"develop": {
			"pytest": {"version": "==7.4.0"}
		}
	}`)

	p := &PipfileLockParser{}
	result, err := p.Parse(context.Background(), "/app/Pipfile.lock", content)
	require.NoError(t, err)

	assert.True(t, result.LockfileUsed)
	assert.Len(t, result.Dependencies, 3)

	byName := depMap(result.Dependencies)
	assert.Equal(t, "2.3.3", byName["flask"].Version, "== prefix stripped")
	assert.Equal(t, "dev", byName["pytest"].Scope)
}

func TestPoetryLockParser(t *testing.T) {
	content := []byte(`
[[package]]
name = "flask"
version = "2.3.3"
category = "main"

[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"
`)

	p := &PoetryLockParser{}
	result, err := p.Parse(context.Background(), "/app/poetry.lock", content)
	require.NoError(t, err)

	assert.True(t, result.LockfileUsed)
	assert.Len(t, result.Dependencies, 2)

	byName := depMap(result.Dependencies)
	assert.Equal(t, "2.3.3", byName["flask"].Version)
	assert.Equal(t, "dev", byName["pytest"].Scope)
}

func TestUvLockParser(t *testing.T) {
	content := []byte(`
version = 1

[[package]]
name = "flask"
version = "2.3.3"

[[package]]
name = "uvicorn"
version = "0.30.1"
`)

	p := &UvLockParser{}
	result, err := p.Parse(context.Background(), "/app/uv.lock", content)
	require.NoError(t, err)

	assert.True(t, result.LockfileUsed)
	assert.Len(t, result.Dependencies, 2)
}
