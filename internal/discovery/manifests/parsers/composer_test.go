package parsers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComposerParser(t *testing.T) {
	content := []byte(`{
		"name": "acme/backend",
		"version": "3.1.0",
		"require": {
			"php": ">=8.1",
			"ext-json": "*",
			"laravel/framework": "^10.0",
			"monolog/monolog": "^3.0"
		},
		"require-dev": {
			"phpunit/phpunit": "^10.0"
		}
	}`)

	p := &ComposerParser{}
	result, err := p.Parse(context.Background(), "/app/composer.json", content)
	require.NoError(t, err)

	assert.Equal(t, "acme/backend", result.ProjectName)
	assert.Len(t, result.Dependencies, 3, "php and ext-json should be skipped")

	byName := depMap(result.Dependencies)
	assert.Equal(t, "laravel", byName["laravel/framework"].Vendor)
	assert.Equal(t, "runtime", byName["laravel/framework"].Scope)
	assert.Equal(t, "dev", byName["phpunit/phpunit"].Scope)
}

func TestComposerLockParser(t *testing.T) {
	content := []byte(`{
		"packages": [
			{"name": "laravel/framework", "version": "v10.48.4"},
			{"name": "monolog/monolog", "version": "3.5.0"}
		],
		"packages-dev": [
			{"name": "phpunit/phpunit", "version": "10.5.11"}
		]
	}`)

	p := &ComposerLockParser{}
	result, err := p.Parse(context.Background(), "/app/composer.lock", content)
	require.NoError(t, err)

	assert.True(t, result.LockfileUsed)
	assert.Len(t, result.Dependencies, 3)

	byName := depMap(result.Dependencies)
	assert.Equal(t, "10.48.4", byName["laravel/framework"].Version, "v prefix should be stripped")
	assert.Equal(t, "dev", byName["phpunit/phpunit"].Scope)
}
