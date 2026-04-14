package parsers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGemfileParser(t *testing.T) {
	content := []byte(`
source "https://rubygems.org"

gem "rails", "~> 7.0"
gem "pg", ">= 0.18"
gem "puma", "~> 5.0"
gem 'nokogiri'

group :development, :test do
  gem "rspec-rails"
end
`)

	p := &GemfileParser{}
	result, err := p.Parse(context.Background(), "/app/Gemfile", content)
	require.NoError(t, err)

	assert.Len(t, result.Dependencies, 5)

	byName := depMap(result.Dependencies)
	assert.Equal(t, "7.0", byName["rails"].Version, "~> prefix stripped")
	assert.Equal(t, "0.18", byName["pg"].Version, ">= prefix stripped")
	assert.Empty(t, byName["nokogiri"].Version)
	assert.True(t, byName["rails"].Direct)
}

func TestGemfileLockParser(t *testing.T) {
	content := []byte(`GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.8)
      actioncable (= 7.0.8)
    pg (1.5.4)
    puma (5.6.7)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  rails (~> 7.0)
  pg (>= 0.18)
  puma (~> 5.0)
`)

	p := &GemfileLockParser{}
	result, err := p.Parse(context.Background(), "/app/Gemfile.lock", content)
	require.NoError(t, err)

	assert.True(t, result.LockfileUsed)
	assert.Len(t, result.Dependencies, 4, "includes transitive deps")

	byName := depMap(result.Dependencies)
	assert.Equal(t, "7.0.8", byName["rails"].Version)
	assert.Equal(t, "7.0.8", byName["actioncable"].Version)
	assert.Equal(t, "1.5.4", byName["pg"].Version)
}
