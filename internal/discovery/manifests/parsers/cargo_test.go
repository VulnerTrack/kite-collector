package parsers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCargoTomlParser(t *testing.T) {
	content := []byte(`
[package]
name = "my-crate"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.32", features = ["full"] }

[dev-dependencies]
criterion = "0.5"

[build-dependencies]
cc = "1.0"
`)

	p := &CargoTomlParser{}
	result, err := p.Parse(context.Background(), "/app/Cargo.toml", content)
	require.NoError(t, err)

	assert.Equal(t, "my-crate", result.ProjectName)
	assert.Equal(t, "0.1.0", result.ProjectVersion)
	assert.Len(t, result.Dependencies, 4)

	byName := depMap(result.Dependencies)
	assert.Equal(t, "1.0", byName["serde"].Version)
	assert.Equal(t, "1.32", byName["tokio"].Version, "table format version extracted")
	assert.Equal(t, "dev", byName["criterion"].Scope)
	assert.Equal(t, "build", byName["cc"].Scope)
}

func TestCargoLockParser(t *testing.T) {
	content := []byte(`
[[package]]
name = "my-crate"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.188"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.32.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)

	p := &CargoLockParser{}
	result, err := p.Parse(context.Background(), "/app/Cargo.lock", content)
	require.NoError(t, err)

	assert.True(t, result.LockfileUsed)
	assert.Equal(t, "my-crate", result.ProjectName, "root package detected")
	assert.Len(t, result.Dependencies, 2, "root package excluded from deps")

	byName := depMap(result.Dependencies)
	assert.Equal(t, "1.0.188", byName["serde"].Version)
}
