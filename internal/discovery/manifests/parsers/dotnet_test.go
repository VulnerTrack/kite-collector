package parsers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCsprojParser(t *testing.T) {
	content := []byte(`<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Microsoft.Extensions.Logging" Version="8.0.0" />
  </ItemGroup>
</Project>`)

	p := &CsprojParser{}
	result, err := p.Parse(context.Background(), "/app/MyApp.csproj", content)
	require.NoError(t, err)

	assert.Len(t, result.Dependencies, 2)

	byName := depMap(result.Dependencies)
	assert.Equal(t, "13.0.3", byName["Newtonsoft.Json"].Version)
	assert.Equal(t, "Newtonsoft", byName["Newtonsoft.Json"].Vendor)
	assert.Equal(t, "8.0.0", byName["Microsoft.Extensions.Logging"].Version)
}

func TestPackagesConfigParser(t *testing.T) {
	content := []byte(`<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.1" />
  <package id="NUnit" version="3.13.3" />
</packages>`)

	p := &PackagesConfigParser{}
	result, err := p.Parse(context.Background(), "/app/packages.config", content)
	require.NoError(t, err)

	assert.Len(t, result.Dependencies, 2)
	byName := depMap(result.Dependencies)
	assert.Equal(t, "13.0.1", byName["Newtonsoft.Json"].Version)
}
