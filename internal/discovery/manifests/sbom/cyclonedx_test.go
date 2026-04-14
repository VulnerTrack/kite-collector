package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestGenerate_BasicBOM(t *testing.T) {
	asset := model.Asset{
		ID:        uuid.New(),
		AssetType: model.AssetTypeSoftwareProject,
		Hostname:  "my-app",
	}

	sw := []model.InstalledSoftware{
		{
			ID:             uuid.New(),
			AssetID:        asset.ID,
			SoftwareName:   "express",
			Vendor:         "express",
			Version:        "4.18.2",
			PackageManager: "node",
			CPE23:          "cpe:2.3:a:*:express:4.18.2:*:*:*:*:node.js:*:*",
		},
		{
			ID:             uuid.New(),
			AssetID:        asset.ID,
			SoftwareName:   "lodash",
			Vendor:         "lodash",
			Version:        "4.17.21",
			PackageManager: "node",
		},
	}

	bom, err := Generate(asset, sw)
	require.NoError(t, err)

	assert.Equal(t, "CycloneDX", bom.BOMFormat)
	assert.Equal(t, specVersion, bom.SpecVersion)
	assert.Equal(t, 1, bom.Version)
	assert.Contains(t, bom.SerialNumber, "urn:uuid:")
	assert.Equal(t, "my-app", bom.Metadata.Component.Name)
	assert.Len(t, bom.Components, 2)
	assert.Equal(t, "library", bom.Components[0].Type)
	assert.Equal(t, "express", bom.Components[0].Name)
	assert.Equal(t, "4.18.2", bom.Components[0].Version)
	assert.Equal(t, "pkg:npm/express@4.18.2", bom.Components[0].PURL)
}

func TestGenerate_JSON(t *testing.T) {
	asset := model.Asset{
		ID:        uuid.New(),
		AssetType: model.AssetTypeSoftwareProject,
		Hostname:  "test-project",
	}

	bom, err := Generate(asset, nil)
	require.NoError(t, err)

	data, err := bom.JSON()
	require.NoError(t, err)

	// Verify it's valid JSON.
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(data, &parsed))
	assert.Equal(t, "CycloneDX", parsed["bomFormat"])
}

func TestBuildPURL(t *testing.T) {
	tests := []struct {
		ecosystem string
		name      string
		version   string
		want      string
	}{
		{"node", "express", "4.18.2", "pkg:npm/express@4.18.2"},
		{"python", "requests", "2.31.0", "pkg:pypi/requests@2.31.0"},
		{"go", "github.com/google/uuid", "1.6.0", "pkg:golang/github.com%2Fgoogle/uuid@1.6.0"},
		{"java", "org.apache:log4j-core", "2.17.1", "pkg:maven/org.apache/log4j-core@2.17.1"},
		{"php", "laravel/framework", "10.0.0", "pkg:composer/laravel/framework@10.0.0"},
		{"rust", "serde", "1.0.0", "pkg:cargo/serde@1.0.0"},
		{"ruby", "rails", "7.0.0", "pkg:gem/rails@7.0.0"},
		{"dart", "flutter_bloc", "8.0.0", "pkg:pub/flutter_bloc@8.0.0"},
		{"dotnet", "Newtonsoft.Json", "13.0.3", "pkg:nuget/Newtonsoft.Json@13.0.3"},
		{"unknown", "pkg", "1.0", ""},
		{"node", "express", "", "pkg:npm/express"},
	}

	for _, tc := range tests {
		got := buildPURL(tc.ecosystem, tc.name, tc.version)
		assert.Equal(t, tc.want, got, "buildPURL(%q, %q, %q)", tc.ecosystem, tc.name, tc.version)
	}
}

func TestGenerateAll(t *testing.T) {
	id1 := uuid.New()
	id2 := uuid.New()
	id3 := uuid.New()

	assets := []model.Asset{
		{ID: id1, AssetType: model.AssetTypeSoftwareProject, Hostname: "app1"},
		{ID: id2, AssetType: model.AssetTypeRepository, Hostname: "repo"}, // skipped
		{ID: id3, AssetType: model.AssetTypeSoftwareProject, Hostname: "app2"},
	}

	swMap := map[uuid.UUID][]model.InstalledSoftware{
		id1: {{SoftwareName: "express", Version: "4.18.2", PackageManager: "node"}},
		// id3 has no software — should be skipped
	}

	boms := GenerateAll(assets, swMap)
	assert.Len(t, boms, 1)
	assert.Contains(t, boms, id1)
}

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()

	bom := &BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: specVersion,
		Version:     1,
		Components:  []Component{{Type: "library", Name: "test", Version: "1.0.0"}},
	}

	err := WriteFile(bom, dir, "test-sbom.json")
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, "test-sbom.json"))
	require.NoError(t, err)

	var parsed BOM
	require.NoError(t, json.Unmarshal(data, &parsed))
	assert.Equal(t, "CycloneDX", parsed.BOMFormat)
	assert.Len(t, parsed.Components, 1)
}
