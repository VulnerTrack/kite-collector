// Package sbom generates CycloneDX SBOM documents from manifest scan results.
package sbom

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// CycloneDX spec version produced.
const specVersion = "1.5"

// BOM is the top-level CycloneDX Bill of Materials.
type BOM struct {
	Metadata     Metadata    `json:"metadata"`
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Components   []Component `json:"components"`
	Version      int         `json:"version"`
}

// Metadata describes the SBOM producer and subject.
type Metadata struct {
	Component *MetaComp `json:"component,omitempty"`
	Timestamp string    `json:"timestamp"`
	Tools     []Tool    `json:"tools"`
}

// Tool identifies the tool that produced the BOM.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// MetaComp is the top-level component described by the BOM.
type MetaComp struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Version string `json:"version,omitempty"`
}

// Component is a single library/package in the BOM.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type"`
	CPE     string `json:"cpe,omitempty"`
	PURL    string `json:"purl,omitempty"`
	Scope   string `json:"scope,omitempty"`
}

// ecosystemToPURL maps parser ecosystem identifiers to Package URL type prefixes.
var ecosystemToPURL = map[string]string{
	"node":   "npm",
	"php":    "composer",
	"python": "pypi",
	"go":     "golang",
	"rust":   "cargo",
	"ruby":   "gem",
	"java":   "maven",
	"dart":   "pub",
	"elixir": "hex",
	"swift":  "swift",
	"perl":   "cpan",
	"dotnet": "nuget",
}

// Generate creates a CycloneDX BOM from a project asset and its installed software.
func Generate(asset model.Asset, software []model.InstalledSoftware) (*BOM, error) {
	serial, err := uuid.NewV7()
	if err != nil {
		serial = uuid.New()
	}

	bom := &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  specVersion,
		Version:      1,
		SerialNumber: "urn:uuid:" + serial.String(),
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []Tool{
				{Name: "kite-collector"},
			},
			Component: &MetaComp{
				Type: "application",
				Name: asset.Hostname,
			},
		},
		Components: make([]Component, 0, len(software)),
	}

	for _, sw := range software {
		comp := Component{
			Type:    "library",
			Name:    sw.SoftwareName,
			Version: sw.Version,
			CPE:     sw.CPE23,
			PURL:    buildPURL(sw.PackageManager, sw.SoftwareName, sw.Version),
		}
		bom.Components = append(bom.Components, comp)
	}

	return bom, nil
}

// JSON serialises the BOM to indented JSON bytes.
func (b *BOM) JSON() ([]byte, error) {
	return json.MarshalIndent(b, "", "  ")
}

// buildPURL constructs a Package URL from ecosystem, name, and version.
func buildPURL(ecosystem, name, version string) string {
	purlType, ok := ecosystemToPURL[ecosystem]
	if !ok {
		return ""
	}

	// Maven-style names use group:artifact → namespace/name in PURL.
	namespace := ""
	pkgName := name
	if purlType == "maven" {
		if parts := strings.SplitN(name, ":", 2); len(parts) == 2 {
			namespace = parts[0]
			pkgName = parts[1]
		}
	}

	// Composer names use vendor/package → namespace/name in PURL.
	if purlType == "composer" {
		if parts := strings.SplitN(name, "/", 2); len(parts) == 2 {
			namespace = parts[0]
			pkgName = parts[1]
		}
	}

	// Go module paths use the full path as namespace.
	if purlType == "golang" {
		if i := strings.LastIndex(name, "/"); i > 0 {
			namespace = name[:i]
			pkgName = name[i+1:]
		}
	}

	var purl strings.Builder
	purl.WriteString("pkg:")
	purl.WriteString(purlType)
	purl.WriteByte('/')
	if namespace != "" {
		purl.WriteString(url.PathEscape(namespace))
		purl.WriteByte('/')
	}
	purl.WriteString(url.PathEscape(pkgName))
	if version != "" {
		purl.WriteByte('@')
		purl.WriteString(url.PathEscape(version))
	}
	return purl.String()
}

// GenerateAll produces one BOM per project asset. Returns a map of asset ID → BOM.
func GenerateAll(assets []model.Asset, softwareByAsset map[uuid.UUID][]model.InstalledSoftware) map[uuid.UUID]*BOM {
	boms := make(map[uuid.UUID]*BOM)
	for _, a := range assets {
		if a.AssetType != model.AssetTypeSoftwareProject {
			continue
		}
		sw := softwareByAsset[a.ID]
		if len(sw) == 0 {
			continue
		}
		bom, err := Generate(a, sw)
		if err != nil {
			continue
		}
		boms[a.ID] = bom
	}
	return boms
}

// WriteFile writes a BOM to a file in the given directory.
func WriteFile(bom *BOM, dir, filename string) error {
	data, err := bom.JSON()
	if err != nil {
		return fmt.Errorf("marshal BOM: %w", err)
	}

	target := filepath.Join(dir, filename)
	return writeFileAtomic(target, data)
}

// writeFileAtomic writes data to a temp file then renames to target.
func writeFileAtomic(target string, data []byte) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".sbom-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
