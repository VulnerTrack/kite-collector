package chocolatey

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
)

// rawNuspec mirrors the on-disk NuGet metadata shape. Only the
// fields we surface in audit are tagged; everything else flows past.
type rawNuspec struct {
	XMLName  xml.Name    `xml:"package"`
	Metadata rawMetadata `xml:"metadata"`
}

type rawMetadata struct {
	ID                       string            `xml:"id"`
	Version                  string            `xml:"version"`
	Title                    string            `xml:"title"`
	Authors                  string            `xml:"authors"`
	Owners                   string            `xml:"owners"`
	ProjectURL               string            `xml:"projectUrl"`
	LicenseURL               string            `xml:"licenseUrl"`
	License                  rawLicense        `xml:"license"`
	Description              string            `xml:"description"`
	Summary                  string            `xml:"summary"`
	Tags                     string            `xml:"tags"`
	ReleaseNotes             string            `xml:"releaseNotes"`
	RequireLicenseAcceptance string            `xml:"requireLicenseAcceptance"`
	Dependencies             rawDependencyList `xml:"dependencies"`
}

// rawLicense surfaces the NuGet 4.9+ `<license type="expression">MIT</license>`
// form alongside the legacy `<licenseUrl>...</licenseUrl>` element.
type rawLicense struct {
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

type rawDependencyList struct {
	Group      []rawDependencyGroup `xml:"group"`
	Dependency []rawDependency      `xml:"dependency"`
}

type rawDependencyGroup struct {
	TargetFramework string          `xml:"targetFramework,attr"`
	Dependency      []rawDependency `xml:"dependency"`
}

type rawDependency struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

// ParseNuspec walks a single .nuspec body and returns a populated
// Package. The body is plain UTF-8 XML (no BOM, no UTF-16); we still
// strip a UTF-8 BOM if present.
//
// `filePath` is recorded verbatim and feeds the file_hash + file_path
// columns; it doesn't need to exist on disk.
func ParseNuspec(body []byte, filePath string) (Package, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return Package{}, fmt.Errorf("empty nuspec")
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	dec := xml.NewDecoder(bytes.NewReader(body))
	// nuspec uses a default xmlns; non-strict mode lets the bare
	// element names in our struct tags match without each pulling the
	// namespace through.
	dec.Strict = false
	dec.Entity = xml.HTMLEntity

	var raw rawNuspec
	if err := dec.Decode(&raw); err != nil {
		return Package{}, fmt.Errorf("unmarshal nuspec: %w", err)
	}

	pkg := Package{
		FilePath:          filePath,
		FileHash:          HashContents(body),
		PackageID:         strings.TrimSpace(raw.Metadata.ID),
		PackageVersion:    strings.TrimSpace(raw.Metadata.Version),
		Title:             strings.TrimSpace(raw.Metadata.Title),
		Authors:           strings.TrimSpace(raw.Metadata.Authors),
		Owners:            strings.TrimSpace(raw.Metadata.Owners),
		ProjectURL:        strings.TrimSpace(raw.Metadata.ProjectURL),
		LicenseURL:        strings.TrimSpace(raw.Metadata.LicenseURL),
		LicenseExpression: licenseExpression(raw.Metadata.License),
		Description:       strings.TrimSpace(raw.Metadata.Description),
		Summary:           strings.TrimSpace(raw.Metadata.Summary),
		Tags:              strings.TrimSpace(raw.Metadata.Tags),
		ReleaseNotes:      strings.TrimSpace(raw.Metadata.ReleaseNotes),
		Dependencies:      flattenDependencies(raw.Metadata.Dependencies),
	}
	AnnotateSecurity(&pkg)
	return pkg, nil
}

// licenseExpression returns the SPDX expression when the nuspec uses
// the modern `<license type="expression">MIT</license>` form. The
// legacy `<licenseUrl>` field stays on Package.LicenseURL untouched.
func licenseExpression(l rawLicense) string {
	if strings.EqualFold(strings.TrimSpace(l.Type), "expression") {
		return strings.TrimSpace(l.Content)
	}
	return ""
}

// flattenDependencies merges the two NuGet dependency forms into
// one slice. Both `<dependencies><dependency …/></dependencies>` and
// `<dependencies><group …><dependency …/></group></dependencies>` are
// emitted in the wild; we don't care about the per-target-framework
// grouping for inventory purposes.
func flattenDependencies(d rawDependencyList) []Dependency {
	out := make([]Dependency, 0, len(d.Dependency)+len(d.Group))
	for _, e := range d.Dependency {
		if id := strings.TrimSpace(e.ID); id != "" {
			out = append(out, Dependency{ID: id, Version: strings.TrimSpace(e.Version)})
		}
	}
	for _, g := range d.Group {
		for _, e := range g.Dependency {
			if id := strings.TrimSpace(e.ID); id != "" {
				out = append(out, Dependency{ID: id, Version: strings.TrimSpace(e.Version)})
			}
		}
	}
	return out
}
