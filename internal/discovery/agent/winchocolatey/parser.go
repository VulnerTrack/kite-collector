package winchocolatey

import (
	"bytes"
	"encoding/xml"
	"strings"
)

// NuspecFields captures the canonical Chocolatey nuspec
// metadata that maps to the software-licence inventory
// schema (title, manufacturer, install date, purpose, URL,
// DP/DS-relevant tags).
type NuspecFields struct {
	PackageID    string
	Title        string
	Authors      string
	Copyright    string
	Version      string
	ProjectURL   string
	LicenseURL   string
	Description  string
	Tags         string
	ReleaseNotes string
}

// nuspecPackage models the top-level Chocolatey nuspec
// document. The schema is:
//
//	<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
//	  <metadata>
//	    <id>...</id>
//	    <title>...</title>
//	    <authors>...</authors>
//	    <copyright>...</copyright>
//	    <version>...</version>
//	    <projectUrl>...</projectUrl>
//	    <licenseUrl>...</licenseUrl>
//	    <description>...</description>
//	    <tags>...</tags>
//	    <releaseNotes>...</releaseNotes>
//	  </metadata>
//	</package>
type nuspecPackage struct {
	XMLName  xml.Name `xml:"package"`
	Metadata struct {
		ID           string `xml:"id"`
		Title        string `xml:"title"`
		Authors      string `xml:"authors"`
		Copyright    string `xml:"copyright"`
		Version      string `xml:"version"`
		ProjectURL   string `xml:"projectUrl"`
		LicenseURL   string `xml:"licenseUrl"`
		Description  string `xml:"description"`
		Tags         string `xml:"tags"`
		ReleaseNotes string `xml:"releaseNotes"`
	} `xml:"metadata"`
}

// ParseNuspec extracts NuspecFields from an XML body.
// Returns ok=false on empty / non-XML / unparseable input.
func ParseNuspec(body []byte) (NuspecFields, bool) {
	var out NuspecFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '<' {
		return out, false
	}
	var doc nuspecPackage
	if err := xml.Unmarshal(body, &doc); err != nil {
		return out, false
	}
	out.PackageID = strings.TrimSpace(doc.Metadata.ID)
	out.Title = strings.TrimSpace(doc.Metadata.Title)
	out.Authors = strings.TrimSpace(doc.Metadata.Authors)
	out.Copyright = strings.TrimSpace(doc.Metadata.Copyright)
	out.Version = strings.TrimSpace(doc.Metadata.Version)
	out.ProjectURL = strings.TrimSpace(doc.Metadata.ProjectURL)
	out.LicenseURL = strings.TrimSpace(doc.Metadata.LicenseURL)
	out.Description = strings.TrimSpace(doc.Metadata.Description)
	out.Tags = strings.TrimSpace(doc.Metadata.Tags)
	out.ReleaseNotes = strings.TrimSpace(doc.Metadata.ReleaseNotes)
	if !hasAny(out) {
		return out, false
	}
	return out, true
}

func hasAny(f NuspecFields) bool {
	return f.PackageID != "" || f.Title != "" || f.Authors != "" ||
		f.Version != "" || f.ProjectURL != "" || f.LicenseURL != "" ||
		f.Description != "" || f.Tags != "" || f.Copyright != ""
}

// PublisherFromNuspec returns the best-effort publisher string:
// authors first, copyright second, "" when neither set.
func PublisherFromNuspec(f NuspecFields) string {
	if f.Authors != "" {
		return f.Authors
	}
	if f.Copyright != "" {
		return f.Copyright
	}
	return ""
}

// TitleFromNuspec returns title first, then package_id, then "".
func TitleFromNuspec(f NuspecFields) string {
	if f.Title != "" {
		return f.Title
	}
	return f.PackageID
}
