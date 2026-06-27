package linuxflatpak

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"strings"
)

// MetadataFields captures Flatpak `metadata` INI fields.
type MetadataFields struct {
	AppID       string
	Runtime     string
	SDK         string
	Command     string
	Sockets     string
	Devices     string
	Filesystems string
	Shared      string
}

// MetainfoFields captures the AppStream metainfo.xml fields.
type MetainfoFields struct {
	AppID       string
	Name        string
	Summary     string
	Description string
	License     string
	Homepage    string
	Version     string
	ReleaseDate string
}

// ParseFlatpakMetadata parses an INI-style `metadata` body
// and returns the canonical fields.
func ParseFlatpakMetadata(body []byte) (MetadataFields, bool) {
	var out MetadataFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return out, false
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var section string
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") &&
			strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSpace(
				strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]"))
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:eq])
		val := strings.TrimSpace(trimmed[eq+1:])
		applyMetadataKey(section, key, val, &out)
	}
	if !metadataHasAny(out) {
		return out, false
	}
	return out, true
}

func metadataHasAny(f MetadataFields) bool {
	return f.AppID != "" || f.Runtime != "" || f.Command != "" ||
		f.Sockets != "" || f.Devices != "" ||
		f.Filesystems != "" || f.Shared != ""
}

func applyMetadataKey(section, key, val string, out *MetadataFields) {
	switch section {
	case "Application":
		switch key {
		case "name":
			if out.AppID == "" {
				out.AppID = val
			}
		case "runtime":
			out.Runtime = val
		case "sdk":
			out.SDK = val
		case "command":
			out.Command = val
		}
	case "Context":
		switch key {
		case "sockets":
			out.Sockets = val
		case "devices":
			out.Devices = val
		case "filesystems":
			out.Filesystems = val
		case "shared":
			out.Shared = val
		}
	}
}

// metainfoXML models the relevant subset of an AppStream
// metainfo.xml document.
type metainfoXML struct {
	XMLName     xml.Name        `xml:"component"`
	ID          string          `xml:"id"`
	Name        string          `xml:"name"`
	Summary     string          `xml:"summary"`
	Description string          `xml:"description"`
	License     string          `xml:"project_license"`
	URLs        []metainfoURL   `xml:"url"`
	Releases    metainfoRelease `xml:"releases"`
}

type metainfoURL struct {
	Type string `xml:"type,attr"`
	Text string `xml:",chardata"`
}

type metainfoRelease struct {
	Releases []metainfoSingleRelease `xml:"release"`
}

type metainfoSingleRelease struct {
	Version string `xml:"version,attr"`
	Date    string `xml:"date,attr"`
}

// ParseMetainfoXML extracts MetainfoFields from an AppStream
// XML body. Returns ok=false on empty / non-XML input.
func ParseMetainfoXML(body []byte) (MetainfoFields, bool) {
	var out MetainfoFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '<' {
		return out, false
	}
	var doc metainfoXML
	if err := xml.Unmarshal(body, &doc); err != nil {
		return out, false
	}
	out.AppID = strings.TrimSpace(doc.ID)
	out.Name = strings.TrimSpace(doc.Name)
	out.Summary = strings.TrimSpace(doc.Summary)
	out.Description = strings.TrimSpace(doc.Description)
	out.License = strings.TrimSpace(doc.License)
	for _, u := range doc.URLs {
		if strings.EqualFold(strings.TrimSpace(u.Type), "homepage") {
			out.Homepage = strings.TrimSpace(u.Text)
			break
		}
	}
	if len(doc.Releases.Releases) > 0 {
		latest := doc.Releases.Releases[0]
		out.Version = strings.TrimSpace(latest.Version)
		out.ReleaseDate = strings.TrimSpace(latest.Date)
	}
	if !metainfoHasAny(out) {
		return out, false
	}
	return out, true
}

func metainfoHasAny(f MetainfoFields) bool {
	return f.AppID != "" || f.Name != "" || f.Summary != "" ||
		f.Description != "" || f.License != "" ||
		f.Homepage != "" || f.Version != ""
}
