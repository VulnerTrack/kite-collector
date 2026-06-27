package winnpm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// rawManifest mirrors the npm `package.json` fields we care
// about. `Bin` is `string | map[string]string`; `Repository` is
// `string | {type, url}` — we accept either via raw json.
type rawManifest struct {
	Engines      map[string]string `json:"engines"`
	Dependencies map[string]string `json:"dependencies"`
	Scripts      map[string]string `json:"scripts"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Description  string            `json:"description"`
	Homepage     string            `json:"homepage"`
	Main         string            `json:"main"`
	License      json.RawMessage   `json:"license"`
	Author       json.RawMessage   `json:"author"`
	Repository   json.RawMessage   `json:"repository"`
	Bin          json.RawMessage   `json:"bin"`
}

// ParseManifest walks a single npm `package.json` body and
// returns a populated Package (without FilePath / PackageDir /
// InstallPrefix — those are stamped by the collector).
func ParseManifest(body []byte) (Package, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return Package{}, fmt.Errorf("empty manifest")
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	var raw rawManifest
	if err := json.Unmarshal(body, &raw); err != nil {
		return Package{}, fmt.Errorf("unmarshal npm manifest: %w", err)
	}

	out := Package{
		Name:               strings.TrimSpace(raw.Name),
		Version:            strings.TrimSpace(raw.Version),
		Description:        strings.TrimSpace(raw.Description),
		License:            decodeLicense(raw.License),
		Author:             decodeAuthor(raw.Author),
		Homepage:           strings.TrimSpace(raw.Homepage),
		RepositoryURL:      decodeRepositoryURL(raw.Repository),
		MainEntry:          strings.TrimSpace(raw.Main),
		EngineNode:         strings.TrimSpace(raw.Engines["node"]),
		Dependencies:       sortedKeys(raw.Dependencies),
		BinEntries:         decodeBin(raw.Bin, strings.TrimSpace(raw.Name)),
		InstallScriptNames: extractInstallScripts(raw.Scripts),
	}
	AnnotateSecurity(&out)
	return out, nil
}

// decodeLicense handles the two legal shapes:
//
//	"license": "MIT"
//	"license": { "type": "MIT", "url": "..." }
func decodeLicense(raw json.RawMessage) string {
	v := strings.TrimSpace(string(raw))
	if v == "" || v == "null" {
		return ""
	}
	if v[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return strings.TrimSpace(s)
		}
	}
	if v[0] == '{' {
		var obj struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &obj); err == nil {
			return strings.TrimSpace(obj.Type)
		}
	}
	return ""
}

// decodeAuthor handles `"author": "Name <email>"` or
// `"author": { "name": "...", "email": "..." }`.
func decodeAuthor(raw json.RawMessage) string {
	v := strings.TrimSpace(string(raw))
	if v == "" || v == "null" {
		return ""
	}
	if v[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return strings.TrimSpace(s)
		}
	}
	if v[0] == '{' {
		var obj struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		}
		if err := json.Unmarshal(raw, &obj); err == nil {
			if obj.Email != "" {
				return strings.TrimSpace(obj.Name) + " <" +
					strings.TrimSpace(obj.Email) + ">"
			}
			return strings.TrimSpace(obj.Name)
		}
	}
	return ""
}

// decodeRepositoryURL handles `"repository": "<url>"` or
// `"repository": { "type": "git", "url": "..." }`.
func decodeRepositoryURL(raw json.RawMessage) string {
	v := strings.TrimSpace(string(raw))
	if v == "" || v == "null" {
		return ""
	}
	if v[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return strings.TrimSpace(s)
		}
	}
	if v[0] == '{' {
		var obj struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(raw, &obj); err == nil {
			return strings.TrimSpace(obj.URL)
		}
	}
	return ""
}

// decodeBin handles `"bin": "./cli.js"` (shorthand) or
// `"bin": { "tool": "./cli.js", ... }`.
func decodeBin(raw json.RawMessage, pkgName string) []string {
	v := strings.TrimSpace(string(raw))
	if v == "" || v == "null" {
		return nil
	}
	if v[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || s == "" {
			return nil
		}
		// Shorthand uses the package name as the command.
		if pkgName == "" {
			return nil
		}
		// Strip scope from `@scope/name` → `name` for the bin
		// (matches npm's behaviour).
		base := pkgName
		if i := strings.LastIndexByte(base, '/'); i >= 0 {
			base = base[i+1:]
		}
		return []string{base}
	}
	if v[0] == '{' {
		var m map[string]string
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil
		}
		return sortedKeys(m)
	}
	return nil
}

// extractInstallScripts returns the subset of script keys that
// npm runs as part of `npm install`. Order preserved by the
// curated list.
func extractInstallScripts(scripts map[string]string) []string {
	if len(scripts) == 0 {
		return nil
	}
	out := make([]string, 0, len(InstallScriptNames()))
	for _, name := range InstallScriptNames() {
		if v, ok := scripts[name]; ok && strings.TrimSpace(v) != "" {
			out = append(out, name)
		}
	}
	return out
}

// sortedKeys returns a stable alphabetically-sorted slice of map
// keys. Used so the persisted dependency / bin lists are
// deterministic across runs.
func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
