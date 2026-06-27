package winvscode

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// rawManifest mirrors the slice of `package.json` we care about.
// Unknown keys flow past via the json decoder's default behaviour.
type rawManifest struct {
	Engines          map[string]string          `json:"engines"`
	Contributes      map[string]json.RawMessage `json:"contributes"`
	Capabilities     map[string]json.RawMessage `json:"capabilities"`
	Name             string                     `json:"name"`
	DisplayName      string                     `json:"displayName"`
	Version          string                     `json:"version"`
	Publisher        string                     `json:"publisher"`
	Description      string                     `json:"description"`
	Main             string                     `json:"main"`
	ActivationEvents []string                   `json:"activationEvents"`
}

// ParseManifest walks a single VSCode-extension `package.json`
// body and returns a populated Extension (without FilePath /
// ExtensionDir / EditorKind / UserProfile — those are stamped by
// the collector).
func ParseManifest(body []byte) (Extension, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return Extension{}, fmt.Errorf("empty manifest")
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	var raw rawManifest
	if err := json.Unmarshal(body, &raw); err != nil {
		return Extension{}, fmt.Errorf("unmarshal vscode manifest: %w", err)
	}

	out := Extension{
		Publisher:        strings.TrimSpace(raw.Publisher),
		ExtensionName:    strings.TrimSpace(raw.Name),
		ExtensionVersion: strings.TrimSpace(raw.Version),
		DisplayName:      strings.TrimSpace(raw.DisplayName),
		Description:      strings.TrimSpace(raw.Description),
		MainEntry:        strings.TrimSpace(raw.Main),
		EngineVSCode:     strings.TrimSpace(raw.Engines["vscode"]),
		ActivationEvents: dedupeNonEmpty(raw.ActivationEvents),
		Contributes:      sortedKeys(raw.Contributes),
	}

	// Workspace Trust opt-out lives under `capabilities`:
	//   "capabilities": { "untrustedWorkspaces": { "supported": false } }
	if raw.Capabilities != nil {
		if blob, ok := raw.Capabilities["untrustedWorkspaces"]; ok {
			var trust struct {
				Supported   any    `json:"supported"`
				Description string `json:"description"`
			}
			if err := json.Unmarshal(blob, &trust); err == nil {
				switch v := trust.Supported.(type) {
				case bool:
					out.IsWorkspaceTrustDisabled = !v
				case string:
					// "limited" is treated as partially-trusted but
					// not the headline "off" we alert on.
					if strings.EqualFold(strings.TrimSpace(v), "false") {
						out.IsWorkspaceTrustDisabled = true
					}
				}
			}
		}
	}

	AnnotateSecurity(&out)
	return out, nil
}

// dedupeNonEmpty collapses duplicates and drops empty strings.
// Order preserved by first-seen.
func dedupeNonEmpty(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// sortedKeys returns a stable, alphabetically-sorted slice of map
// keys. Used so the persisted `contributes` JSON array is
// deterministic across runs.
func sortedKeys(m map[string]json.RawMessage) []string {
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
