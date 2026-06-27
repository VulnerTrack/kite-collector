package macoshomebrew

import (
	"bytes"
	"encoding/json"
	"strings"
)

// ReceiptFields captures INSTALL_RECEIPT.json metadata.
type ReceiptFields struct {
	HomebrewVersion       string
	Version               string
	Time                  int64
	RuntimeDeps           int64
	BuiltAsBottle         bool
	PouredFromBottle      bool
	InstalledOnRequest    bool
	InstalledAsDependency bool
}

// CaskFields captures cask metadata JSON.
type CaskFields struct {
	Token       string
	Name        string
	Description string
	Homepage    string
	Version     string
	URL         string
	AutoUpdates bool
}

// installReceipt models the canonical install_receipt.json
// shape. Some fields are kept as raw json.RawMessage so the
// schema-tolerant Source.Stable.Version path can be extracted
// in either Homebrew layout.
type installReceipt struct {
	Source struct {
		Spec   string `json:"spec,omitempty"`
		Stable struct {
			Version string `json:"version,omitempty"`
		} `json:"stable,omitempty"`
	} `json:"source,omitempty"`
	HomebrewVersion       string          `json:"homebrew_version,omitempty"`
	RuntimeDependencies   json.RawMessage `json:"runtime_dependencies,omitempty"`
	Time                  int64           `json:"time,omitempty"`
	BuiltAsBottle         bool            `json:"built_as_bottle,omitempty"`
	PouredFromBottle      bool            `json:"poured_from_bottle,omitempty"`
	InstalledOnRequest    bool            `json:"installed_on_request,omitempty"`
	InstalledAsDependency bool            `json:"installed_as_dependency,omitempty"`
}

// ParseInstallReceipt extracts ReceiptFields from a JSON
// body. Returns ok=false on empty / non-JSON input.
func ParseInstallReceipt(body []byte) (ReceiptFields, bool) {
	var out ReceiptFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return out, false
	}
	var r installReceipt
	if err := json.Unmarshal(body, &r); err != nil {
		return out, false
	}
	out.HomebrewVersion = strings.TrimSpace(r.HomebrewVersion)
	out.Time = r.Time
	out.BuiltAsBottle = r.BuiltAsBottle
	out.PouredFromBottle = r.PouredFromBottle
	out.InstalledOnRequest = r.InstalledOnRequest
	out.InstalledAsDependency = r.InstalledAsDependency
	out.Version = strings.TrimSpace(r.Source.Stable.Version)
	// runtime_dependencies is an array — count entries by
	// scanning for `{` start-of-object markers; this avoids
	// declaring a polymorphic schema for the various Homebrew
	// versions.
	if len(r.RuntimeDependencies) > 0 {
		out.RuntimeDeps = int64(bytes.Count(r.RuntimeDependencies,
			[]byte(`{`)))
	}
	if !receiptHasAny(out) {
		return out, false
	}
	return out, true
}

func receiptHasAny(f ReceiptFields) bool {
	return f.HomebrewVersion != "" || f.Time != 0 ||
		f.Version != "" || f.RuntimeDeps > 0 ||
		f.BuiltAsBottle || f.PouredFromBottle ||
		f.InstalledOnRequest || f.InstalledAsDependency
}

// caskJSON models the cask metadata JSON. Homebrew uses
// `name` as an array of strings — we extract the first.
type caskJSON struct {
	Token       string          `json:"token,omitempty"`
	Name        json.RawMessage `json:"name,omitempty"`
	Desc        string          `json:"desc,omitempty"`
	Homepage    string          `json:"homepage,omitempty"`
	Version     string          `json:"version,omitempty"`
	URL         json.RawMessage `json:"url,omitempty"`
	AutoUpdates bool            `json:"auto_updates,omitempty"`
}

// ParseCaskMetadata extracts CaskFields from a JSON body.
func ParseCaskMetadata(body []byte) (CaskFields, bool) {
	var out CaskFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return out, false
	}
	var c caskJSON
	if err := json.Unmarshal(body, &c); err != nil {
		return out, false
	}
	out.Token = strings.TrimSpace(c.Token)
	out.Description = strings.TrimSpace(c.Desc)
	out.Homepage = strings.TrimSpace(c.Homepage)
	out.Version = strings.TrimSpace(c.Version)
	out.AutoUpdates = c.AutoUpdates
	// `name` is an array of strings; pull the first.
	if len(c.Name) > 0 {
		var arr []string
		if err := json.Unmarshal(c.Name, &arr); err == nil && len(arr) > 0 {
			out.Name = strings.TrimSpace(arr[0])
		} else {
			// Fallback: maybe a single string.
			var single string
			if err := json.Unmarshal(c.Name, &single); err == nil {
				out.Name = strings.TrimSpace(single)
			}
		}
	}
	// `url` may be string or object {"url": "...", "verified": "..."}.
	if len(c.URL) > 0 {
		var single string
		if err := json.Unmarshal(c.URL, &single); err == nil {
			out.URL = strings.TrimSpace(single)
		} else {
			var obj struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal(c.URL, &obj); err == nil {
				out.URL = strings.TrimSpace(obj.URL)
			}
		}
	}
	if !caskHasAny(out) {
		return out, false
	}
	return out, true
}

func caskHasAny(f CaskFields) bool {
	return f.Token != "" || f.Name != "" || f.Description != "" ||
		f.Homepage != "" || f.Version != "" || f.URL != ""
}
