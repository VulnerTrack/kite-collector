package classifier

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/vulnertrack/kite-collector/internal/model"
	"gopkg.in/yaml.v3"
)

// AllowlistEntry represents one allowed asset pattern.
type AllowlistEntry struct {
	Hostname   string `yaml:"hostname"`
	MACAddress string `yaml:"mac_address"`
	IPAddress  string `yaml:"ip_address"`
}

// allowlistFile is the top-level YAML structure for the allowlist file.
type allowlistFile struct {
	Assets []AllowlistEntry `yaml:"assets"`
}

// Authorizer checks whether discovered assets are present in an
// organisation-maintained allowlist.
type Authorizer struct {
	entries     []AllowlistEntry
	matchFields []string
}

// NewAuthorizer loads the allowlist from a YAML file and returns an Authorizer
// configured to match on the given fields.  If allowlistPath is empty or the
// file does not exist, an authorizer with zero entries is returned so that
// every asset evaluates to "unknown" (no data to decide).
func NewAuthorizer(allowlistPath string, matchFields []string) (*Authorizer, error) {
	// Validate that all match_fields are currently supported.
	for _, f := range matchFields {
		switch strings.ToLower(f) {
		case "hostname":
			// supported
		case "mac_address", "ip_address":
			return nil, fmt.Errorf("match_field %q is not yet supported; only \"hostname\" is available", f)
		default:
			return nil, fmt.Errorf("unknown match_field %q", f)
		}
	}

	a := &Authorizer{
		matchFields: matchFields,
	}

	if allowlistPath == "" {
		return a, nil
	}

	data, err := os.ReadFile(allowlistPath) //#nosec G304 -- path from trusted config file, not user input
	if err != nil {
		if os.IsNotExist(err) {
			return a, nil
		}
		return nil, fmt.Errorf("read allowlist %s: %w", allowlistPath, err)
	}

	var f allowlistFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse allowlist YAML: %w", err)
	}
	a.entries = f.Assets
	return a, nil
}

// Authorize determines whether an asset matches any allowlist entry.
//
// Matching rules:
//   - If no entries are loaded, return "unknown" (nothing to compare against).
//   - If entries exist and the asset matches ALL configured matchFields of any
//     single entry, return "authorized".
//   - If entries exist but nothing matches, return "unauthorized".
//
// Hostname matching supports glob patterns via path.Match.
//
// NOTE: model.Asset does not carry ip_address or mac_address directly; those
// live on model.NetworkInterface.  In Phase 1 the authorizer only matches on
// hostname.  IP and MAC match fields are accepted but will never produce a
// positive match until the asset model is extended or the interface is
// widened to accept network interfaces.
func (a *Authorizer) Authorize(asset model.Asset) model.AuthorizationState {
	if len(a.entries) == 0 {
		return model.AuthorizationUnknown
	}

	for _, entry := range a.entries {
		if a.entryMatches(entry, asset) {
			return model.AuthorizationAuthorized
		}
	}
	return model.AuthorizationUnauthorized
}

// entryMatches returns true when every configured match field in the entry
// matches the corresponding value on the asset.
func (a *Authorizer) entryMatches(entry AllowlistEntry, asset model.Asset) bool {
	if len(a.matchFields) == 0 {
		return false
	}

	for _, field := range a.matchFields {
		switch strings.ToLower(field) {
		case "hostname":
			if entry.Hostname == "" {
				continue // entry does not constrain this field
			}
			matched, err := path.Match(
				strings.ToLower(entry.Hostname),
				strings.ToLower(asset.Hostname),
			)
			if err != nil || !matched {
				return false
			}

		case "mac_address":
			// Asset struct does not carry MAC; never matches in Phase 1.
			if entry.MACAddress != "" {
				return false
			}

		case "ip_address":
			// Asset struct does not carry IP; never matches in Phase 1.
			if entry.IPAddress != "" {
				return false
			}

		default:
			// Unknown field — cannot match, so entry fails.
			return false
		}
	}
	return true
}
