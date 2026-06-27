package driver

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

// MSFTBlocklist holds the parsed Microsoft Recommended Driver Block Rules
// (a Windows Defender Application Control SiPolicy XML). Lookups are O(1)
// against multiple hash representations.
type MSFTBlocklist struct {
	bySHA256       map[string]MSFTBlockRule
	byAuthentihash map[string]MSFTBlockRule
	byPESHA1       map[string]MSFTBlockRule
	byFilename     map[string]MSFTBlockRule
}

// MSFTBlockRule is one Deny rule from the SiPolicy.
type MSFTBlockRule struct {
	ID                 string
	FriendlyName       string
	HashType           string // "Authenticode_SHA256", "Hash" (file SHA-256), "PageHash_SHA1"
	HashHex            string
	FileName           string
	MinimumFileVersion string
}

// sipolicy is the XML root of a SiPolicy CI policy file.
type sipolicy struct {
	XMLName   xml.Name      `xml:"SiPolicy"`
	FileRules fileRulesNode `xml:"FileRules"`
}

type fileRulesNode struct {
	XMLName xml.Name      `xml:"FileRules"`
	Denies  []denyRuleXML `xml:"Deny"`
	Allows  []denyRuleXML `xml:"Allow"`
}

// denyRuleXML covers both Deny and Allow elements (same shape).
type denyRuleXML struct {
	XMLName            xml.Name `xml:""`
	ID                 string   `xml:"ID,attr"`
	FriendlyName       string   `xml:"FriendlyName,attr"`
	Hash               string   `xml:"Hash,attr"`
	FileName           string   `xml:"FileName,attr"`
	MinimumFileVersion string   `xml:"MinimumFileVersion,attr"`
}

// LoadMSFTBlocklistFromFile reads a SiPolicy XML file from disk.
func LoadMSFTBlocklistFromFile(path string) (*MSFTBlocklist, error) {
	data, err := os.ReadFile(path) //#nosec G304 -- caller-resolved policy path
	if err != nil {
		return nil, fmt.Errorf("blocklist read %s: %w", path, err)
	}
	return ParseMSFTBlocklistXML(data)
}

// ParseMSFTBlocklistXML decodes a SiPolicy XML payload.
func ParseMSFTBlocklistXML(raw []byte) (*MSFTBlocklist, error) {
	var pol sipolicy
	if err := xml.Unmarshal(raw, &pol); err != nil {
		return nil, fmt.Errorf("blocklist unmarshal: %w", err)
	}

	bl := &MSFTBlocklist{
		bySHA256:       map[string]MSFTBlockRule{},
		byAuthentihash: map[string]MSFTBlockRule{},
		byPESHA1:       map[string]MSFTBlockRule{},
		byFilename:     map[string]MSFTBlockRule{},
	}
	for _, d := range pol.FileRules.Denies {
		rule := MSFTBlockRule{
			ID:                 d.ID,
			FriendlyName:       d.FriendlyName,
			HashHex:            strings.ToLower(strings.TrimSpace(d.Hash)),
			FileName:           d.FileName,
			MinimumFileVersion: d.MinimumFileVersion,
		}
		bl.classify(rule)
	}
	return bl, nil
}

// classify routes the rule into the right hash bucket. WDAC SiPolicy uses a
// few different hash types — we infer by length:
//
//	64 hex chars  → SHA-256 (file hash or Authenticode SHA-256, ambiguous —
//	                stored in both maps so either side matches)
//	40 hex chars  → SHA-1 (legacy Authenticode or PageHash)
func (bl *MSFTBlocklist) classify(rule MSFTBlockRule) {
	switch len(rule.HashHex) {
	case 64:
		rule.HashType = "SHA256"
		bl.bySHA256[rule.HashHex] = rule
		bl.byAuthentihash[rule.HashHex] = rule
	case 40:
		rule.HashType = "SHA1"
		bl.byPESHA1[rule.HashHex] = rule
	case 0:
		// pure filename rule
	default:
		// unknown length — best-effort; drop it
	}
	if name := strings.ToLower(strings.TrimSpace(rule.FileName)); name != "" {
		bl.byFilename[name] = rule
	}
}

// Match returns the matching block rule, in order of strongest evidence:
// SHA-256 (file or Authenticode) → Authentihash → SHA-1 (PE) → filename.
func (bl *MSFTBlocklist) Match(d LoadedDriver) *MSFTBlockRule {
	if d.OnDiskSHA256 != "" {
		if r, ok := bl.bySHA256[strings.ToLower(d.OnDiskSHA256)]; ok {
			return &r
		}
	}
	if d.Authentihash != "" {
		if r, ok := bl.byAuthentihash[strings.ToLower(d.Authentihash)]; ok {
			return &r
		}
	}
	if d.Path != "" {
		base := strings.ToLower(filepathBaseSafe(d.Path))
		if r, ok := bl.byFilename[base]; ok {
			return &r
		}
	}
	if d.Name != "" {
		if r, ok := bl.byFilename[strings.ToLower(d.Name)]; ok {
			return &r
		}
	}
	return nil
}

// Size returns the number of unique rules indexed.
func (bl *MSFTBlocklist) Size() int {
	if bl == nil {
		return 0
	}
	seen := make(map[string]struct{})
	for k := range bl.bySHA256 {
		seen["sha256:"+k] = struct{}{}
	}
	for k := range bl.byPESHA1 {
		seen["sha1:"+k] = struct{}{}
	}
	for k := range bl.byFilename {
		seen["name:"+k] = struct{}{}
	}
	return len(seen)
}
