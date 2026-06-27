package driver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// LOLDriversFeedURL is the canonical drivers.json published by loldrivers.io.
// MIT-licensed dataset of known-vulnerable Windows drivers.
const LOLDriversFeedURL = "https://www.loldrivers.io/api/drivers.json"

// LOLDriverEntry models the upstream JSON schema. Only the fields used for
// matching are decoded — the schema is large and many fields are advisory
// (acknowledgement, references, MITRE techniques).
type LOLDriverEntry struct {
	ID            string                  `json:"Id"`
	Category      string                  `json:"Category"`
	Verified      string                  `json:"Verified"`
	Tags          []string                `json:"Tags"`
	KnownVulnIDs  []string                `json:"KnownVulnerableSamples_CVE,omitempty"`
	MITRE         []string                `json:"MitreID"`
	Samples       []LOLDriverSample       `json:"KnownVulnerableSamples"`
	OriginalFiles []LOLDriverOriginalFile `json:"OriginalFilename,omitempty"`
}

// LOLDriverSample holds the file-level identifiers used for matching.
type LOLDriverSample struct {
	Filename     string `json:"Filename,omitempty"`
	MD5          string `json:"MD5,omitempty"`
	SHA1         string `json:"SHA1,omitempty"`
	SHA256       string `json:"SHA256,omitempty"`
	Authentihash string `json:"Authentihash,omitempty"`
	IMPHASH      string `json:"ImportedHash,omitempty"`
	Description  string `json:"Description,omitempty"`
	Company      string `json:"Company,omitempty"`
}

// LOLDriverOriginalFile is the original publisher / filename pair.
type LOLDriverOriginalFile struct {
	Filename string `json:"Filename"`
	Hash     string `json:"Sha256,omitempty"`
}

// LOLDriversIndex is the deduplicated set of indices used to look a driver up
// by SHA-256, Authentihash, or IMPHASH. Lookups are O(1).
type LOLDriversIndex struct {
	bySHA256       map[string]*LOLDriverEntry
	byAuthentihash map[string]*LOLDriverEntry
	byImpHash      map[string]*LOLDriverEntry
	byFilename     map[string][]*LOLDriverEntry
}

// NewLOLDriversIndex constructs a lookup index from a parsed entry list.
func NewLOLDriversIndex(entries []LOLDriverEntry) *LOLDriversIndex {
	idx := &LOLDriversIndex{
		bySHA256:       make(map[string]*LOLDriverEntry, len(entries)),
		byAuthentihash: make(map[string]*LOLDriverEntry, len(entries)),
		byImpHash:      make(map[string]*LOLDriverEntry, len(entries)),
		byFilename:     make(map[string][]*LOLDriverEntry, len(entries)),
	}
	for i := range entries {
		entry := &entries[i]
		for _, s := range entry.Samples {
			if h := strings.ToLower(s.SHA256); h != "" {
				idx.bySHA256[h] = entry
			}
			if h := strings.ToLower(s.Authentihash); h != "" {
				idx.byAuthentihash[h] = entry
			}
			if h := strings.ToLower(s.IMPHASH); h != "" {
				idx.byImpHash[h] = entry
			}
			if name := strings.ToLower(strings.TrimSpace(s.Filename)); name != "" {
				idx.byFilename[name] = append(idx.byFilename[name], entry)
			}
		}
		for _, of := range entry.OriginalFiles {
			if name := strings.ToLower(strings.TrimSpace(of.Filename)); name != "" {
				idx.byFilename[name] = append(idx.byFilename[name], entry)
			}
		}
	}
	return idx
}

// Match returns the LOLDrivers entry that matches the given driver via, in
// order: SHA-256 → Authentihash → IMPHASH → filename. Returns nil when no
// match is found. Matching by filename is best-effort and only runs if the
// hashes don't match — it's a noisier signal because legitimate driver
// names (rwdrv.sys, mhyprot.sys) sometimes collide.
func (idx *LOLDriversIndex) Match(d LoadedDriver) *LOLDriverEntry {
	if d.OnDiskSHA256 != "" {
		if e := idx.bySHA256[strings.ToLower(d.OnDiskSHA256)]; e != nil {
			return e
		}
	}
	if d.Authentihash != "" {
		if e := idx.byAuthentihash[strings.ToLower(d.Authentihash)]; e != nil {
			return e
		}
	}
	if d.ImportHash != "" {
		if e := idx.byImpHash[strings.ToLower(d.ImportHash)]; e != nil {
			return e
		}
	}
	if d.Path != "" {
		base := strings.ToLower(filepathBaseSafe(d.Path))
		if hits := idx.byFilename[base]; len(hits) > 0 {
			return hits[0]
		}
	}
	return nil
}

// Size returns the count of indexed entries (across all hash maps).
func (idx *LOLDriversIndex) Size() int {
	if idx == nil {
		return 0
	}
	seen := make(map[*LOLDriverEntry]struct{}, len(idx.bySHA256))
	for _, e := range idx.bySHA256 {
		seen[e] = struct{}{}
	}
	for _, e := range idx.byAuthentihash {
		seen[e] = struct{}{}
	}
	for _, e := range idx.byImpHash {
		seen[e] = struct{}{}
	}
	return len(seen)
}

// LoadLOLDrivers fetches the upstream JSON feed and decodes it. The HTTP
// client is configurable for tests; the default uses a 30 s timeout and
// caps the body to 64 MB.
type LOLDriversLoader struct {
	HTTP    *http.Client
	FeedURL string
	MaxSize int64
}

// NewLOLDriversLoader returns a loader configured with the canonical feed
// URL and a 30 s HTTP timeout.
func NewLOLDriversLoader() *LOLDriversLoader {
	return &LOLDriversLoader{
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		FeedURL: LOLDriversFeedURL,
		MaxSize: 64 << 20,
	}
}

// Load fetches and parses the LOLDrivers feed.
func (l *LOLDriversLoader) Load(ctx context.Context) ([]LOLDriverEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.FeedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("loldrivers request: %w", err)
	}
	resp, err := l.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("loldrivers fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("loldrivers fetch: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, l.MaxSize))
	if err != nil {
		return nil, fmt.Errorf("loldrivers read: %w", err)
	}
	return ParseLOLDriversJSON(body)
}

// LoadFromFile parses a previously-fetched local copy of drivers.json.
// Useful for offline/air-gapped agent deployments.
func LoadLOLDriversFromFile(path string) ([]LOLDriverEntry, error) {
	data, err := os.ReadFile(path) //#nosec G304 -- caller-resolved feed path
	if err != nil {
		return nil, fmt.Errorf("loldrivers read %s: %w", path, err)
	}
	return ParseLOLDriversJSON(data)
}

// ParseLOLDriversJSON decodes the drivers.json payload.
func ParseLOLDriversJSON(raw []byte) ([]LOLDriverEntry, error) {
	var entries []LOLDriverEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("loldrivers unmarshal: %w", err)
	}
	return entries, nil
}

// filepathBaseSafe returns the base name of a path, handling both "/" and
// "\" separators (matters for Windows driver paths on a Linux build host).
func filepathBaseSafe(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[i+1:]
		}
	}
	return path
}
