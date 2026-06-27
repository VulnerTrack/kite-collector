package browserpolicies

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// vendorSeed pairs a browser kind with the dir(s) and file(s) we
// should harvest on each OS. Chrome and Edge use a directory of
// JSON files; Firefox uses a single `policies.json`.
type vendorSeed struct {
	browser BrowserKind
	dirs    []string // each dir is walked for *.json
	files   []string // each file is parsed individually
}

// DefaultSeeds is the canonical set of policy locations across
// Windows, Linux, and macOS. The collector iterates and parses
// whatever's readable.
func DefaultSeeds() []vendorSeed {
	return []vendorSeed{
		{
			browser: BrowserChrome,
			dirs: []string{
				`C:\Program Files\Google\Chrome\policies\managed`,
				`C:\Program Files (x86)\Google\Chrome\policies\managed`,
				"/etc/opt/chrome/policies/managed",
				"/Library/Managed Preferences/com.google.Chrome",
			},
		},
		{
			browser: BrowserEdge,
			dirs: []string{
				`C:\Program Files (x86)\Microsoft\Edge\Application\policies\managed`,
				`C:\Program Files\Microsoft\Edge\Application\policies\managed`,
				"/etc/opt/edge/policies/managed",
				"/etc/opt/microsoft/edge/policies/managed",
			},
		},
		{
			browser: BrowserFirefox,
			files: []string{
				`C:\Program Files\Mozilla Firefox\distribution\policies.json`,
				`C:\Program Files (x86)\Mozilla Firefox\distribution\policies.json`,
				"/etc/firefox/policies/policies.json",
				"/usr/lib64/firefox/distribution/policies.json",
				"/usr/lib/firefox/distribution/policies.json",
				"/Applications/Firefox.app/Contents/Resources/distribution/policies.json",
			},
		},
	}
}

// fileCollector parses every browser policy file reachable from
// the configured seed list. Test seam swaps readFile / readDir.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	seeds    []vendorSeed
}

// NewCollector returns a Collector wired to the canonical browser-
// policy paths across Windows / Linux / macOS.
func NewCollector() Collector {
	return &fileCollector{
		seeds:    DefaultSeeds(),
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
}

func (c *fileCollector) Name() string { return "browserpolicies" }

func (c *fileCollector) Collect(_ context.Context) ([]Policy, error) {
	out := make([]Policy, 0, 32)

	for _, seed := range c.seeds {
		for _, dir := range seed.dirs {
			entries, err := c.readDir(dir)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				return nil, err
			}
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].Name() < entries[j].Name()
			})
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				name := e.Name()
				if !strings.EqualFold(filepath.Ext(name), ".json") {
					continue
				}
				if strings.HasPrefix(name, ".") {
					continue
				}
				full := filepath.Join(dir, name)
				body, err := c.readFile(full)
				if err != nil {
					continue
				}
				policies, err := ParseChromeFamilyPolicy(body, full, seed.browser)
				if err != nil {
					continue
				}
				out = append(out, policies...)
				if len(out) >= MaxRows {
					break
				}
			}
			if len(out) >= MaxRows {
				break
			}
		}
		for _, f := range seed.files {
			body, err := c.readFile(f)
			if err != nil {
				continue
			}
			var policies []Policy
			if seed.browser == BrowserFirefox {
				policies, err = ParseFirefoxPolicy(body, f)
			} else {
				policies, err = ParseChromeFamilyPolicy(body, f, seed.browser)
			}
			if err != nil {
				continue
			}
			out = append(out, policies...)
			if len(out) >= MaxRows {
				break
			}
		}
		if len(out) >= MaxRows {
			break
		}
	}

	if len(out) > MaxRows {
		out = out[:MaxRows]
	}
	SortPolicies(out)
	return out, nil
}
