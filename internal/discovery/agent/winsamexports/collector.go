package winsamexports

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxWalkDepth bounds per-root tree depth.
const MaxWalkDepth = 8

// fileCollector walks SAM-export roots + per-user dirs.
type fileCollector struct {
	now          func() time.Time
	getenv       func(string) string
	readFile     func(string) ([]byte, error)
	readDir      func(string) ([]os.DirEntry, error)
	statFile     func(string) (os.FileInfo, error)
	installRoots []string
	usersBases   []string
}

// NewCollector returns a Collector wired to canonical paths.
func NewCollector() Collector {
	return &fileCollector{
		installRoots: DefaultInstallRoots(),
		usersBases:   DefaultUsersBases(),
		getenv:       os.Getenv,
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          time.Now,
	}
}

func (c *fileCollector) Name() string { return "winsamexports" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("SAM_EXPORTS_DIR")); p != "" {
		roots = append([]string{p}, roots...)
	}

	for _, r := range roots {
		c.walk(r, "", &out, 0)
		if len(out) >= MaxRows {
			break
		}
	}

	for _, base := range c.usersBases {
		entries, err := c.readDir(base)
		if err != nil {
			continue
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if isSystemPseudoProfile(name) || strings.HasPrefix(name, ".") {
				continue
			}
			for _, rel := range UserSAMDirs() {
				c.walk(filepath.Join(append([]string{base, name}, rel...)...),
					name, &out, 0)
				if len(out) >= MaxRows {
					break
				}
			}
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
	SortRows(out)
	return out, nil
}

func (c *fileCollector) walk(dir, user string, out *[]Row, depth int) {
	if depth > MaxWalkDepth {
		return
	}
	entries, err := c.readDir(dir)
	if err != nil {
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		if e.IsDir() {
			c.walk(full, user, out, depth+1)
			if len(*out) >= MaxRows {
				return
			}
			continue
		}
		if !IsCandidateExt(e.Name()) {
			continue
		}
		if !IsCandidateName(e.Name()) {
			continue
		}
		c.consider(full, user, out)
		if len(*out) >= MaxRows {
			return
		}
	}
}

func (c *fileCollector) consider(path, user string, out *[]Row) {
	for _, existing := range *out {
		if existing.FilePath == path {
			return
		}
	}
	fi, err := c.statFile(path)
	if err != nil {
		return
	}
	row := Row{
		FilePath:     path,
		FileSize:     fi.Size(),
		FileMode:     int(fi.Mode().Perm()),
		FileOwnerUID: ownerUID(fi),
		UserProfile:  user,
		ToolKind:     ToolKindFromName(filepath.Base(path)),
	}

	if fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			if host := HostnameFromText(string(body)); host != "" {
				row.AssetHostnameHash = HashHostname(host)
			}
			if ts := InventoryTimestampFromText(string(body)); ts != "" {
				row.InventoryTimestamp = ts
			}
			row.SoftwareCount = SoftwareRowCount(body)
			row.PIISoftwareCount = CountPIIRows(body)
			row.UnlicensedCount = CountUnlicensedRows(body)
			row.PublishersDistinctCount = countDistinctPublishers(body)
		}
	}

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}

	AnnotateSecurityWithClock(&row, c.now)
	*out = append(*out, row)
}

// countDistinctPublishers returns the number of distinct
// publisher tokens seen in the body. Tokens beyond a small
// cap (256) collapse into one count to bound work.
func countDistinctPublishers(body []byte) int64 {
	const maxTokens = 256
	publishers := make(map[string]struct{}, 32)
	lower := strings.ToLower(string(body))
	for _, line := range strings.Split(lower, "\n") {
		fields := strings.FieldsFunc(line, func(r rune) bool {
			switch r {
			case ',', ';', '|', '\t':
				return true
			}
			return false
		})
		for _, f := range fields {
			f = strings.TrimSpace(f)
			if isLikelyPublisher(f) {
				publishers[f] = struct{}{}
				if len(publishers) >= maxTokens {
					return int64(maxTokens)
				}
			}
		}
	}
	return int64(len(publishers))
}

func isLikelyPublisher(s string) bool {
	if len(s) < 3 || len(s) > 64 {
		return false
	}
	for _, marker := range []string{
		"microsoft", "google", "adobe", "autodesk", "intel",
		"apple", "oracle", "ibm", "vmware", "citrix",
		"jetbrains", "intuit", "sage", "sap", "amazon",
		"eset", "symantec", "kaspersky", "mcafee", "salesforce",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
