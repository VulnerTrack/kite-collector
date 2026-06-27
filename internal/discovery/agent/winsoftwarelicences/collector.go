package winsoftwarelicences

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxWalkDepth bounds per-root tree depth. Program Files
// trees can be deep — 8 levels covers
// `Program Files\<Pub>\<Product>\<Version>\<Module>\license`.
const MaxWalkDepth = 8

// fileCollector walks licence install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winsoftwarelicences" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 32)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("SOFTWARE_LICENCES_DIR")); p != "" {
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
			for _, rel := range UserLicenceDirs() {
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
		ArtifactKind: ArtifactKindFromName(filepath.Base(path)),
		LicenseType:  LicenseUnknown,
		DPDSClass:    DPDSUnknown,
	}
	// Derive product / publisher from the install-path
	// breadcrumb when possible: ...\<Publisher>\<Product>\<...>\license.dat
	pub, prod := PublisherProductFromPath(path)
	row.Publisher = pub
	row.ProductTitle = prod
	// Install date proxy = file mtime in YYYYMMDD.
	row.InstallDateYYYYMMDD = fi.ModTime().UTC().Format("20060102")

	if fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			if fields, ok := ParseLicence(body); ok {
				if row.ProductTitle == "" && fields.ProductTitle != "" {
					row.ProductTitle = fields.ProductTitle
				}
				if row.Publisher == "" && fields.Publisher != "" {
					row.Publisher = fields.Publisher
				}
				if fields.ProductURL != "" {
					row.ProductURL = fields.ProductURL
				}
				if fields.InstallDate != "" {
					if d := normaliseDate(fields.InstallDate); d != "" {
						row.InstallDateYYYYMMDD = d
					}
				}
				if fields.ExpiryDate != "" {
					if d := normaliseDate(fields.ExpiryDate); d != "" {
						row.ExpiryDateYYYYMMDD = d
					}
				}
				if fields.LicenseType != "" && fields.LicenseType != LicenseUnknown {
					row.LicenseType = fields.LicenseType
				}
				if fields.LicenseKeyRaw != "" {
					row.LicenseKeyHash = HashLicenseKey(fields.LicenseKeyRaw)
				}
				if fields.LicensePurpose != "" {
					row.LicensePurpose = fields.LicensePurpose
				}
			}
		}
	}

	// DP/DS classification — use product + publisher hints.
	row.DPDSClass = ClassifyDPDS(row.ProductTitle, row.Publisher)

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}

	AnnotateSecurityWithClock(&row, c.now)
	*out = append(*out, row)
}

// PublisherProductFromPath extracts publisher + product hints
// from an install-path breadcrumb. Handles both
// `Program Files\<Publisher>\<Product>\...` and the
// `ProgramData\<Publisher>\<Product>\...` shape, as well as
// the analogous Unix `/opt/<vendor>/<product>/...` layout.
func PublisherProductFromPath(path string) (publisher, product string) {
	// Normalise both Windows (\) and POSIX (/) separators
	// regardless of host OS so that Windows-style paths
	// resolve correctly when this code runs on Linux CI.
	clean := strings.ReplaceAll(filepath.ToSlash(path), `\`, "/")
	parts := strings.Split(clean, "/")
	if len(parts) < 4 {
		return "", ""
	}
	// Find anchor segments.
	for i, p := range parts {
		lp := strings.ToLower(p)
		switch lp {
		case "program files", "program files (x86)", "programdata", "opt", "applications":
			if i+2 < len(parts) {
				return parts[i+1], parts[i+2]
			}
			if i+1 < len(parts) {
				return parts[i+1], ""
			}
			return "", ""
		}
	}
	return "", ""
}

func normaliseDate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 10 {
		return ""
	}
	// Accept YYYY-MM-DD and YYYY/MM/DD.
	if t, err := time.Parse("2006-01-02", s[:10]); err == nil {
		return t.UTC().Format("20060102")
	}
	if t, err := time.Parse("2006/01/02", s[:10]); err == nil {
		return t.UTC().Format("20060102")
	}
	return ""
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
