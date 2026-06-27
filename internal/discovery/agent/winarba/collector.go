package winarba

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxWalkDepth bounds per-agency tree depth.
const MaxWalkDepth = 8

// fileCollector walks provincial-tax agency roots. Test seam
// swaps readFile / readDir / statFile / getenv.
type fileCollector struct {
	getenv   func(string) string
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	statFile func(string) (os.FileInfo, error)
	roots    []AgencyRoot
}

// NewCollector returns a Collector wired to canonical roots.
func NewCollector() Collector {
	return &fileCollector{
		roots:    DefaultAgencyRoots(),
		getenv:   os.Getenv,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
}

func (c *fileCollector) Name() string { return "winarba" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]AgencyRoot{}, c.roots...)
	if p := strings.TrimSpace(c.getenv("ARBA_HOME")); p != "" {
		roots = append([]AgencyRoot{{Path: p, Agency: AgencyARBA}}, roots...)
	}
	if p := strings.TrimSpace(c.getenv("AGIP_HOME")); p != "" {
		roots = append([]AgencyRoot{{Path: p, Agency: AgencyAGIP}}, roots...)
	}

	for _, r := range roots {
		c.walk(r.Path, r.Agency, &out, 0)
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

func (c *fileCollector) walk(dir string, agency Agency, out *[]Row, depth int) {
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
			c.walk(full, agency, out, depth+1)
			if len(*out) >= MaxRows {
				return
			}
			continue
		}
		if !isCandidateExt(e.Name()) {
			continue
		}
		kind := FileKindFromName(e.Name())
		if kind == KindUnknown {
			continue
		}
		c.consider(full, agency, kind, out)
		if len(*out) >= MaxRows {
			return
		}
	}
}

func (c *fileCollector) consider(path string, agency Agency, kind FileKind, out *[]Row) {
	fi, err := c.statFile(path)
	if err != nil {
		return
	}
	row := Row{
		FilePath:     path,
		FileSize:     fi.Size(),
		FileMode:     int(fi.Mode().Perm()),
		FileOwnerUID: ownerUID(fi),
		Agency:       agency,
		FileKind:     kind,
	}
	if row.Agency == AgencyUnknown {
		row.Agency = AgencyFromPath(c.roots, path)
	}
	row.LastModified = fi.ModTime().UTC().Format(time.RFC3339)
	row.CuitEntityPrefix, row.CuitSuffix4 = CuitFingerprintFromName(filepath.Base(path))
	row.PeriodYYYYMM = PeriodFromName(filepath.Base(path))

	if fi.Size() > MaxFileBytes {
		// Inventory metadata only — skip hashing huge dumps.
		AnnotateSecurity(&row)
		*out = append(*out, row)
		return
	}
	body, err := c.readFile(path)
	if err != nil {
		AnnotateSecurity(&row)
		*out = append(*out, row)
		return
	}
	row.FileHash = HashContents(body)
	row.RecordCount = CountLines(body)
	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func isCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".txt", ".csv", ".tsv", ".dat":
		return true
	}
	return false
}
