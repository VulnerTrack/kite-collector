package winbcracendeu

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MaxWalkDepth bounds per-root tree depth.
const MaxWalkDepth = 6

// fileCollector walks BCRA install roots. Test seam swaps
// readFile / readDir / statFile / getenv.
type fileCollector struct {
	getenv       func(string) string
	readFile     func(string) ([]byte, error)
	readDir      func(string) ([]os.DirEntry, error)
	statFile     func(string) (os.FileInfo, error)
	installRoots []string
}

// NewCollector returns a Collector wired to canonical paths.
func NewCollector() Collector {
	return &fileCollector{
		installRoots: DefaultInstallRoots(),
		getenv:       os.Getenv,
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
	}
}

func (c *fileCollector) Name() string { return "winbcracendeu" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("BCRA_HOME")); p != "" {
		roots = append([]string{p}, roots...)
	}
	if p := strings.TrimSpace(c.getenv("BCRA_CENDEU_DIR")); p != "" {
		roots = append([]string{p}, roots...)
	}

	for _, r := range roots {
		c.walk(r, "", &out, 0)
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
		if !isCandidateExt(e.Name()) {
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
		SnapshotKind: SnapshotKindFromName(path),
		PeriodYYYYMM: PeriodFromName(filepath.Base(path)),
	}
	row.TargetCuitPrefix, row.TargetCuitSuffix4 = CuitFingerprintFromName(filepath.Base(path))

	if fi.Size() > MaxFileBytes {
		// Inventory metadata only.
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

	stats := ParseCENDEUSnapshot(body)
	row.RecordCount = stats.RecordCount
	row.DistinctEntityCount = stats.DistinctEntityCount
	row.MaxSituacion = stats.MaxSituacion
	row.HasChequesRechazados = stats.HasChequesRechazados

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func isCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".csv", ".txt", ".tsv", ".dat", ".zip", ".xls", ".xlsx":
		return true
	}
	return false
}
